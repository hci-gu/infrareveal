// Package geolocation owns the replaceable local City database. Downloads never
// hold a lookup lock; a validated replacement is installed in one atomic rename.
package geolocation

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/oschwald/maxminddb-golang"
)

type Lookup interface {
	City(net.IP) (*geoip2.City, error)
}

func Version(db Lookup) uint64 {
	if v, ok := db.(interface{ Version() uint64 }); ok {
		return v.Version()
	}
	return 0
}

type Status struct {
	Available       bool   `json:"available"`
	DatabaseType    string `json:"database_type"`
	BuildMS         int64  `json:"build_ms"`
	Bytes           int64  `json:"bytes"`
	Configured      bool   `json:"configured"`
	AccountID       string `json:"account_id"`
	Phase           string `json:"phase"`
	DownloadedBytes int64  `json:"downloaded_bytes"`
	StartedMS       int64  `json:"started_ms"`
	FinishedMS      int64  `json:"finished_ms"`
	Error           string `json:"error"`
	Message         string `json:"message"`
}

type credentials struct {
	AccountID  string `json:"account_id"`
	LicenseKey string `json:"license_key"`
}

type Manager struct {
	mu                    sync.RWMutex
	reader                *geoip2.Reader
	path, credentialsPath string
	credentials           credentials
	status                Status
	generation            atomic.Uint64
	cancel                context.CancelFunc
	done                  chan struct{}
	closed                bool
	client                *http.Client
	endpoint              string
}

func Open(path, credentialsPath string) *Manager {
	m := &Manager{path: path, credentialsPath: credentialsPath, endpoint: "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz", client: &http.Client{Timeout: 10 * time.Minute}, status: Status{Phase: "idle"}}
	if b, err := os.ReadFile(credentialsPath); err == nil {
		_ = json.Unmarshal(b, &m.credentials)
	}
	if db, err := geoip2.Open(path); err == nil {
		m.reader = db
		m.readMetadata()
	} else {
		m.status.Message = "No readable City database is installed."
	}
	return m
}

func (m *Manager) readMetadata() {
	m.status.Available = true
	m.status.DatabaseType = m.reader.Metadata().DatabaseType
	m.status.BuildMS = int64(m.reader.Metadata().BuildEpoch) * 1000
	if s, err := os.Stat(m.path); err == nil {
		m.status.Bytes = s.Size()
	}
}

func (m *Manager) City(ip net.IP) (*geoip2.City, error) {
	if m == nil {
		return nil, errors.New("City database unavailable")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.reader == nil {
		return nil, errors.New("City database unavailable")
	}
	return m.reader.City(ip)
}
func (m *Manager) Version() uint64 {
	if m == nil {
		return 0
	}
	return m.generation.Load()
}
func (m *Manager) Status() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := m.status
	s.AccountID = m.credentials.AccountID
	s.Configured = m.credentials.AccountID != "" && m.credentials.LicenseKey != ""
	return s
}

// An empty key preserves the saved key only for the same account. Secrets are
// never included in Status, URLs, logs or download error messages.
func (m *Manager) Configure(account, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("Gateway is stopping")
	}
	if m.done != nil {
		return errors.New("Wait for the current refresh to finish")
	}
	account, key = strings.TrimSpace(account), strings.TrimSpace(key)
	if account == "" || strings.Trim(account, "0123456789") != "" {
		return errors.New("Enter your numeric MaxMind account ID")
	}
	if key == "" && account == m.credentials.AccountID {
		key = m.credentials.LicenseKey
	}
	if key == "" || len(key) > 512 || strings.ContainsAny(key, "\r\n") {
		return errors.New("Enter a valid MaxMind license key")
	}
	c := credentials{account, key}
	b, _ := json.Marshal(c)
	if err := os.MkdirAll(filepath.Dir(m.credentialsPath), 0700); err != nil {
		return errors.New("Cannot save MaxMind settings")
	}
	f, err := os.CreateTemp(filepath.Dir(m.credentialsPath), ".maxmind-*")
	if err != nil {
		return errors.New("Cannot save MaxMind settings")
	}
	defer os.Remove(f.Name())
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err == nil {
		err = os.Rename(f.Name(), m.credentialsPath)
	}
	if err != nil {
		return errors.New("Cannot save MaxMind settings")
	}
	m.credentials = c
	return nil
}

func (m *Manager) Refresh() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("Gateway is stopping")
	}
	if m.done != nil {
		return nil
	} // Repeated clicks join the same refresh.
	if m.credentials.AccountID == "" || m.credentials.LicenseKey == "" {
		return errors.New("Save your MaxMind account ID and license key first")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	m.cancel, m.done = cancel, make(chan struct{})
	m.status.Phase, m.status.Error, m.status.Message = "downloading", "", "Downloading GeoLite2 City from MaxMind."
	m.status.StartedMS, m.status.FinishedMS, m.status.DownloadedBytes = time.Now().UnixMilli(), 0, 0
	c, done := m.credentials, m.done
	go func() {
		defer cancel()
		err := m.download(ctx, c)
		m.mu.Lock()
		if err != nil {
			m.status.Phase, m.status.Error = "failed", err.Error()
		}
		m.status.FinishedMS = time.Now().UnixMilli()
		m.done, m.cancel = nil, nil
		close(done)
		m.mu.Unlock()
	}()
	return nil
}

type progressReader struct {
	io.Reader
	manager *Manager
}

func (r progressReader) Read(p []byte) (int, error) {
	n, e := r.Reader.Read(p)
	r.manager.mu.Lock()
	r.manager.status.DownloadedBytes += int64(n)
	r.manager.mu.Unlock()
	return n, e
}

const maxDatabaseBytes = 512 * 1024 * 1024

func (m *Manager) download(ctx context.Context, c credentials) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.endpoint, nil)
	if err != nil {
		return errors.New("Cannot prepare MaxMind download")
	}
	req.SetBasicAuth(c.AccountID, c.LicenseKey)
	res, err := m.client.Do(req)
	if err != nil {
		return errors.New("Could not connect to MaxMind; check the internet connection and retry")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("MaxMind returned HTTP %d; check your account access and license key", res.StatusCode)
	}
	compressed := &io.LimitedReader{R: progressReader{res.Body, m}, N: maxDatabaseBytes + 1}
	gz, err := gzip.NewReader(compressed)
	if err != nil {
		return errors.New("MaxMind download is not a valid gzip archive")
	}
	defer gz.Close()
	if err = os.MkdirAll(filepath.Dir(m.path), 0755); err != nil {
		return errors.New("GeoIP folder is not writable")
	}
	f, err := os.CreateTemp(filepath.Dir(m.path), ".city-download-*")
	if err != nil {
		return errors.New("GeoIP folder is not writable; check its disk space and mount")
	}
	defer os.Remove(f.Name())
	defer f.Close()
	// Never extract paths from the archive. Stream only the expected regular file
	// into our own temporary file, with bounds on compressed and expanded input.
	expanded := &io.LimitedReader{R: gz, N: maxDatabaseBytes + 1}
	tr := tar.NewReader(expanded)
	found := false
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.New("GeoIP archive is incomplete or invalid")
		}
		if ctx.Err() != nil {
			return errors.New("GeoIP refresh was cancelled")
		}
		if h.Typeflag == tar.TypeReg && filepath.Base(h.Name) == "GeoLite2-City.mmdb" {
			if found || h.Size <= 0 || h.Size > maxDatabaseBytes {
				return errors.New("Unexpected City database in archive")
			}
			if _, err = io.Copy(f, tr); err != nil {
				return errors.New("Cannot write GeoIP download; check free disk space")
			}
			found = true
		}
	}
	// Consume the gzip trailer as well: a valid MMDB inside a truncated gzip must
	// not replace the installed file.
	if _, err = io.Copy(io.Discard, expanded); err != nil || expanded.N <= 0 || compressed.N <= 0 || !found {
		return errors.New("GeoIP download is incomplete or exceeds its size limit")
	}
	if err = f.Sync(); err != nil {
		return errors.New("Cannot save GeoIP download")
	}
	if err = f.Close(); err != nil {
		return errors.New("Cannot close GeoIP download")
	}
	m.mu.Lock()
	m.status.Phase, m.status.Message = "validating", "Checking the downloaded database."
	m.mu.Unlock()
	check, err := maxminddb.Open(f.Name())
	if err != nil {
		return errors.New("Downloaded City database is invalid")
	}
	err = check.Verify()
	meta := check.Metadata
	_ = check.Close()
	if err != nil || meta.DatabaseType != "GeoLite2-City" || meta.BuildEpoch == 0 {
		return errors.New("Downloaded file is not a valid GeoLite2 City database")
	}
	next, err := geoip2.Open(f.Name())
	if err != nil {
		return errors.New("Cannot open downloaded City database")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if ctx.Err() != nil || m.closed {
		_ = next.Close()
		return errors.New("GeoIP refresh was cancelled")
	}
	if m.reader != nil && meta.BuildEpoch < m.reader.Metadata().BuildEpoch {
		_ = next.Close()
		return errors.New("Downloaded database is older than the installed version")
	}
	if m.reader != nil && meta.BuildEpoch == m.reader.Metadata().BuildEpoch && meta.DatabaseType == m.reader.Metadata().DatabaseType {
		_ = next.Close()
		m.status.Phase, m.status.Message = "complete", "The installed GeoLite2 City database is already up to date."
		return nil
	}
	if err = os.Rename(f.Name(), m.path); err != nil {
		_ = next.Close()
		return errors.New("Cannot replace the City database; the existing database is unchanged")
	}
	old := m.reader
	m.reader = next
	m.readMetadata()
	m.generation.Add(1)
	m.status.Phase, m.status.Message = "complete", "GeoLite2 City updated. New traffic uses the refreshed database."
	if old != nil {
		_ = old.Close()
	}
	return nil
}

func (m *Manager) Close(ctx context.Context) error {
	m.mu.Lock()
	m.closed = true
	done := m.done
	if m.cancel != nil {
		m.cancel()
	}
	m.mu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.reader != nil {
		err := m.reader.Close()
		m.reader = nil
		return err
	}
	return nil
}
