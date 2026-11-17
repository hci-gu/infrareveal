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

// ASNLookup is optional: a missing ASN database leaves network owners unknown.
type ASNLookup interface {
	ASN(net.IP) (*geoip2.ASN, error)
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
	ASNAvailable    bool   `json:"asn_available"`
	ASNBuildMS      int64  `json:"asn_build_ms"`
	ASNBytes        int64  `json:"asn_bytes"`
}

// An edition is one GeoLite2 database the manager installs and serves.
type edition struct {
	name, file, databaseType, temp string
	city                           bool
}

var (
	cityEdition = edition{name: "GeoLite2 City", file: "GeoLite2-City.mmdb", databaseType: "GeoLite2-City", temp: ".city-download-*", city: true}
	asnEdition  = edition{name: "GeoLite2 ASN", file: "GeoLite2-ASN.mmdb", databaseType: "GeoLite2-ASN", temp: ".asn-download-*"}
)

type credentials struct {
	AccountID  string `json:"account_id"`
	LicenseKey string `json:"license_key"`
}

type Manager struct {
	mu                             sync.RWMutex
	reader, asn                    *geoip2.Reader
	path, asnPath, credentialsPath string
	credentials                    credentials
	status                         Status
	generation                     atomic.Uint64
	cancel                         context.CancelFunc
	done                           chan struct{}
	closed                         bool
	client                         *http.Client
	endpoint, asnEndpoint          string
}

// Open serves the City database at path and, when present, the ASN database
// beside it as asn.mmdb.
func Open(path, credentialsPath string) *Manager {
	return OpenWithASN(path, filepath.Join(filepath.Dir(path), "asn.mmdb"), credentialsPath)
}

func OpenWithASN(path, asnPath, credentialsPath string) *Manager {
	m := &Manager{path: path, asnPath: asnPath, credentialsPath: credentialsPath, endpoint: "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz", asnEndpoint: "https://download.maxmind.com/geoip/databases/GeoLite2-ASN/download?suffix=tar.gz", client: &http.Client{Timeout: 10 * time.Minute}, status: Status{Phase: "idle"}}
	if b, err := os.ReadFile(credentialsPath); err == nil {
		_ = json.Unmarshal(b, &m.credentials)
	}
	if db, err := geoip2.Open(path); err == nil {
		m.reader = db
		m.readMetadata()
	} else {
		m.status.Message = "No readable City database is installed."
	}
	if db, err := geoip2.Open(asnPath); err == nil && db.Metadata().DatabaseType == asnEdition.databaseType {
		m.asn = db
		m.readASNMetadata()
	} else if err == nil {
		_ = db.Close()
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

func (m *Manager) readASNMetadata() {
	m.status.ASNAvailable = true
	m.status.ASNBuildMS = int64(m.asn.Metadata().BuildEpoch) * 1000
	if s, err := os.Stat(m.asnPath); err == nil {
		m.status.ASNBytes = s.Size()
	}
}

func (m *Manager) ASN(ip net.IP) (*geoip2.ASN, error) {
	if m == nil {
		return nil, errors.New("ASN database unavailable")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.asn == nil {
		return nil, errors.New("ASN database unavailable")
	}
	return m.asn.ASN(ip)
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
	c, done, endpoint, asnEndpoint := m.credentials, m.done, m.endpoint, m.asnEndpoint
	go func() {
		defer cancel()
		err := m.download(ctx, c, cityEdition, endpoint)
		if err == nil && asnEndpoint != "" {
			m.mu.Lock()
			cityMessage := m.status.Message
			m.status.Phase, m.status.Message = "downloading", "Downloading GeoLite2 ASN from MaxMind."
			m.mu.Unlock()
			// City stays installed when only the optional ASN database fails.
			if err = m.download(ctx, c, asnEdition, asnEndpoint); err != nil {
				err = fmt.Errorf("%s ASN: %w", cityMessage, err)
			} else {
				m.mu.Lock()
				m.status.Message = cityMessage + " " + m.status.Message
				m.mu.Unlock()
			}
		}
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

func (m *Manager) download(ctx context.Context, c credentials, ed edition, endpoint string) error {
	path := m.path
	if !ed.city {
		path = m.asnPath
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
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
	if err = os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return errors.New("GeoIP folder is not writable")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ed.temp)
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
		if h.Typeflag == tar.TypeReg && filepath.Base(h.Name) == ed.file {
			if found || h.Size <= 0 || h.Size > maxDatabaseBytes {
				return fmt.Errorf("Unexpected %s database in archive", ed.name)
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
		return fmt.Errorf("Downloaded %s database is invalid", ed.name)
	}
	err = check.Verify()
	meta := check.Metadata
	_ = check.Close()
	if err != nil || meta.DatabaseType != ed.databaseType || meta.BuildEpoch == 0 {
		return fmt.Errorf("Downloaded file is not a valid %s database", ed.name)
	}
	next, err := geoip2.Open(f.Name())
	if err != nil {
		return fmt.Errorf("Cannot open downloaded %s database", ed.name)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if ctx.Err() != nil || m.closed {
		_ = next.Close()
		return errors.New("GeoIP refresh was cancelled")
	}
	current := &m.reader
	if !ed.city {
		current = &m.asn
	}
	if *current != nil && meta.BuildEpoch < (*current).Metadata().BuildEpoch {
		_ = next.Close()
		return fmt.Errorf("Downloaded %s database is older than the installed version", ed.name)
	}
	if *current != nil && meta.BuildEpoch == (*current).Metadata().BuildEpoch && meta.DatabaseType == (*current).Metadata().DatabaseType {
		_ = next.Close()
		m.status.Phase, m.status.Message = "complete", fmt.Sprintf("The installed %s database is already up to date.", ed.name)
		return nil
	}
	if err = os.Rename(f.Name(), path); err != nil {
		_ = next.Close()
		return fmt.Errorf("Cannot replace the %s database; the existing database is unchanged", ed.name)
	}
	old := *current
	*current = next
	if ed.city {
		m.readMetadata()
	} else {
		m.readASNMetadata()
	}
	m.generation.Add(1)
	m.status.Phase, m.status.Message = "complete", fmt.Sprintf("%s updated. New traffic uses the refreshed database.", ed.name)
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
	var err error
	if m.reader != nil {
		err = m.reader.Close()
		m.reader = nil
	}
	if m.asn != nil {
		err = errors.Join(err, m.asn.Close())
		m.asn = nil
	}
	return err
}
