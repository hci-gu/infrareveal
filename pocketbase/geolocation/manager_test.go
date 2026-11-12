package geolocation

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func archive(t *testing.T, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "GeoLite2-City_test/GeoLite2-City.mmdb", Mode: 0600, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func fixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/GeoLite2-City-Test.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func manager(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	m := Open(filepath.Join(dir, "city.mmdb"), filepath.Join(dir, "maxmind.json"))
	t.Cleanup(func() {
		if err := m.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	if err := m.Configure("123456", "fixture-key"); err != nil {
		t.Fatal(err)
	}
	return m
}
func completed(t *testing.T, m *Manager) Status {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s := m.Status()
		if s.FinishedMS > 0 {
			return s
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("refresh did not finish")
	return Status{}
}
func TestInstallReloadAndKeepCredentialsPrivate(t *testing.T) {
	m := manager(t)
	data := fixture(t)
	body := archive(t, data)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account, key, ok := r.BasicAuth()
		if !ok || account != "123456" || key != "fixture-key" {
			t.Error("missing MaxMind authentication")
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()
	m.endpoint = server.URL
	var queries sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		queries.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = m.City(net.ParseIP("81.2.69.160"))
					_ = m.Version()
				}
			}
		})
	}
	if err := m.Refresh(); err != nil {
		t.Fatal(err)
	}
	s := completed(t, m)
	close(stop)
	queries.Wait()
	if s.Phase != "complete" || !s.Available || m.Version() != 1 || s.Bytes != int64(len(data)) {
		t.Fatalf("install: %+v", s)
	}
	if _, err := m.City(net.ParseIP("81.2.69.160")); err != nil {
		t.Fatal(err)
	}
	stored, _ := os.ReadFile(m.path)
	if !bytes.Equal(stored, data) {
		t.Fatal("installed file differs")
	}
	public, _ := json.Marshal(s)
	if bytes.Contains(public, []byte("fixture-key")) {
		t.Fatal("license key exposed")
	}
	st, _ := os.Stat(m.credentialsPath)
	if st.Mode().Perm() != 0600 {
		t.Fatal("credentials mode", st.Mode())
	}
	if err := m.Configure("654321", ""); err == nil {
		t.Fatal("new account reused old key")
	}
	if err := m.Configure("123456", ""); err != nil {
		t.Fatal(err)
	}
	if err := m.Refresh(); err != nil {
		t.Fatal(err)
	}
	if s = completed(t, m); !strings.Contains(s.Message, "already up to date") || m.Version() != 1 {
		t.Fatalf("same version: %+v", s)
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(m.path), ".city-download-*"))
	if len(leftovers) != 0 {
		t.Fatal("temporary files retained")
	}
}
func TestFailedDownloadsPreserveInstalledDatabase(t *testing.T) {
	for _, kind := range []string{"http", "invalid", "truncated", "wrong-file"} {
		t.Run(kind, func(t *testing.T) {
			m := manager(t)
			original := fixture(t)
			if err := os.WriteFile(m.path, original, 0600); err != nil {
				t.Fatal(err)
			}
			// Reopen the fixture so both the original file and the live reader are checked.
			if err := m.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			m = Open(m.path, m.credentialsPath)
			defer m.Close(context.Background())
			body := archive(t, original)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch kind {
				case "http":
					w.WriteHeader(401)
				case "invalid":
					_, _ = io.WriteString(w, "not gzip")
				case "truncated":
					_, _ = w.Write(body[:len(body)-8])
				case "wrong-file":
					_, _ = w.Write(archive(t, []byte("not mmdb")))
				}
			}))
			defer server.Close()
			m.endpoint = server.URL
			if err := m.Refresh(); err != nil {
				t.Fatal(err)
			}
			if s := completed(t, m); s.Phase != "failed" || !s.Available || s.Error == "" {
				t.Fatalf("failure: %+v", s)
			}
			got, _ := os.ReadFile(m.path)
			if !bytes.Equal(got, original) {
				t.Fatal("failed download replaced original")
			}
			if _, err := m.City(net.ParseIP("81.2.69.160")); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestRefreshJoinsAndCloseCancels(t *testing.T) {
	m := manager(t)
	entered := make(chan struct{})
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); close(entered); <-r.Context().Done() }))
	defer server.Close()
	m.endpoint = server.URL
	if err := m.Refresh(); err != nil {
		t.Fatal(err)
	}
	<-entered
	if err := m.Refresh(); err != nil {
		t.Fatal(err)
	}
	if err := m.Configure("123456", "new-key"); err == nil {
		t.Fatal("settings changed during download")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := m.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatal("duplicate downloads")
	}
	if err := m.Refresh(); err == nil {
		t.Fatal("closed manager restarted")
	}
}
