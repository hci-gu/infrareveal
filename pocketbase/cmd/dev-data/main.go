// dev-data creates a fresh map/activity database with deterministic example
// traffic. It does not import or convert any previous application schema.
package main

import (
	"flag"
	"fmt"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
	"log"
	"myapp/data"
	_ "myapp/migrations"
	"myapp/observer"
	"os"
	"path/filepath"
	"time"
)

func main() {
	dir := flag.String("dir", "./pb_data", "development database directory")
	reset := flag.Bool("reset", false, "delete existing disposable pb_data directory first; stop the server before using")
	diagnostics := flag.Bool("diagnostics", false, "create the three optional diagnostics collections")
	flag.Parse()
	path, err := filepath.Abs(*dir)
	if err != nil {
		log.Fatal(err)
	}
	if *reset {
		if filepath.Base(path) != "pb_data" {
			log.Fatal("reset only accepts a directory named pb_data")
		}
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
			log.Fatal("refusing to reset a symlink")
		}
		if err = os.RemoveAll(path); err != nil {
			log.Fatal(err)
		}
	}
	if entries, err := os.ReadDir(path); err == nil && len(entries) > 0 {
		log.Fatal("directory is not empty; stop the server and pass --reset to replace disposable development data")
	}
	app := pocketbase.NewWithConfig(pocketbase.Config{DefaultDataDir: path, HideStartBanner: true})
	if err = app.Bootstrap(); err != nil {
		log.Fatal(err)
	}
	defer app.ResetBootstrapState()
	if err = app.RunAppMigrations(); err != nil {
		log.Fatal(err)
	}
	if *diagnostics {
		if err = data.InstallDiagnostics(app); err != nil {
			log.Fatal(err)
		}
	}
	if err = seed(app, *diagnostics, time.Now()); err != nil {
		log.Fatal(err)
	}
	count := 7
	if *diagnostics {
		count = 10
	}
	fmt.Printf("Fresh database: %s\n%d application collections; example recording seeded.\n", path, count)
}

func seed(app core.App, diagnostics bool, now time.Time) error {
	policy := observer.DefaultPolicy()
	start := now.Add(-3*time.Minute).UnixMilli() / policy.ChunkMS * policy.ChunkMS
	session := data.Session{ID: data.ID("example-session"), Name: "Example · observed service activity", StartedMS: start, EndedMS: start + 120000, RetainedFromMS: start, Revision: 1, Policy: policy, GateAuditComplete: true, Diagnostics: data.Diagnostics{Flows: diagnostics, DNS: diagnostics}, Capture: data.CaptureHealth{Quality: "complete", ConfirmedMS: start + 120000, Epoch: "example", Generation: 1}}
	lat, lon := 59.3293, 18.0686
	destinations := []data.Destination{{ID: data.ID("example-stockholm"), IP: "203.0.113.10", Version: "illustrative", ObservedMS: start, City: "Stockholm", Country: "Sweden", CountryCode: "SE", Lat: &lat, Lon: &lon, Precision: "city", AccuracyKM: 50, Provider: "Example destination"}, {ID: data.ID("example-unknown"), IP: "203.0.113.20", Version: "illustrative", ObservedMS: start, Precision: "unknown"}}
	err := app.RunInTransaction(func(tx core.App) error {
		if _, err := data.Write(tx, "sessions", session); err != nil {
			return err
		}
		for _, d := range destinations {
			if _, err := data.Write(tx, "destinations", d); err != nil {
				return err
			}
		}
		for site := 0; site < 3; site++ {
			service := []string{"svt.se", "news.example", "endpoint:203.0.113.20|udp|443"}[site]
			label := []string{"svt.se", "news.example", "203.0.113.20"}[site]
			dest := destinations[0]
			protocol := "tcp"
			evidence := data.Attribution{Hostname: service, Source: "dns_answer", MatchedIP: dest.IP, ObservedMS: start, Confidence: "medium", PolicyVersion: session.Policy.Version}
			if site == 2 {
				dest = destinations[1]
				protocol = "udp"
				evidence = data.Attribution{Source: "destination_ip", MatchedIP: dest.IP, Confidence: "hidden", PolicyVersion: session.Policy.Version}
			}
			for elapsed := int64(0); elapsed < 120000; elapsed += policy.ChunkMS {
				if site == 0 && elapsed >= 25000 && elapsed < 90000 {
					continue
				}
				if site == 1 && (elapsed < 10000 || elapsed > 40000) {
					continue
				}
				if site == 2 && elapsed > 15000 {
					continue
				}
				c := data.TrafficChunk{ID: data.ID(service, fmt.Sprint(elapsed)), Session: session.ID, CaptureEpoch: "example", ClientID: "example-client", ClientIP: "10.0.0.100", ServiceKey: service, ServiceLabel: label, DestinationID: dest.ID, DestinationIP: dest.IP, Protocol: protocol, DestinationPort: 443, NetworkEpoch: "example-network", StartMS: start + elapsed, BucketMS: policy.BucketMS, ChunkMS: policy.ChunkMS, Generation: 1, Sealed: true, Evidence: evidence}
				for offset := int64(0); offset+policy.BucketMS <= min(1500, policy.ChunkMS, 120000-elapsed); offset += policy.BucketMS {
					c.Samples = append(c.Samples, data.Sample{offset, 150, 3000 + int64(site)*500, 90, 2880 + int64(site)*500, 1, 2})
				}
				if _, err := data.Write(tx, "traffic_chunks", c); err != nil {
					return err
				}
			}
		}
		if _, err := data.Write(tx, "capture_intervals", data.CaptureInterval{ID: data.ID("example-coverage"), Session: session.ID, CaptureEpoch: "example", StartMS: start, EndMS: start + 120000, Quality: "complete"}); err != nil {
			return err
		}
		if diagnostics {
			_, err := data.Write(tx, "dns_queries", map[string]any{"id": data.ID("example-dns"), "session": session.ID, "client_ip": "10.0.0.100", "query_name": "www.svt.se", "query_type": "A", "answers": []string{destinations[0].IP}, "aliases": []string{}, "observed_ms": start, "source": "example"})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return observer.RebuildBlocks(app, session.ID, session.EndedMS)
}
