package observer

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"io"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
)

var (
	dnsQueryRE = regexp.MustCompile(`\bquery\[([^\]]+)\]\s+(\S+)\s+from\s+(\S+)`)
	dnsReplyRE = regexp.MustCompile(`\b(?:reply|cached)\s+(\S+)\s+is\s+(\S+)`)
)

type recentDNSQuery struct {
	recordID string
	clientIP string
	seenAt   time.Time
}

type DNSMasqIngestor struct {
	app          *pocketbase.PocketBase
	path         string
	sessionID    func() string
	mu           sync.Mutex
	recentByName map[string][]recentDNSQuery
}

func StartDNSMasqIngestor(ctx context.Context, app *pocketbase.PocketBase, path string, sessionID func() string) {
	ingestor := &DNSMasqIngestor{
		app:          app,
		path:         path,
		sessionID:    sessionID,
		recentByName: make(map[string][]recentDNSQuery),
	}
	go ingestor.run(ctx)
}

func (d *DNSMasqIngestor) run(ctx context.Context) {
	for {
		if err := d.follow(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("dnsmasq observer waiting for %s: %v", d.path, err)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (d *DNSMasqIngestor) follow(ctx context.Context) error {
	file, err := os.Open(d.path)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		return err
	}

	reader := bufio.NewReader(file)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				time.Sleep(300 * time.Millisecond)
				continue
			}
			return err
		}
		d.handleLine(strings.TrimSpace(line))
	}
}

func (d *DNSMasqIngestor) handleLine(line string) {
	if matches := dnsQueryRE.FindStringSubmatch(line); len(matches) == 4 {
		d.recordQuery(matches[3], matches[2], matches[1])
		return
	}

	if matches := dnsReplyRE.FindStringSubmatch(line); len(matches) == 3 {
		d.recordAnswer(matches[1], matches[2])
	}
}

func (d *DNSMasqIngestor) recordQuery(clientIP, queryName, queryType string) {
	sessionID := d.sessionID()
	if sessionID == "" {
		return
	}

	collection, err := d.app.FindCollectionByNameOrId("dns_queries")
	if err != nil {
		log.Printf("dnsmasq observer collection error: %v", err)
		return
	}

	now := time.Now().UTC()
	record := core.NewRecord(collection)
	record.Set("session", sessionID)
	record.Set("client_ip", clientIP)
	record.Set("query_name", strings.TrimSuffix(strings.ToLower(queryName), "."))
	record.Set("query_type", queryType)
	record.Set("answers", []string{})
	record.Set("timestamp", now.Format(time.RFC3339))
	record.Set("source", "dnsmasq")

	if err := d.app.Save(record); err != nil {
		log.Printf("dnsmasq observer save query error: %v", err)
		return
	}

	key := normalizeDNSName(queryName)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pruneLocked(now)
	d.recentByName[key] = append(d.recentByName[key], recentDNSQuery{
		recordID: record.Id,
		clientIP: clientIP,
		seenAt:   now,
	})
}

func (d *DNSMasqIngestor) recordAnswer(queryName, answer string) {
	key := normalizeDNSName(queryName)
	now := time.Now().UTC()

	d.mu.Lock()
	d.pruneLocked(now)
	recent := append([]recentDNSQuery(nil), d.recentByName[key]...)
	d.mu.Unlock()

	for _, item := range recent {
		record, err := d.app.FindRecordById("dns_queries", item.recordID)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				log.Printf("dnsmasq observer find query error: %v", err)
			}
			continue
		}
		answers := record.GetStringSlice("answers")
		if containsString(answers, answer) {
			continue
		}
		answers = append(answers, answer)
		record.Set("answers", answers)
		if err := d.app.Save(record); err != nil {
			log.Printf("dnsmasq observer save answer error: %v", err)
		}
	}
}

func (d *DNSMasqIngestor) pruneLocked(now time.Time) {
	cutoff := now.Add(-45 * time.Second)
	for name, items := range d.recentByName {
		kept := items[:0]
		for _, item := range items {
			if item.seenAt.After(cutoff) {
				kept = append(kept, item)
			}
		}
		if len(kept) == 0 {
			delete(d.recentByName, name)
		} else {
			d.recentByName[name] = kept
		}
	}
}

func normalizeDNSName(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".")
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
