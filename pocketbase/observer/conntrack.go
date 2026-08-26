package observer

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
)

type FlowSample struct {
	Protocol        string
	State           string
	ClientIP        string
	DestinationIP   string
	SourcePort      int
	DestinationPort int
	PacketsOut      int64
	PacketsIn       int64
	BytesOut        int64
	BytesIn         int64
}

type ConntrackSampler struct {
	path       string
	scope      ObservationScope
	mu         sync.Mutex
	suppressed map[string]struct{}
}

func (f FlowSample) Key() string {
	return flowKey(f.Protocol, f.ClientIP, f.SourcePort, f.DestinationIP, f.DestinationPort)
}

func NewConntrackSampler(path string, scope ObservationScope) *ConntrackSampler {
	return &ConntrackSampler{
		path:       path,
		scope:      scope,
		suppressed: make(map[string]struct{}),
	}
}

func StartConntrackSampler(ctx context.Context, app *pocketbase.PocketBase, path string, scope ObservationScope, sessionID func() string) *ConntrackSampler {
	sampler := NewConntrackSampler(path, scope)
	accountingPath := os.Getenv("CONNTRACK_ACCOUNTING_PATH")
	if accountingPath == "" {
		accountingPath = "/proc/sys/net/netfilter/nf_conntrack_acct"
	}
	if enabled, err := ensureConntrackAccounting(accountingPath); err != nil {
		log.Printf("conntrack accounting unavailable at %s: %v; byte and packet counters may remain zero", accountingPath, err)
	} else if enabled {
		log.Printf("conntrack accounting enabled at %s; new flows will include byte and packet counters", accountingPath)
	}

	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		var loggedMissing bool
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sessionID := sessionID()
				if sessionID == "" {
					continue
				}
				err := sampler.sampleAndPersist(app, sessionID)
				if err != nil {
					if !loggedMissing {
						log.Printf("conntrack observer unavailable at %s: %v", path, err)
						loggedMissing = true
					}
					continue
				}
				loggedMissing = false
			}
		}
	}()

	return sampler
}

func (sampler *ConntrackSampler) SuppressCurrentFlows() error {
	sampler.mu.Lock()
	defer sampler.mu.Unlock()

	samples, err := ReadConntrackSamples(sampler.path, sampler.scope)
	if err != nil {
		return err
	}
	for _, sample := range samples {
		sampler.suppressed[sample.Key()] = struct{}{}
	}
	return nil
}

func (sampler *ConntrackSampler) ReadUnsuppressedSamples() ([]FlowSample, error) {
	sampler.mu.Lock()
	defer sampler.mu.Unlock()
	return sampler.readUnsuppressedSamples()
}

func (sampler *ConntrackSampler) readUnsuppressedSamples() ([]FlowSample, error) {
	samples, err := ReadConntrackSamples(sampler.path, sampler.scope)
	if err != nil {
		return nil, err
	}

	present := make(map[string]struct{}, len(samples))
	for _, sample := range samples {
		present[sample.Key()] = struct{}{}
	}
	for key := range sampler.suppressed {
		if _, ok := present[key]; !ok {
			delete(sampler.suppressed, key)
		}
	}

	result := make([]FlowSample, 0, len(samples))
	for _, sample := range samples {
		if _, suppressed := sampler.suppressed[sample.Key()]; !suppressed {
			result = append(result, sample)
		}
	}
	return result, nil
}

func (sampler *ConntrackSampler) sampleAndPersist(app *pocketbase.PocketBase, sessionID string) error {
	sampler.mu.Lock()
	defer sampler.mu.Unlock()

	samples, err := sampler.readUnsuppressedSamples()
	if err != nil {
		return err
	}
	for _, sample := range samples {
		if err := upsertFlow(app, sessionID, sample); err != nil {
			return err
		}
	}
	return nil
}

func ensureConntrackAccounting(path string) (bool, error) {
	if path == "" {
		return false, nil
	}

	value, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(string(value)) == "1" {
		return false, nil
	}

	if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
		return false, err
	}
	return true, nil
}

func ReadConntrackSamples(path string, scope ObservationScope) ([]FlowSample, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var samples []FlowSample
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		sample, ok := parseConntrackLine(scanner.Text(), scope)
		if ok {
			samples = append(samples, sample)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return samples, nil
}

func ParseConntrackLine(line string, clientPrefix string) (FlowSample, bool) {
	return parseConntrackLine(line, NewObservationScope(clientPrefix, ""))
}

func parseConntrackLine(line string, scope ObservationScope) (FlowSample, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return FlowSample{}, false
	}

	protocol := ""
	protocolIndex := -1
	for i, field := range fields {
		switch field {
		case "tcp", "udp", "icmp":
			protocol = field
			protocolIndex = i
		}
	}
	if protocol == "" {
		return FlowSample{}, false
	}

	state := ""
	if protocol == "tcp" && protocolIndex+3 < len(fields) && !strings.Contains(fields[protocolIndex+3], "=") {
		state = fields[protocolIndex+3]
	}

	original := map[string]string{}
	reply := map[string]string{}
	current := original
	for _, field := range fields[protocolIndex+1:] {
		if !strings.Contains(field, "=") {
			continue
		}
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		if key == "src" && len(original) > 0 {
			current = reply
		}
		current[key] = value
	}

	clientIP := original["src"]
	destinationIP := original["dst"]
	destinationPort := parseInt(original["dport"])
	if protocol != "icmp" && destinationPort == 0 {
		return FlowSample{}, false
	}
	if !scope.Includes(protocol, clientIP, destinationIP, destinationPort) {
		return FlowSample{}, false
	}

	return FlowSample{
		Protocol:        protocol,
		State:           state,
		ClientIP:        clientIP,
		DestinationIP:   destinationIP,
		SourcePort:      parseInt(original["sport"]),
		DestinationPort: destinationPort,
		PacketsOut:      parseInt64(original["packets"]),
		PacketsIn:       parseInt64(reply["packets"]),
		BytesOut:        parseInt64(original["bytes"]),
		BytesIn:         parseInt64(reply["bytes"]),
	}, true
}

func upsertFlow(app *pocketbase.PocketBase, sessionID string, sample FlowSample) error {
	now := time.Now().UTC().Format(time.RFC3339)
	key := sample.Key()

	record, err := app.FindFirstRecordByFilter(
		"flows",
		"session={:session} && flow_key={:flow_key}",
		dbx.Params{"session": sessionID, "flow_key": key},
	)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		collection, err := app.FindCollectionByNameOrId("flows")
		if err != nil {
			return err
		}
		record = core.NewRecord(collection)
		record.Set("session", sessionID)
		record.Set("flow_key", key)
		record.Set("client_ip", sample.ClientIP)
		record.Set("destination_ip", sample.DestinationIP)
		record.Set("source_port", sample.SourcePort)
		record.Set("destination_port", sample.DestinationPort)
		record.Set("protocol", sample.Protocol)
		record.Set("start", now)
		record.Set("source", "conntrack")
	}

	record.Set("state", sample.State)
	record.Set("last_seen", now)
	record.Set("bytes_out", sample.BytesOut)
	record.Set("bytes_in", sample.BytesIn)
	record.Set("packets_out", sample.PacketsOut)
	record.Set("packets_in", sample.PacketsIn)

	return app.Save(record)
}

func parseInt(value string) int {
	n, _ := strconv.Atoi(value)
	return n
}

func parseInt64(value string) int64 {
	n, _ := strconv.ParseInt(value, 10, 64)
	return n
}
