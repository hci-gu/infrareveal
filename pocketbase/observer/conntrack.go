package observer

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
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

func (f FlowSample) Key() string {
	return fmt.Sprintf("%s|%s|%d|%s|%d", f.Protocol, f.ClientIP, f.SourcePort, f.DestinationIP, f.DestinationPort)
}

func StartConntrackSampler(ctx context.Context, app *pocketbase.PocketBase, path string, clientPrefix string, sessionID func() string) {
	if clientPrefix == "" {
		clientPrefix = "10.0.0."
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
				samples, err := ReadConntrackSamples(path, clientPrefix)
				if err != nil {
					if !loggedMissing {
						log.Printf("conntrack observer unavailable at %s: %v", path, err)
						loggedMissing = true
					}
					continue
				}
				loggedMissing = false
				for _, sample := range samples {
					if err := upsertFlow(app, sessionID, sample); err != nil {
						log.Printf("conntrack observer save flow error: %v", err)
					}
				}
			}
		}
	}()
}

func ReadConntrackSamples(path string, clientPrefix string) ([]FlowSample, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var samples []FlowSample
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		sample, ok := ParseConntrackLine(scanner.Text(), clientPrefix)
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
	if clientPrefix != "" && !strings.HasPrefix(clientIP, clientPrefix) {
		return FlowSample{}, false
	}

	destinationIP := original["dst"]
	if clientIP == "" || destinationIP == "" {
		return FlowSample{}, false
	}

	destinationPort := parseInt(original["dport"])
	if protocol != "icmp" && destinationPort == 0 {
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
