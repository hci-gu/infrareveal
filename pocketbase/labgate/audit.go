package labgate

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

type auditItem struct {
	terminal bool
	decision Decision
	flush    chan struct{}
}

// AuditWriter owns persistence ordering and is deliberately separated from
// kernel verdicts by a bounded non-blocking queue.
type AuditWriter struct {
	app            core.App
	items          chan auditItem
	dropped        atomic.Uint64
	closeOnce      sync.Once
	mu             sync.RWMutex
	closed         bool
	done           chan struct{}
	dropsMu        sync.Mutex
	dropsBySession map[string]uint64
}

func NewAuditWriter(app core.App, capacity int) *AuditWriter {
	if capacity < 8 {
		capacity = 8
	}
	writer := &AuditWriter{app: app, items: make(chan auditItem, capacity), done: make(chan struct{}), dropsBySession: make(map[string]uint64)}
	go writer.run()
	return writer
}

func (writer *AuditWriter) TryQueued(decision Decision) bool {
	return writer.try(auditItem{decision: decision})
}
func (writer *AuditWriter) TryTerminal(decision Decision) bool {
	return writer.try(auditItem{terminal: true, decision: decision})
}
func (writer *AuditWriter) Dropped() uint64 { return writer.dropped.Load() }

func (writer *AuditWriter) try(item auditItem) bool {
	writer.mu.RLock()
	defer writer.mu.RUnlock()
	if writer.closed {
		writer.recordDrop(item.decision.SessionID)
		return false
	}
	select {
	case writer.items <- item:
		return true
	default:
		writer.recordDrop(item.decision.SessionID)
		return false
	}
}

// Flush waits until all audit items accepted before this call have completed.
// It is used only after traffic has been drained, never on the verdict path.
func (writer *AuditWriter) Flush(ctx context.Context) error {
	writer.mu.RLock()
	if writer.closed {
		writer.mu.RUnlock()
		return nil
	}
	ack := make(chan struct{})
	select {
	case writer.items <- auditItem{flush: ack}:
		writer.mu.RUnlock()
	case <-ctx.Done():
		writer.mu.RUnlock()
		return ctx.Err()
	}
	select {
	case <-ack:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (writer *AuditWriter) DroppedForSession(sessionID string) uint64 {
	writer.dropsMu.Lock()
	defer writer.dropsMu.Unlock()
	return writer.dropsBySession[sessionID]
}

func (writer *AuditWriter) recordDrop(sessionID string) {
	writer.dropped.Add(1)
	if sessionID == "" {
		return
	}
	writer.dropsMu.Lock()
	writer.dropsBySession[sessionID]++
	writer.dropsMu.Unlock()
}

func (writer *AuditWriter) Close(ctx context.Context) error {
	writer.closeOnce.Do(func() {
		writer.mu.Lock()
		writer.closed = true
		close(writer.items)
		writer.mu.Unlock()
	})
	select {
	case <-writer.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (writer *AuditWriter) run() {
	defer close(writer.done)
	for item := range writer.items {
		if item.flush != nil {
			close(item.flush)
			continue
		}
		var err error
		for attempt := 0; attempt < 3; attempt++ {
			if item.terminal {
				err = writer.persistTerminal(item.decision)
			} else {
				err = writer.persistQueued(item.decision)
			}
			if err == nil {
				break
			}
			time.Sleep(time.Duration(20*(attempt+1)) * time.Millisecond)
		}
		if err != nil {
			writer.recordDrop(item.decision.SessionID)
		}
	}
}

func (writer *AuditWriter) persistQueued(decision Decision) error {
	if _, err := writer.find(decision); err == nil {
		return nil
	}
	collection, err := writer.app.FindCollectionByNameOrId("gate_events")
	if err != nil {
		return err
	}
	record := core.NewRecord(collection)
	setAuditRecord(record, decision)
	return writer.app.Save(record)
}

func (writer *AuditWriter) persistTerminal(decision Decision) error {
	record, err := writer.find(decision)
	if err != nil {
		collection, collectionErr := writer.app.FindCollectionByNameOrId("gate_events")
		if collectionErr != nil {
			return collectionErr
		}
		record = core.NewRecord(collection)
	}
	if record.GetString("state") != "" && record.GetString("state") != string(DecisionQueued) {
		return nil
	}
	setAuditRecord(record, decision)
	return writer.app.Save(record)
}

func (writer *AuditWriter) find(decision Decision) (*core.Record, error) {
	records, err := writer.app.FindRecordsByFilter("gate_events", "session={:session} && decision_id={:decision}", "", 1, 0, dbx.Params{"session": decision.SessionID, "decision": decision.ID})
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("gate audit record not found")
	}
	return records[0], nil
}

func setAuditRecord(record *core.Record, decision Decision) {
	record.Set("session", decision.SessionID)
	record.Set("decision_id", decision.ID)
	record.Set("flow_key", decision.FlowKey)
	record.Set("client_ip", decision.ClientIP)
	record.Set("destination_ip", decision.RemoteIP)
	record.Set("source_port", decision.ClientPort)
	record.Set("destination_port", decision.RemotePort)
	record.Set("protocol", decision.Protocol)
	record.Set("mode", string(decision.Mode))
	record.Set("direction", string(decision.Direction))
	record.Set("wire_bytes", decision.WireBytes)
	record.Set("payload_bytes", decision.PayloadBytes)
	record.Set("tcp_flags", decision.TCPFlags)
	record.Set("packet_count", decision.PacketCount)
	record.Set("state", string(decision.State))
	record.Set("actor", decision.Actor)
	record.Set("reason", decision.Reason)
	record.Set("verdict_source", string(decision.Source))
	record.Set("queued_at", decision.QueuedAt.UTC().Format(time.RFC3339Nano))
	if !decision.DecidedAt.IsZero() {
		record.Set("decided_at", decision.DecidedAt.UTC().Format(time.RFC3339Nano))
	}
	record.Set("wait_ms", decision.WaitMS)
}
