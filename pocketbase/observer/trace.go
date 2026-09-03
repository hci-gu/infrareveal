package observer

import (
	"fmt"
	"time"

	"myapp/debugtrace"
)

func usableTraceSink(sink debugtrace.Sink) debugtrace.Sink {
	if sink == nil {
		return debugtrace.NopSink{}
	}
	return sink
}

func tracePort(value int) *uint16 {
	if value <= 0 || value > 65535 {
		return nil
	}
	port := uint16(value)
	return &port
}

func traceCount(value int64) *uint64 {
	count := uint64(max(value, 0))
	return &count
}

func traceProcessedNow() *int64 {
	now := time.Now().UnixMilli()
	return &now
}

func traceEventID(prefix, recordID string, occurredAt time.Time) string {
	return fmt.Sprintf("%s:%s:%d", prefix, recordID, occurredAt.UnixMilli())
}
