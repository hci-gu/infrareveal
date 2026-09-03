package debugtrace

import (
	"fmt"
	"hash/fnv"
	"sort"
	"time"
)

const burstBucketDuration = 50 * time.Millisecond

type burstKey struct {
	sessionID string
	bucketMs  int64
	flowKey   string
	direction Direction
}

type burstGroup struct {
	input BurstInput
	key   burstKey
}

type burstCoalescer struct {
	groups    map[burstKey]*burstGroup
	maxGroups int
}

func newBurstCoalescer(maxGroups int) *burstCoalescer {
	return &burstCoalescer{groups: make(map[burstKey]*burstGroup), maxGroups: max(1, maxGroups)}
}

func (coalescer *burstCoalescer) add(input BurstInput) ([]Event, bool) {
	if input.SessionID == "" || input.TraceID == "" || input.FlowKey == "" || input.OccurredAtMs < 0 ||
		(input.Direction != ClientToRemote && input.Direction != RemoteToClient) {
		return nil, false
	}
	bucketMs := input.OccurredAtMs / burstBucketDuration.Milliseconds() * burstBucketDuration.Milliseconds()
	flushed := coalescer.flushBefore(bucketMs)
	key := burstKey{sessionID: input.SessionID, bucketMs: bucketMs, flowKey: input.FlowKey, direction: input.Direction}
	if group := coalescer.groups[key]; group != nil {
		group.input.WireBytes += input.WireBytes
		group.input.PayloadBytes += input.PayloadBytes
		group.input.PacketCount += input.PacketCount
		group.input.TCPFlags |= input.TCPFlags
		return flushed, true
	}
	if len(coalescer.groups) >= coalescer.maxGroups {
		return flushed, false
	}
	input.OccurredAtMs = bucketMs
	coalescer.groups[key] = &burstGroup{input: input, key: key}
	return flushed, true
}

func (coalescer *burstCoalescer) flushBefore(cutoffMs int64) []Event {
	var groups []*burstGroup
	for key, group := range coalescer.groups {
		if key.bucketMs < cutoffMs {
			groups = append(groups, group)
			delete(coalescer.groups, key)
		}
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].key.bucketMs != groups[j].key.bucketMs {
			return groups[i].key.bucketMs < groups[j].key.bucketMs
		}
		return burstGroupID(groups[i].key) < burstGroupID(groups[j].key)
	})
	events := make([]Event, 0, len(groups))
	for _, group := range groups {
		wireBytes := group.input.WireBytes
		payloadBytes := group.input.PayloadBytes
		packetCount := group.input.PacketCount
		tcpFlags := group.input.TCPFlags
		events = append(events, Event{
			ID: burstGroupID(group.key), SessionID: group.input.SessionID, TraceID: group.input.TraceID,
			Kind: KindBurst, Stage: StageHeaderCapture, Direction: group.input.Direction,
			OccurredAtMs: group.key.bucketMs, Timing: TimingObserved,
			Summary: Summary{
				Protocol: group.input.Protocol, FlowKey: group.input.FlowKey, WireBytes: &wireBytes, PayloadBytes: &payloadBytes,
				PacketCount: &packetCount, TCPFlags: &tcpFlags,
			},
		})
	}
	return events
}

func burstGroupID(key burstKey) string {
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(key.flowKey))
	return fmt.Sprintf("live-burst:%s:%d:%x:%s", key.sessionID, key.bucketMs, hash.Sum64(), key.direction)
}
