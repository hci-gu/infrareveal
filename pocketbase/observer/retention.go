package observer

import (
	"fmt"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"myapp/data"
)

// PruneSession shares the maintenance transaction. Crossing immutable prefixes
// lose only the newly expired contributions; the correction tail is replayed
// after deletion. The caller advances retained_from_ms in this same commit.
func PruneSession(app core.App, session string, cutoffMS int64) error {
	return pruneSession(app, session, cutoffMS, time.Now().UnixMilli())
}

func pruneSession(app core.App, session string, cutoffMS, nowMS int64) error {
	record, err := app.FindRecordById("sessions", session)
	if err != nil {
		return err
	}
	s, err := data.Decode[data.Session](record)
	if err != nil {
		return err
	}
	if s.Policy.BucketMS <= 0 {
		s.Policy = DefaultPolicy()
	}
	cutoffMS = max(s.StartedMS, s.RetainedFromMS, cutoffMS)
	cutoffMS = (cutoffMS + s.Policy.BucketMS - 1) / s.Policy.BucketMS * s.Policy.BucketMS
	// Catch up once if maintenance overtook projection. Expiring bins are no
	// longer correctable, including the deleted part of an unsealed chunk.
	if record.GetInt64("block_watermark_ms") < cutoffMS {
		if _, err := rebuildBlocks(app, s, max(s.StartedMS, s.RetainedFromMS), nowMS, cutoffMS); err != nil {
			return err
		}
		record, err = app.FindRecordById("sessions", session)
		if err != nil {
			return err
		}
		s.Revision = record.GetInt64("revision")
	}
	p := dbx.Params{"s": session, "cut": cutoffMS}
	crossing, err := readRecords[storedBlock](app, "activity_blocks", "session={:s} AND start_ms<{:cut} AND end_ms>{:cut}", p)
	if err != nil {
		return err
	}
	prefixes := map[string]*storedBlock{}
	first := map[string]int64{}
	from, to := cutoffMS, cutoffMS
	for i := range crossing {
		b := &crossing[i]
		if b.Prefix == nil || b.Prefix.Block.ActiveMS == 0 || b.Prefix.Block.StartMS >= cutoffMS {
			continue
		}
		prefix := b.Prefix
		if prefix.Block.EndMS <= cutoffMS {
			// There is retained mutable activity, but none of its immutable
			// prefix remains. Keep only its identity and continuity proof.
			prefix.Block.Sent, prefix.Block.Received, prefix.Block.ActiveMS = 0, 0, 0
			prefix.Confidence = map[string]int64{}
			prefix.PartialMS, prefix.UnknownMS = 0, 0
			prefix.AckSent, prefix.AckReceived = 0, 0
			continue
		}
		key := blockGroup(b.ClientID, b.ServiceKey)
		prefixes[key] = b
		from = min(from, prefix.Block.StartMS)
		to = max(to, min(prefix.Block.EndMS, cutoffMS+s.Policy.QuietGapMS+s.Policy.BucketMS))
	}
	// A crossing block's next payload is at most one quiet gap away. Leading
	// ACK-only bins after the cutoff are outside its newly displayed span.
	if len(prefixes) > 0 {
		if _, err := walkBins(app, session, s.Policy, cutoffMS, to, func(c data.TrafficChunk, bin activityBin) error {
			key := blockGroup(c.ClientID, c.ServiceKey)
			b := prefixes[key]
			if b != nil && bin.active && bin.end <= b.Prefix.Block.EndMS {
				if _, ok := first[key]; !ok {
					first[key] = bin.start
				}
			}
			return nil
		}); err != nil {
			return err
		}
		for key, b := range prefixes {
			if _, ok := first[key]; !ok {
				return fmt.Errorf("crossing block %s has no retained payload", b.ID)
			}
		}
		end := cutoffMS
		for _, at := range first {
			end = max(end, at)
		}
		if _, err := walkBins(app, session, s.Policy, from, end, func(c data.TrafficChunk, bin activityBin) error {
			key := blockGroup(c.ClientID, c.ServiceKey)
			b := prefixes[key]
			if b == nil || bin.start < b.Prefix.Block.StartMS || bin.end > first[key] {
				return nil
			}
			prefix := b.Prefix
			prefix.Block.Sent -= bin.sent
			prefix.Block.Received -= bin.received
			if bin.active {
				prefix.Block.ActiveMS -= bin.end - bin.start
				prefix.Confidence[bin.confidence]--
			}
			return nil
		}); err != nil {
			return err
		}
		coverage, err := readCoverage(app, session, from, end)
		if err != nil {
			return err
		}
		for key, b := range prefixes {
			prefix := b.Prefix
			partial, unknown := coverageDuration(coverage, prefix.Block.StartMS, first[key])
			prefix.PartialMS -= partial
			prefix.UnknownMS -= unknown
			prefix.Block.StartMS = first[key]
		}
	}
	changed := false
	for _, b := range crossing {
		if b.Prefix == nil {
			continue
		}
		if !b.PrefixOpen {
			b.ActivityBlock = b.Prefix.summary(nowMS, s.Policy)
			b.Revision = s.Revision + 1
			changed = true
		}
		if _, err := data.Write(app, "activity_blocks", b); err != nil {
			return err
		}
	}
	deleted, err := app.DB().NewQuery("DELETE FROM activity_blocks WHERE session={:s} AND end_ms<={:cut}").Bind(p).Execute()
	if err != nil {
		return err
	}
	if count, err := deleted.RowsAffected(); err != nil {
		return err
	} else {
		changed = changed || count > 0
	}
	if _, err = app.DB().NewQuery("DELETE FROM traffic_chunks WHERE session={:s} AND start_ms+chunk_ms<= {:cut}").Bind(p).Execute(); err != nil {
		return err
	}
	// Keyset paging also bounds many bindings in the one crossing source chunk.
	if _, err = walkTraffic(app, session, s.Policy, cutoffMS, cutoffMS, func(c data.TrafficChunk) error {
		c.Samples = clipSamples(c, cutoffMS)
		if len(c.Samples) == 0 {
			_, err := app.DB().Delete("traffic_chunks", dbx.HashExp{"id": c.ID}).Execute()
			return err
		}
		_, err := data.Write(app, "traffic_chunks", c)
		return err
	}); err != nil {
		return err
	}
	if _, err = app.DB().NewQuery("DELETE FROM capture_intervals WHERE session={:s} AND end_ms<= {:cut}").Bind(p).Execute(); err != nil {
		return err
	}
	if _, err = app.DB().NewQuery("UPDATE capture_intervals SET start_ms={:cut} WHERE session={:s} AND start_ms < {:cut}").Bind(p).Execute(); err != nil {
		return err
	}
	if changed {
		if err := data.BumpRevision(app, session); err != nil {
			return err
		}
		s.Revision++
	}
	s.RetainedFromMS = cutoffMS
	_, err = rebuildBlocks(app, s, cutoffMS, nowMS, cutoffMS)
	return err
}
