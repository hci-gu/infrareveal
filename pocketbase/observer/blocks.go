package observer

import (
	"database/sql"
	"fmt"
	"maps"
	"reflect"
	"sort"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"myapp/data"
)

type activityBin struct {
	start, end, sent, received int64
	active                     bool
	confidence                 string
}

func intervalQuality(coverage []data.CaptureInterval, start, end int64) string {
	if end <= start {
		return "complete"
	}
	position, quality := start, "complete"
	for _, c := range coverage {
		if c.EndMS <= position || c.StartMS >= end {
			continue
		}
		if c.StartMS > position || c.Quality == "unavailable" {
			return "unknown"
		}
		if c.Quality != "complete" {
			quality = "partial"
		}
		position = max(position, c.EndMS)
		if position >= end {
			return quality
		}
	}
	return "unknown"
}

// ProjectBlocks has no storage or clock dependencies. Anchors retain identity
// across pruning; all displayed totals are recomputed solely from retained bins.
func ProjectBlocks(chunks []data.TrafficChunk, coverage []data.CaptureInterval, anchors []data.ActivityBlock, policy data.Policy, from, now int64) []data.ActivityBlock {
	coverage = append([]data.CaptureInterval(nil), coverage...)
	sort.Slice(coverage, func(i, j int) bool { return coverage[i].StartMS < coverage[j].StartMS })
	groups := map[string][]*data.TrafficChunk{}
	anchorGroups := map[string][]data.ActivityBlock{}
	usedAnchors := map[string]bool{}
	groupKey := func(session, client, service string) string { return session + "|" + client + "|" + service }
	for i := range chunks {
		c := &chunks[i]
		key := groupKey(c.Session, c.ClientID, c.ServiceKey)
		groups[key] = append(groups[key], c)
	}
	for _, a := range anchors {
		key := groupKey(a.Session, a.ClientID, a.ServiceKey)
		anchorGroups[key] = append(anchorGroups[key], a)
	}
	result := []data.ActivityBlock{}
	// Only one chunk's bins need to be materialized at once. A long recording
	// costs time proportional to its samples, not one heap object per sample.
	bucket := policy.BucketMS
	if bucket <= 0 {
		bucket = 50
	}
	chunkSize := policy.ChunkMS
	if chunkSize <= 0 {
		chunkSize = 5000
	}
	for key, group := range groups {
		sort.Slice(group, func(i, j int) bool { return group[i].StartMS < group[j].StartMS })
		bins := make([]activityBin, chunkSize/bucket)
		used := make([]bool, len(bins))
		var current *data.ActivityBlock
		var ackSent, ackReceived int64
		finish := func() {
			if current == nil {
				return
			}
			current.Quality = intervalQuality(coverage, current.StartMS, current.EndMS)
			current.Provisional = now < current.EndMS+policy.QuietGapMS+policy.CorrectionMS
			for _, a := range anchorGroups[key] {
				if !usedAnchors[a.ID] && a.OriginalStartMS < from && a.EndMS > from && a.EndMS > current.StartMS && a.OriginalStartMS < current.OriginalStartMS {
					current.ID = a.ID
					current.OriginalStartMS = a.OriginalStartMS
					usedAnchors[a.ID] = true
				}
			}
			current.Clipped = current.OriginalStartMS < current.StartMS
			result = append(result, *current)
		}
		for cursor := 0; cursor < len(group); {
			start := group[cursor].StartMS
			representative := group[cursor]
			clear(bins)
			clear(used)
			for cursor < len(group) && group[cursor].StartMS == start {
				c := group[cursor]
				cursor++
				for _, sample := range c.Samples {
					at, end := c.StartMS+sample[0], c.StartMS+sample[0]+c.BucketMS
					if at < from || end > now {
						continue
					}
					index := sample[0] / bucket
					if index < 0 || index >= int64(len(bins)) {
						continue
					}
					bin := &bins[index]
					if !used[index] {
						*bin = activityBin{start: at, end: end, confidence: c.Evidence.Confidence}
						used[index] = true
					}
					if bin.confidence != c.Evidence.Confidence {
						bin.confidence = "mixed"
					}
					bin.sent += sample[1]
					bin.received += sample[2]
					bin.active = bin.active || sample[3]+sample[4] > 0
				}
			}
			for i, bin := range bins {
				if !used[i] {
					continue
				}
				if !bin.active {
					if current != nil {
						ackSent += bin.sent
						ackReceived += bin.received
					}
					continue
				}
				if current == nil || bin.start-current.EndMS > policy.QuietGapMS || intervalQuality(coverage, current.EndMS, bin.start) == "unknown" {
					finish()
					c := representative
					current = &data.ActivityBlock{ID: data.ID(c.Session, c.ClientID, c.ServiceKey, fmt.Sprint(bin.start)), Session: c.Session, ClientID: c.ClientID, ClientIP: c.ClientIP, ServiceKey: c.ServiceKey, ServiceLabel: c.ServiceLabel, OriginalStartMS: bin.start, StartMS: bin.start, EndMS: bin.start, Confidence: bin.confidence}
				} else {
					current.Sent += ackSent
					current.Received += ackReceived
				}
				ackSent = 0
				ackReceived = 0
				current.Sent += bin.sent
				current.Received += bin.received
				current.ActiveMS += max(0, bin.end-max(bin.start, current.EndMS))
				current.EndMS = max(current.EndMS, bin.end)
				if current.Confidence != bin.confidence {
					current.Confidence = "mixed"
				}
			}
		}
		finish()
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].StartMS == result[j].StartMS {
			return result[i].ID < result[j].ID
		}
		return result[i].StartMS < result[j].StartMS
	})
	return result
}

func readRecords[T any](app core.App, name, filter string, params dbx.Params) ([]T, error) {
	rows, err := app.FindAllRecords(name, dbx.NewExp(filter, params))
	if err != nil {
		return nil, err
	}
	out := make([]T, 0, len(rows))
	for _, r := range rows {
		v, err := data.Decode[T](r)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// blockPrefix contains only the sufficient statistics of immutable bins. The
// pending ACKs and coverage belong to the gap after the last payload bin; they
// are included only if a later payload joins this block. No sample history is
// retained in this private, size-limited field.
type blockPrefix struct {
	Block       data.ActivityBlock `json:"block"`
	Confidence  map[string]int64   `json:"confidence"`
	PartialMS   int64              `json:"partial_ms"`
	UnknownMS   int64              `json:"unknown_ms"`
	AckSent     int64              `json:"ack_sent"`
	AckReceived int64              `json:"ack_received"`
	GapPartial  int64              `json:"gap_partial"`
	GapUnknown  int64              `json:"gap_unknown"`
}

type storedBlock struct {
	data.ActivityBlock
	Prefix     *blockPrefix `json:"block_prefix"`
	PrefixOpen bool         `json:"prefix_open"`
}

func (p blockPrefix) clone() *blockPrefix {
	p.Confidence = maps.Clone(p.Confidence)
	return &p
}

func (p *blockPrefix) summary(now int64, policy data.Policy) data.ActivityBlock {
	b := p.Block
	b.Confidence = ""
	first := true
	for confidence, count := range p.Confidence {
		if count <= 0 {
			continue
		}
		if first {
			b.Confidence = confidence
			first = false
		} else {
			b.Confidence = "mixed"
		}
	}
	b.Quality = "complete"
	if p.PartialMS > 0 {
		b.Quality = "partial"
	}
	if p.UnknownMS > 0 {
		b.Quality = "unknown"
	}
	b.Clipped = b.OriginalStartMS < b.StartMS
	b.Provisional = now < b.EndMS+policy.QuietGapMS+policy.CorrectionMS
	return b
}

// coverageDuration follows the same first-covered-interval rule as
// intervalQuality. Durations, unlike a single worst-quality label, can be
// subtracted exactly when the retained start advances.
func coverageDuration(coverage []data.CaptureInterval, start, end int64) (partial, unknown int64) {
	if end <= start {
		return 0, 0
	}
	position := start
	for _, c := range coverage {
		if c.EndMS <= position || c.StartMS >= end {
			continue
		}
		if c.StartMS > position {
			unknown += c.StartMS - position
			position = c.StartMS
		}
		next := min(end, c.EndMS)
		if c.Quality == "unavailable" {
			unknown += next - position
		} else if c.Quality != "complete" {
			partial += next - position
		}
		position = next
		if position >= end {
			break
		}
	}
	return partial, unknown + max(0, end-position)
}

func readCoverage(app core.App, session string, from, to int64) ([]data.CaptureInterval, error) {
	rows, err := readRecords[data.CaptureInterval](app, "capture_intervals", "session={:s} AND end_ms>{:from} AND start_ms<{:to}", dbx.Params{"s": session, "from": from, "to": to})
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].StartMS == rows[j].StartMS {
			return rows[i].ID < rows[j].ID
		}
		return rows[i].StartMS < rows[j].StartMS
	})
	return rows, err
}

const blockReadPage = 256

// Both the initial catch-up and steady-state replay use keyset pages. There is
// no OFFSET scan or whole-recording slice, even after a long offline interval.
func walkTraffic(app core.App, session string, policy data.Policy, from, to int64, visit func(data.TrafficChunk) error) (int, error) {
	params := dbx.Params{"s": session, "from": from, "to": to, "lower": max(0, from-policy.ChunkMS), "after": int64(-1), "id": ""}
	count := 0
	for {
		rows, err := data.ReadTraffic(app.DB().Select("*").From("traffic_chunks").Where(dbx.NewExp("session={:s} AND start_ms>={:lower} AND start_ms+chunk_ms>{:from} AND start_ms<{:to} AND (start_ms>{:after} OR (start_ms={:after} AND id>{:id}))", params)).OrderBy("start_ms", "id").Limit(blockReadPage))
		if err != nil {
			return count, err
		}
		count += len(rows)
		for _, row := range rows {
			if err := visit(row); err != nil {
				return count, err
			}
		}
		if len(rows) < blockReadPage {
			return count, nil
		}
		last := rows[len(rows)-1]
		params["after"], params["id"] = last.StartMS, last.ID
	}
}

func blockGroup(client, service string) string { return client + "\x00" + service }

// Union concurrent bindings one five-second chunk at a time. Emitting in time
// order lets the projector retire quiet groups while catching up with history.
func walkBins(app core.App, session string, policy data.Policy, from, to int64, visit func(data.TrafficChunk, activityBin) error) (int, error) {
	type group struct {
		representative data.TrafficChunk
		bins           []activityBin
		used           []bool
	}
	groups := map[string]*group{}
	start := int64(-1)
	flush := func() error {
		keys := make([]string, 0, len(groups))
		for key := range groups {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for i := int64(0); i < policy.ChunkMS/policy.BucketMS; i++ {
			for _, key := range keys {
				g := groups[key]
				if g.used[i] {
					if err := visit(g.representative, g.bins[i]); err != nil {
						return err
					}
				}
			}
		}
		clear(groups)
		return nil
	}
	count, err := walkTraffic(app, session, policy, from, to, func(c data.TrafficChunk) error {
		if c.StartMS != start {
			if err := flush(); err != nil {
				return err
			}
			start = c.StartMS
		}
		key := blockGroup(c.ClientID, c.ServiceKey)
		g := groups[key]
		if g == nil {
			representative := c
			representative.Samples = nil
			g = &group{representative: representative, bins: make([]activityBin, policy.ChunkMS/policy.BucketMS), used: make([]bool, policy.ChunkMS/policy.BucketMS)}
			groups[key] = g
		}
		for _, sample := range c.Samples {
			at, end := c.StartMS+sample[0], c.StartMS+sample[0]+c.BucketMS
			index := sample[0] / policy.BucketMS
			if at < from || end > to || index < 0 || index >= int64(len(g.bins)) {
				continue
			}
			bin := &g.bins[index]
			if !g.used[index] {
				*bin = activityBin{start: at, end: end, confidence: c.Evidence.Confidence}
				g.used[index] = true
			}
			if bin.confidence != c.Evidence.Confidence {
				bin.confidence = "mixed"
			}
			bin.sent += sample[1]
			bin.received += sample[2]
			bin.active = bin.active || sample[3]+sample[4] > 0
		}
		return nil
	})
	if err == nil {
		err = flush()
	}
	return count, err
}

type blockAccumulator struct {
	value      blockPrefix
	through    int64
	prefix     *blockPrefix
	prefixOpen bool
}

func (a *blockAccumulator) checkpoint(coverage []data.CaptureInterval, watermark int64, open bool) {
	a.prefix = a.value.clone()
	partial, unknown := coverageDuration(coverage, max(a.value.Block.EndMS, a.through), watermark)
	a.prefix.GapPartial += partial
	a.prefix.GapUnknown += unknown
	a.prefixOpen = open
}

func RebuildBlocks(app core.App, session string, nowMS int64) error {
	return app.RunInTransaction(func(tx core.App) error {
		r, err := tx.FindRecordById("sessions", session)
		if err != nil {
			return err
		}
		s, err := data.Decode[data.Session](r)
		if err != nil {
			return err
		}
		_, err = rebuildBlocks(tx, s, max(s.StartedMS, s.RetainedFromMS), nowMS, 0)
		return err
	})
}

// minimumWatermark is used only by retention: bins about to be deleted cannot
// subsequently be corrected, so their identity bridge can be folded too.
func rebuildBlocks(app core.App, s data.Session, from, nowMS, minimumWatermark int64) (int, error) {
	if nowMS == 0 {
		nowMS = time.Now().UnixMilli()
	}
	if s.EndedMS > 0 && !s.Active {
		nowMS = s.EndedMS
	}
	if s.Policy.BucketMS <= 0 {
		s.Policy = DefaultPolicy()
	}
	policy := s.Policy
	summaryNow := nowMS
	if !s.Active && s.EndedMS > 0 {
		summaryNow = nowMS + policy.QuietGapMS + policy.CorrectionMS
	}
	record, err := app.FindRecordById("sessions", s.ID)
	if err != nil {
		return 0, err
	}
	watermark := max(from, record.GetInt64("block_watermark_ms"))
	confirmed := nowMS
	if s.Capture.ConfirmedMS > 0 {
		confirmed = min(confirmed, s.Capture.ConfirmedMS)
	}
	next := max(watermark, (confirmed-policy.CorrectionMS)/policy.ChunkMS*policy.ChunkMS)
	if !s.Active && s.EndedMS > 0 {
		next = max(watermark, confirmed/policy.BucketMS*policy.BucketMS)
	}
	var unsealed sql.NullInt64
	if err := app.DB().NewQuery("SELECT MIN(start_ms) FROM traffic_chunks WHERE session={:s} AND sealed=0").Bind(dbx.Params{"s": s.ID}).Row(&unsealed); err != nil {
		return 0, err
	}
	if unsealed.Valid {
		next = max(watermark, min(next, unsealed.Int64))
	}
	next = max(next, minimumWatermark)
	// A capture gap can close a block before its provisional timeout. Finalize
	// those small pending rows without reading their already-folded source bins.
	finalized, err := app.DB().NewQuery("UPDATE activity_blocks SET provisional=0, revision={:revision} WHERE session={:s} AND provisional=1 AND end_ms<={:end}").Bind(dbx.Params{"s": s.ID, "revision": s.Revision + 1, "end": summaryNow - policy.QuietGapMS - policy.CorrectionMS}).Execute()
	if err != nil {
		return 0, err
	}
	finalizedCount, err := finalized.RowsAffected()
	if err != nil {
		return 0, err
	}
	coverage, err := readCoverage(app, s.ID, watermark, max(nowMS, next))
	if err != nil {
		return 0, err
	}
	rows, err := readRecords[storedBlock](app, "activity_blocks", "session={:s} AND (prefix_open=1 OR (prefix_open=0 AND end_ms>={:from}))", dbx.Params{"s": s.ID, "from": watermark})
	if err != nil {
		return 0, err
	}
	old := map[string]storedBlock{}
	anchors := map[string][]data.ActivityBlock{}
	usedAnchors := map[string]bool{}
	current := map[string]*blockAccumulator{}
	for _, b := range rows {
		old[b.ID] = b
		key := blockGroup(b.ClientID, b.ServiceKey)
		anchors[key] = append(anchors[key], b.ActivityBlock)
		if b.PrefixOpen && b.Prefix != nil {
			current[key] = &blockAccumulator{value: *b.Prefix.clone(), through: watermark}
			usedAnchors[b.ID] = true
		}
	}
	changed := finalizedCount > 0
	emit := func(a *blockAccumulator) error {
		if a.value.Block.ActiveMS == 0 {
			return nil
		}
		b := storedBlock{ActivityBlock: a.value.summary(summaryNow, policy), Prefix: a.prefix, PrefixOpen: a.prefixOpen}
		previous, exists := old[b.ID]
		delete(old, b.ID)
		b.Revision = previous.Revision
		if !exists || previous.ActivityBlock != b.ActivityBlock {
			b.Revision = s.Revision + 1
			changed = true
		}
		if exists && reflect.DeepEqual(previous, b) {
			return nil
		}
		_, err := data.Write(app, "activity_blocks", b)
		return err
	}
	checkpointed := false
	finish := func(a *blockAccumulator) error {
		if !checkpointed {
			a.checkpoint(coverage, a.value.Block.EndMS, false)
		}
		return emit(a)
	}
	checkpoint := func() error {
		for key, a := range current {
			open := a.value.Block.EndMS+policy.QuietGapMS >= next
			a.checkpoint(coverage, next, open)
			if !open {
				if err := emit(a); err != nil {
					return err
				}
				delete(current, key)
			}
		}
		checkpointed = true
		return nil
	}
	lastExpire := int64(-1)
	count, err := walkBins(app, s.ID, policy, watermark, nowMS, func(c data.TrafficChunk, bin activityBin) error {
		if !checkpointed && bin.start >= next {
			if err := checkpoint(); err != nil {
				return err
			}
		}
		if lastExpire < 0 || bin.start-lastExpire >= policy.ChunkMS {
			for key, a := range current {
				if a.value.Block.EndMS+policy.QuietGapMS < bin.start {
					if err := finish(a); err != nil {
						return err
					}
					delete(current, key)
				}
			}
			lastExpire = bin.start
		}
		key := blockGroup(c.ClientID, c.ServiceKey)
		a := current[key]
		if !bin.active {
			if a != nil {
				a.value.AckSent += bin.sent
				a.value.AckReceived += bin.received
			}
			return nil
		}
		var gapPartial, gapUnknown int64
		if a != nil {
			gapPartial, gapUnknown = coverageDuration(coverage, max(a.value.Block.EndMS, a.through), bin.start)
			gapPartial += a.value.GapPartial
			gapUnknown += a.value.GapUnknown
			if bin.start-a.value.Block.EndMS > policy.QuietGapMS || gapUnknown > 0 {
				if err := finish(a); err != nil {
					return err
				}
				a = nil
			}
		}
		if a == nil {
			b := data.ActivityBlock{ID: data.ID(c.Session, c.ClientID, c.ServiceKey, fmt.Sprint(bin.start)), Session: c.Session, ClientID: c.ClientID, ClientIP: c.ClientIP, ServiceKey: c.ServiceKey, ServiceLabel: c.ServiceLabel, OriginalStartMS: bin.start, StartMS: bin.start, EndMS: bin.start}
			for _, old := range anchors[key] {
				if !usedAnchors[old.ID] && old.OriginalStartMS < from && old.EndMS > from && old.EndMS > b.StartMS && old.OriginalStartMS < b.OriginalStartMS {
					b.ID, b.OriginalStartMS = old.ID, old.OriginalStartMS
					usedAnchors[old.ID] = true
				}
			}
			a = &blockAccumulator{value: blockPrefix{Block: b, Confidence: map[string]int64{}}}
			current[key] = a
			gapPartial, gapUnknown = 0, 0
		}
		v := &a.value
		if v.Block.ActiveMS == 0 {
			// Retention may have removed the whole immutable prefix while a
			// mutable suffix still continues its identity. Leading ACKs stay out.
			v.Block.StartMS = bin.start
			gapPartial, gapUnknown = 0, 0
		} else {
			v.Block.Sent += v.AckSent
			v.Block.Received += v.AckReceived
		}
		v.AckSent, v.AckReceived, v.GapPartial, v.GapUnknown = 0, 0, 0, 0
		v.Block.Sent += bin.sent
		v.Block.Received += bin.received
		v.Block.ActiveMS += bin.end - bin.start
		v.Block.EndMS = bin.end
		v.Confidence[bin.confidence]++
		partial, unknown := coverageDuration(coverage, bin.start, bin.end)
		v.PartialMS += gapPartial + partial
		v.UnknownMS += gapUnknown + unknown
		a.through = bin.end
		return nil
	})
	if err != nil {
		return count, err
	}
	if !checkpointed {
		if err := checkpoint(); err != nil {
			return count, err
		}
	}
	for _, a := range current {
		if err := emit(a); err != nil {
			return count, err
		}
	}
	for id := range old {
		if _, err := app.DB().Delete("activity_blocks", dbx.HashExp{"id": id}).Execute(); err != nil {
			return count, err
		}
		changed = true
	}
	if next != record.GetInt64("block_watermark_ms") {
		if _, err := app.DB().NewQuery("UPDATE sessions SET block_watermark_ms={:next} WHERE id={:s}").Bind(dbx.Params{"s": s.ID, "next": next}).Execute(); err != nil {
			return count, err
		}
	}
	if changed {
		err = data.BumpRevision(app, s.ID)
	}
	return count, err
}
