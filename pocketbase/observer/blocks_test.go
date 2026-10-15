package observer

import (
	"fmt"
	"reflect"
	"sort"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
	"myapp/data"
	"myapp/testsupport"
	"testing"
)

func blockChunk(service string, start int64, samples ...data.Sample) data.TrafficChunk {
	return data.TrafficChunk{Session: "session", ClientID: "client", ClientIP: "10.0.0.100", ServiceKey: service, ServiceLabel: service, StartMS: start, BucketMS: 50, ChunkMS: 5000, Evidence: data.Attribution{Confidence: "medium"}, Samples: samples}
}
func TestBlocksSplitRepeatedVisitsWithoutConnectionIdentity(t *testing.T) {
	p := DefaultPolicy()
	p.QuietGapMS = 1000
	chunks := []data.TrafficChunk{blockChunk("svt.se", 100000, data.Sample{0, 150, 0, 90, 0, 1}, data.Sample{100, 70, 0, 0, 0, 1}, data.Sample{200, 150, 0, 90, 0, 1}, data.Sample{2000, 150, 0, 90, 0, 1}, data.Sample{4000, 70, 0, 0, 0, 1})}
	coverage := []data.CaptureInterval{{StartMS: 100000, EndMS: 105000, Quality: "complete"}}
	blocks := ProjectBlocks(chunks, coverage, nil, p, 100000, 105000)
	if len(blocks) != 2 {
		t.Fatalf("repeated visits not split: %#v", blocks)
	}
	if blocks[0].StartMS != 100000 || blocks[0].EndMS != 100250 || blocks[0].ActiveMS != 100 || blocks[0].Sent != 370 {
		t.Fatalf("span/active/ACK counts wrong: %#v", blocks[0])
	}
	if blocks[1].ActiveMS != 50 || blocks[1].Sent != 150 {
		t.Fatalf("later visit totals wrong: %#v", blocks[1])
	}
	// 70 ACK-only bytes after the visits stay in traffic totals, outside blocks.
	if totals(chunks)[0]-blocks[0].Sent-blocks[1].Sent != 70 {
		t.Fatal("unallocated traffic disappeared")
	}
}
func TestBlocksUnionConcurrentBindingsAndKeepServicesSeparate(t *testing.T) {
	chunks := []data.TrafficChunk{blockChunk("svt.se", 100000, data.Sample{0, 150, 0, 90, 0, 1}), blockChunk("svt.se", 100000, data.Sample{0, 0, 200, 0, 140, 0, 1}), blockChunk("other.example", 100000, data.Sample{0, 50, 0, 20, 0, 1})}
	blocks := ProjectBlocks(chunks, []data.CaptureInterval{{StartMS: 100000, EndMS: 100100, Quality: "complete"}}, nil, DefaultPolicy(), 100000, 100100)
	if len(blocks) != 2 {
		t.Fatalf("services merged: %v", blocks)
	}
	for _, b := range blocks {
		if b.ActiveMS != 50 {
			t.Fatalf("concurrency inflated active time: %#v", b)
		}
		if b.ServiceKey == "svt.se" && (b.Sent != 150 || b.Received != 200) {
			t.Fatal("binding counts not combined")
		}
	}
}
func TestCaptureGapSplitsActivityEvenInsideQuietGap(t *testing.T) {
	chunks := []data.TrafficChunk{blockChunk("svt.se", 100000, data.Sample{0, 150, 0, 90, 0, 1}, data.Sample{200, 150, 0, 90, 0, 1})}
	coverage := []data.CaptureInterval{{StartMS: 100000, EndMS: 100100, Quality: "complete"}, {StartMS: 100200, EndMS: 100300, Quality: "partial"}}
	blocks := ProjectBlocks(chunks, coverage, nil, DefaultPolicy(), 100000, 100300)
	if len(blocks) != 2 || blocks[0].Quality != "complete" || blocks[1].Quality != "partial" {
		t.Fatalf("unknown gap presented as silence: %#v", blocks)
	}
}
func TestConfidenceDoesNotLeakIntoEarlierBlocks(t *testing.T) {
	p := DefaultPolicy()
	p.QuietGapMS = 1000
	earlier := blockChunk("svt.se", 100000, data.Sample{0, 150, 0, 90, 0, 1})
	later := blockChunk("svt.se", 105000, data.Sample{0, 150, 0, 90, 0, 1})
	later.Evidence.Confidence = "low"
	blocks := ProjectBlocks([]data.TrafficChunk{earlier, later}, []data.CaptureInterval{{StartMS: 100000, EndMS: 106000, Quality: "complete"}}, nil, p, 100000, 106000)
	if len(blocks) != 2 || blocks[0].Confidence != "medium" || blocks[1].Confidence != "low" {
		t.Fatalf("future confidence changed earlier block: %#v", blocks)
	}
}
func TestBlocksIncludeOnlyCompleteSourceBins(t *testing.T) {
	chunks := []data.TrafficChunk{blockChunk("svt.se", 100000, data.Sample{0, 150, 0, 90, 0, 1}, data.Sample{50, 200, 0, 140, 0, 1}, data.Sample{100, 300, 0, 240, 0, 1})}
	blocks := ProjectBlocks(chunks, []data.CaptureInterval{{StartMS: 100000, EndMS: 100150, Quality: "complete"}}, nil, DefaultPolicy(), 100001, 100149)
	if len(blocks) != 1 || blocks[0].StartMS != 100050 || blocks[0].EndMS != 100100 || blocks[0].Sent != 200 || blocks[0].ActiveMS != 50 {
		t.Fatalf("partial bins changed source counts: %+v", blocks)
	}
}

func BenchmarkProjectThirtyMinutes(b *testing.B) {
	var chunks []data.TrafficChunk
	for start := int64(0); start < 1800000; start += 5000 {
		for site := 0; site < 20; site++ {
			c := blockChunk(string(rune('a'+site)), start)
			for offset := int64(0); offset < 5000; offset += 50 {
				c.Samples = append(c.Samples, data.Sample{offset, 150, 900, 90, 840, 1, 1})
			}
			chunks = append(chunks, c)
		}
	}
	coverage := []data.CaptureInterval{{StartMS: 0, EndMS: 1800000, Quality: "complete"}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ProjectBlocks(chunks, coverage, nil, DefaultPolicy(), 0, 1800000)
	}
}

func saveBlockFact(t testing.TB, app core.App, collection string, value any) {
	t.Helper()
	if _, err := data.Write(app, collection, value); err != nil {
		t.Fatal(err)
	}
}

func blockFacts(t testing.TB, app core.App, session string) ([]data.TrafficChunk, []data.CaptureInterval, []data.ActivityBlock) {
	t.Helper()
	p := dbx.Params{"s": session}
	chunks, err := data.ReadTraffic(app.DB().Select("*").From("traffic_chunks").Where(dbx.NewExp("session={:s}", p)).OrderBy("start_ms", "id"))
	if err != nil {
		t.Fatal(err)
	}
	coverage, err := readCoverage(app, session, 0, 9007199254740991)
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := readRecords[data.ActivityBlock](app, "activity_blocks", "session={:s}", p)
	if err != nil {
		t.Fatal(err)
	}
	return chunks, coverage, blocks
}

func compareBlocks(t testing.TB, got, want []data.ActivityBlock) {
	t.Helper()
	normalize := func(blocks []data.ActivityBlock) {
		for i := range blocks {
			blocks[i].Revision = 0
		}
		sort.Slice(blocks, func(i, j int) bool { return blocks[i].ID < blocks[j].ID })
	}
	normalize(got)
	normalize(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("incremental projection differs from full source projection\ngot  %+v\nwant %+v", got, want)
	}
}

func rebuildAndCompare(t testing.TB, app core.App, session string, now int64) int {
	t.Helper()
	chunks, coverage, anchors := blockFacts(t, app, session)
	r, err := app.FindRecordById("sessions", session)
	if err != nil {
		t.Fatal(err)
	}
	s, err := data.Decode[data.Session](r)
	if err != nil {
		t.Fatal(err)
	}
	from := max(s.StartedMS, s.RetainedFromMS)
	want := ProjectBlocks(chunks, coverage, anchors, s.Policy, from, now)
	var count int
	if err := app.RunInTransaction(func(tx core.App) error {
		var err error
		count, err = rebuildBlocks(tx, s, from, now, 0)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	_, _, got := blockFacts(t, app, session)
	compareBlocks(t, got, want)
	return count
}

func TestIncrementalBlocksMatchFullProjectionThroughCorrectionsAndRestart(t *testing.T) {
	app := testsupport.App(t)
	policy := DefaultPolicy()
	policy.CorrectionMS, policy.QuietGapMS = 5000, 10000
	session := "blocksession001"
	saveBlockFact(t, app, "sessions", data.Session{ID: session, Active: true, StartedMS: 100000, Policy: policy})
	saveBlockFact(t, app, "capture_intervals", data.CaptureInterval{ID: data.NewID(), Session: session, StartMS: 100000, EndMS: 140000, Quality: "complete"})
	write := func(service string, start int64, sealed bool, samples ...data.Sample) data.TrafficChunk {
		c := blockChunk(service, start, samples...)
		c.Session, c.ID, c.Sealed = session, data.NewID(), sealed
		saveBlockFact(t, app, "traffic_chunks", c)
		return c
	}
	write("svt.se", 100000, true, data.Sample{0, 150, 0, 90, 0, 1}, data.Sample{400, 200, 0, 140, 0, 1}, data.Sample{4900, 60, 0, 0, 0, 1})
	unknown := write("endpoint:1.2.3.4", 105000, false, data.Sample{0, 100, 0, 40, 0, 1})
	write("svt.se", 110000, false, data.Sample{0, 300, 0, 240, 0, 1}, data.Sample{200, 60, 0, 0, 0, 1})
	rebuildAndCompare(t, app, session, 111000)
	// An atomic attribution correction retracts the old group and joins the
	// sealed prefix, including its pending ACK-only bytes before the watermark.
	if err := app.RunInTransaction(func(tx core.App) error {
		if _, err := tx.DB().Delete("traffic_chunks", dbx.HashExp{"id": unknown.ID}).Execute(); err != nil {
			return err
		}
		unknown.ID, unknown.ServiceKey, unknown.ServiceLabel, unknown.Sealed = data.NewID(), "svt.se", "svt.se", true
		_, err := data.Write(tx, "traffic_chunks", unknown)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	rebuildAndCompare(t, app, session, 116000)
	// Reopen the database with a fresh application. The persisted prefix, not
	// process-local history, resumes the still-mutable source chunk.
	directory := app.DataDir()
	if err := app.ResetBootstrapState(); err != nil {
		t.Fatal(err)
	}
	app = pocketbase.NewWithConfig(pocketbase.Config{DefaultDataDir: directory, HideStartBanner: true})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.ResetBootstrapState() })
	if rows := rebuildAndCompare(t, app, session, 116000); rows != 1 {
		t.Fatalf("restart replayed %d source chunks; want one correction-tail chunk", rows)
	}
	if _, err := app.DB().NewQuery("UPDATE traffic_chunks SET sealed=1 WHERE session={:s}").Bind(dbx.Params{"s": session}).Execute(); err != nil {
		t.Fatal(err)
	}
	write("svt.se", 130000, false, data.Sample{0, 250, 0, 190, 0, 1})
	rebuildAndCompare(t, app, session, 131000)
	_, _, blocks := blockFacts(t, app, session)
	if len(blocks) != 2 || blocks[0].Sent+blocks[1].Sent != 1060 {
		t.Fatalf("quiet split allocated trailing ACKs: %+v", blocks)
	}
	// Retention after that earlier correction also clips a now-closed prefix,
	// without changing its original identity or reintroducing the old group.
	chunks, coverage, anchors := blockFacts(t, app, session)
	want := ProjectBlocks(chunks, coverage, anchors, policy, 105050, 131000)
	if err := app.RunInTransaction(func(tx core.App) error {
		if err := pruneSession(tx, session, 105050, 131000); err != nil {
			return err
		}
		_, err := tx.DB().NewQuery("UPDATE sessions SET retained_from_ms=105050 WHERE id={:s}").Bind(dbx.Params{"s": session}).Execute()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	_, _, blocks = blockFacts(t, app, session)
	compareBlocks(t, blocks, want)
	rebuildAndCompare(t, app, session, 131000)
}

func TestTailReclassificationCanSplitBlockWithoutReusingItsID(t *testing.T) {
	app := testsupport.App(t)
	policy := DefaultPolicy()
	policy.QuietGapMS = 1000
	session := "blocksession006"
	saveBlockFact(t, app, "sessions", data.Session{ID: session, Active: true, StartedMS: 100000, Policy: policy})
	saveBlockFact(t, app, "capture_intervals", data.CaptureInterval{ID: data.NewID(), Session: session, StartMS: 100000, EndMS: 105000, Quality: "complete"})
	c := blockChunk("svt.se", 100000, data.Sample{0, 150, 0, 90, 0, 1}, data.Sample{1000, 150, 0, 90, 0, 1}, data.Sample{2000, 150, 0, 90, 0, 1}, data.Sample{3000, 150, 0, 90, 0, 1})
	c.ID, c.Session = data.NewID(), session
	saveBlockFact(t, app, "traffic_chunks", c)
	rebuildAndCompare(t, app, session, 104000)
	other := c
	other.ID, other.ServiceKey, other.ServiceLabel = data.NewID(), "other.example", "other.example"
	other.Samples = append([]data.Sample(nil), c.Samples[1:3]...)
	c.Samples = []data.Sample{c.Samples[0], c.Samples[3]}
	saveBlockFact(t, app, "traffic_chunks", c)
	saveBlockFact(t, app, "traffic_chunks", other)
	rebuildAndCompare(t, app, session, 104000)
	_, _, blocks := blockFacts(t, app, session)
	if len(blocks) != 3 {
		t.Fatalf("split overwrote a block: %+v", blocks)
	}
	var sum int64
	ids := map[string]bool{}
	for _, b := range blocks {
		if ids[b.ID] {
			t.Fatalf("split reused %s", b.ID)
		}
		ids[b.ID] = true
		sum += b.Sent
	}
	if sum != 600 {
		t.Fatalf("split changed source total: %d", sum)
	}
}

func TestIncrementalBlocksMatchOracleAcrossCoverageAndConfidenceChanges(t *testing.T) {
	app := testsupport.App(t)
	policy := DefaultPolicy()
	policy.CorrectionMS, policy.QuietGapMS = 5000, 6000
	session := "blocksession002"
	saveBlockFact(t, app, "sessions", data.Session{ID: session, Active: true, StartedMS: 100000, Policy: policy})
	for step := int64(0); step < 16; step++ {
		start := 100000 + step*5000
		quality := "complete"
		if step%5 == 2 {
			quality = "partial"
		}
		if step%5 == 3 {
			quality = "unavailable"
		}
		saveBlockFact(t, app, "capture_intervals", data.CaptureInterval{ID: data.NewID(), Session: session, StartMS: start, EndMS: start + 5000, Quality: quality})
		for binding := 0; binding < 3; binding++ {
			c := blockChunk("service.example", start, data.Sample{0, 150, 100, 90, 40, 1, 1}, data.Sample{100, 60, 0, 0, 0, 1}, data.Sample{4900, 300, 0, 240, 0, 1})
			if binding == 2 {
				c.ServiceKey, c.ServiceLabel = "other.example", "other.example"
				c.Samples = c.Samples[:1]
			}
			if step%3 == 1 || binding == 1 {
				c.Evidence.Confidence = "low"
			}
			c.ID, c.Session = data.NewID(), session
			saveBlockFact(t, app, "traffic_chunks", c)
		}
		if _, err := app.DB().NewQuery("UPDATE traffic_chunks SET sealed=1 WHERE session={:s} AND start_ms+chunk_ms<={:end}").Bind(dbx.Params{"s": session, "end": start}).Execute(); err != nil {
			t.Fatal(err)
		}
		rebuildAndCompare(t, app, session, start+5000)
	}
}

func TestIncrementalRetentionSubtractsOnlyExpiredPrefixAndKeepsIdentity(t *testing.T) {
	app := testsupport.App(t)
	policy := DefaultPolicy()
	policy.CorrectionMS, policy.QuietGapMS = 5000, 10000
	session := "blocksession003"
	saveBlockFact(t, app, "sessions", data.Session{ID: session, Active: true, StartedMS: 100000, Policy: policy})
	for step := int64(0); step < 8; step++ {
		start := 100000 + step*5000
		c := blockChunk("svt.se", start, data.Sample{0, 150, 0, 90, 0, 1}, data.Sample{100, 60, 0, 0, 0, 1}, data.Sample{200, 250, 0, 190, 0, 1})
		c.ID, c.Session, c.Sealed = data.NewID(), session, step < 7
		if step == 0 {
			c.Evidence.Confidence = "low"
		}
		saveBlockFact(t, app, "traffic_chunks", c)
		quality := "complete"
		if step == 0 {
			quality = "partial"
		}
		saveBlockFact(t, app, "capture_intervals", data.CaptureInterval{ID: data.NewID(), Session: session, StartMS: start, EndMS: start + 5000, Quality: quality})
	}
	const now = int64(140000)
	rebuildAndCompare(t, app, session, now)
	_, _, original := blockFacts(t, app, session)
	for _, cutoff := range []int64{100050, 100150, 105050, 115100, 135050} {
		chunks, coverage, anchors := blockFacts(t, app, session)
		want := ProjectBlocks(chunks, coverage, anchors, policy, cutoff, now)
		if err := app.RunInTransaction(func(tx core.App) error {
			if err := pruneSession(tx, session, cutoff, now); err != nil {
				return err
			}
			_, err := tx.DB().NewQuery("UPDATE sessions SET retained_from_ms={:cut} WHERE id={:s}").Bind(dbx.Params{"s": session, "cut": cutoff}).Execute()
			return err
		}); err != nil {
			t.Fatalf("cutoff %d: %v", cutoff, err)
		}
		_, _, got := blockFacts(t, app, session)
		compareBlocks(t, got, want)
		if len(got) != 1 || got[0].ID != original[0].ID || got[0].OriginalStartMS != 100000 || !got[0].Clipped {
			t.Fatalf("cutoff %d lost crossing identity: %+v", cutoff, got)
		}
		rebuildAndCompare(t, app, session, now)
	}
}

func TestBlockProjectionWorkDoesNotGrowWithSealedHistory(t *testing.T) {
	app := testsupport.App(t)
	policy := DefaultPolicy()
	session := "blocksession004"
	saveBlockFact(t, app, "sessions", data.Session{ID: session, Active: true, StartedMS: 100000, Policy: policy})
	saveBlockFact(t, app, "capture_intervals", data.CaptureInterval{ID: data.NewID(), Session: session, StartMS: 100000, EndMS: 2000000, Quality: "complete"})
	// More than one keyset page, including multiple pages for a single source
	// time. This must still union concurrent samples before counting active time.
	for binding := 0; binding < blockReadPage+20; binding++ {
		c := blockChunk("svt.se", 100000, data.Sample{0, 150, 0, 90, 0, 1})
		c.ID, c.Session, c.Sealed = data.NewID(), session, true
		saveBlockFact(t, app, "traffic_chunks", c)
	}
	for start := int64(105000); start < 1900000; start += 5000 {
		c := blockChunk("svt.se", start, data.Sample{0, 150, 0, 90, 0, 1})
		c.ID, c.Session, c.Sealed = data.NewID(), session, true
		saveBlockFact(t, app, "traffic_chunks", c)
	}
	rebuildAndCompare(t, app, session, 1900000)
	for i := 0; i < 3; i++ {
		if rows := rebuildAndCompare(t, app, session, 1900000); rows != 2 {
			t.Fatalf("steady-state replay read %d rows from a 30-minute recording; want the two correction-tail chunks", rows)
		}
	}
}

func TestBlockPrefixAndWatermarkRollbackTogether(t *testing.T) {
	app := testsupport.App(t)
	policy := DefaultPolicy()
	session := "blocksession007"
	saveBlockFact(t, app, "sessions", data.Session{ID: session, Active: true, StartedMS: 100000, Policy: policy})
	saveBlockFact(t, app, "capture_intervals", data.CaptureInterval{ID: data.NewID(), Session: session, StartMS: 100000, EndMS: 140000, Quality: "complete"})
	c := blockChunk("svt.se", 100000, data.Sample{0, 150, 0, 90, 0, 1})
	c.ID, c.Session, c.Sealed = data.NewID(), session, true
	saveBlockFact(t, app, "traffic_chunks", c)
	rebuildAndCompare(t, app, session, 115000)
	before, err := readRecords[storedBlock](app, "activity_blocks", "1=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	c.ID, c.StartMS = data.NewID(), 115000
	saveBlockFact(t, app, "traffic_chunks", c)
	if _, err := app.DB().NewQuery("CREATE TRIGGER reject_watermark BEFORE UPDATE ON sessions WHEN NEW.block_watermark_ms != OLD.block_watermark_ms BEGIN SELECT RAISE(ABORT, 'fixture failure'); END").Execute(); err != nil {
		t.Fatal(err)
	}
	if err := RebuildBlocks(app, session, 130000); err == nil {
		t.Fatal("expected transaction failure after block writes")
	}
	after, err := readRecords[storedBlock](app, "activity_blocks", "1=1", nil)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("failed checkpoint left partial block state: %v %v", after, err)
	}
	r, err := app.FindRecordById("sessions", session)
	if err != nil || r.GetInt64("block_watermark_ms") != 105000 {
		t.Fatal("failed checkpoint advanced watermark", err)
	}
	if _, err := app.DB().NewQuery("DROP TRIGGER reject_watermark").Execute(); err != nil {
		t.Fatal(err)
	}
	rebuildAndCompare(t, app, session, 130000)
}

func TestClosedSessionProjectsOnlyWholeFinalBinsAndFinalizesFlags(t *testing.T) {
	app := testsupport.App(t)
	session := "blocksession008"
	saveBlockFact(t, app, "sessions", data.Session{ID: session, StartedMS: 100000, EndedMS: 100075, Policy: DefaultPolicy(), Capture: data.CaptureHealth{ConfirmedMS: 100075}})
	c := blockChunk("svt.se", 100000, data.Sample{0, 150, 0, 90, 0, 1}, data.Sample{50, 250, 0, 190, 0, 1})
	c.ID, c.Session, c.Sealed = data.NewID(), session, true
	saveBlockFact(t, app, "traffic_chunks", c)
	if err := RebuildBlocks(app, session, 100100); err != nil {
		t.Fatal(err)
	}
	_, _, blocks := blockFacts(t, app, session)
	if len(blocks) != 1 || blocks[0].Provisional || blocks[0].Sent != 150 || blocks[0].EndMS != 100050 {
		t.Fatalf("closed projection counted unfinished bin or retained mutable flag: %+v", blocks)
	}
	r, err := app.FindRecordById("sessions", session)
	if err != nil || r.GetInt64("block_watermark_ms") != 100050 {
		t.Fatal("final checkpoint passed last confirmed complete bin", err)
	}
}

func BenchmarkRebuildBlocksThirtyMinutes(b *testing.B) {
	app := testsupport.App(b)
	policy := DefaultPolicy()
	session := "blocksession005"
	saveBlockFact(b, app, "sessions", data.Session{ID: session, Active: true, StartedMS: 100000, Policy: policy})
	saveBlockFact(b, app, "capture_intervals", data.CaptureInterval{ID: data.NewID(), Session: session, StartMS: 100000, EndMS: 1900000, Quality: "complete"})
	if err := app.RunInTransaction(func(tx core.App) error {
		for start := int64(100000); start < 1900000; start += 5000 {
			for binding := 0; binding < 20; binding++ {
				c := blockChunk(fmt.Sprintf("service-%d.example", binding), start)
				for offset := int64(0); offset < 5000; offset += 50 {
					c.Samples = append(c.Samples, data.Sample{offset, 150, 900, 90, 840, 1, 1})
				}
				c.ID, c.Session, c.Sealed = data.NewID(), session, true
				if _, err := data.Write(tx, "traffic_chunks", c); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		b.Fatal(err)
	}
	if err := RebuildBlocks(app, session, 1900000); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := RebuildBlocks(app, session, 1900000); err != nil {
			b.Fatal(err)
		}
	}
}
