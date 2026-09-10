package routing

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCoverageKeepsRepliesAndOnlyMarksProbedGaps(t *testing.T) {
	data := []byte(`{"type":"trace","dst":"203.0.113.9","method":"udp-paris","firsthop":3,"hop_count":5,"probe_count":7,"stop_reason":"HOPLIMIT","hops":[{"addr":"198.51.100.3","probe_ttl":3,"probe_id":1,"rtt":2.1,"icmp_type":11,"icmp_code":0},{"addr":"198.51.100.33","probe_ttl":3,"probe_id":2,"rtt":3.1,"icmp_type":11,"icmp_code":0},{"addr":"203.0.113.9","probe_ttl":5,"probe_id":1,"rtt":4.1,"icmp_type":11,"icmp_code":0}]}`)
	result, err := decodeScamperTrace(data, target{"203.0.113.9", "udp", 443}, 3, 6)
	if err != nil {
		t.Fatal(err)
	}
	if result.Reached {
		t.Fatal("destination Time Exceeded is not terminal evidence")
	}
	if len(result.Hops) != 3 || len(result.Hops[0].Replies) != 2 || result.Hops[0].State != "multipath" || result.Hops[1].State != "no_reply" {
		t.Fatalf("lost individual replies or invented a probed TTL: %+v", result)
	}
	if result.ProbeCount != 7 {
		t.Fatal(result.ProbeCount)
	}
}
func TestCoverageCompletesFromProtocolEvidence(t *testing.T) {
	for _, payload := range []string{
		`{"type":"trace","dst":"203.0.113.9","method":"tcp","firsthop":1,"hop_count":1,"stop_reason":"COMPLETED","hops":[{"addr":"203.0.113.9","probe_ttl":1,"rtt":1,"tcp_flags":18}]}`,
		`{"type":"trace","dst":"203.0.113.9","method":"udp-paris","firsthop":1,"hop_count":1,"stop_reason":"COMPLETED","hops":[{"addr":"203.0.113.9","probe_ttl":1,"rtt":1,"icmp_type":3,"icmp_code":3}]}`,
		`{"type":"trace","dst":"2001:db8::9","method":"icmp-echo-paris","firsthop":1,"hop_count":1,"stop_reason":"COMPLETED","hops":[{"addr":"2001:db8::9","probe_ttl":1,"rtt":1,"icmp_type":129,"icmp_code":0}]}`,
	} {
		ip := "203.0.113.9"
		// The target must be the exact measured address, including IPv6.
		if strings.Contains(payload, "2001:db8") {
			ip = "2001:db8::9"
		}
		got, err := decodeScamperTrace([]byte(payload), target{ip, "tcp", 443}, 1, 4)
		if err != nil || !got.Reached {
			t.Fatalf("terminal evidence rejected: %+v %v", got, err)
		}
	}
}

func TestCoverageRetainsReplyWithoutUsingWrappedRTT(t *testing.T) {
	data := []byte(`{"type":"trace","dst":"203.0.113.9","method":"tcp","firsthop":1,"hop_count":1,"probe_count":1,"stop_reason":"COMPLETED","hops":[{"addr":"203.0.113.9","probe_ttl":1,"rtt":4294967.272,"tcp_flags":20,"tx":{"sec":1789052929,"usec":422414}}]}`)
	got, err := decodeScamperTrace(data, target{"203.0.113.9", "tcp", 443}, 1, 4)
	if err != nil || !got.Reached || len(got.Hops[0].Timings) != 0 {
		t.Fatalf("wrapped RTT corrupted route evidence: %+v %v", got, err)
	}
	reply := got.Hops[0].Replies[0]
	if reply.RTT != nil || reply.ReportedRTT == nil || reply.SeenAt != "" {
		t.Fatalf("wrapped RTT became a measurement or future timestamp: %+v", reply)
	}
}
func TestCoveragePublishesSegmentsAndRetainsThemOnCancellation(t *testing.T) {
	calls := 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := coverageProbe{deadline: time.Second, run: func(ctx context.Context, args []string) ([]byte, error) {
		calls++
		if calls == 2 {
			cancel()
			return nil, context.Canceled
		}
		return []byte(`{"type":"trace","dst":"203.0.113.9","firsthop":1,"hop_count":4,"probe_count":6,"stop_reason":"HOPLIMIT","hops":[{"addr":"198.51.100.1","probe_ttl":1,"rtt":1,"icmp_type":11,"icmp_code":0}]}`), nil
	}}
	publications := 0
	result := p.Run(ctx, target{"203.0.113.9", "tcp", 443}, probePlan{Quality: true, Method: "tcp"}, func(s snapshot) {
		if s.replies() == 1 {
			publications++
		}
	})
	if publications != 1 || result.replies() != 1 || result.Status != "cancelled" || result.Hops[len(result.Hops)-1].State != "not_probed" {
		t.Fatalf("lost progress: %+v publications=%d", result, publications)
	}
}

func TestCoverageCannotReplaceRichEvidenceWithSparseRefresh(t *testing.T) {
	now := time.Now()
	old := snapshot{Attempt: "rich", Reached: true, Measured: now.Add(-time.Minute), ProbedTTL: 10, Hops: []Hop{{TTL: 1, Address: "192.0.2.1"}, {TTL: 2, Address: "192.0.2.2"}, {TTL: 10, Address: "203.0.113.9"}}}
	next := snapshot{Attempt: "sparse", Reached: true, Measured: now, ProbedTTL: 10, Hops: []Hop{{TTL: 1, Address: "192.0.2.1"}, {TTL: 10, Address: "203.0.113.9"}}}
	if betterSnapshot(old, next) {
		t.Fatal("sparse refresh erased richer evidence")
	}
	old.Reached = false
	next.Reached = false
	next.ProbedTTL = 2
	if betterSnapshot(old, next) {
		t.Fatal("a short partial prefix erased a longer partial path")
	}
}
func TestAlternateMethodsPersistWithoutSplicingAndKeepSourceReferences(t *testing.T) {
	app := testApp(t)
	session := testSession(t, app)
	repo := repository{app: app}
	now := time.Now()
	tcp := snapshot{Attempt: "tcp-attempt", Revision: 1, Method: "tcp:443", Reached: true, Measured: now, ProbedTTL: 3, Hops: []Hop{{TTL: 1, Address: "192.0.2.1"}, {TTL: 3, Address: "203.0.113.9"}}}
	icmp := snapshot{Attempt: "icmp-attempt", Revision: 1, Method: "icmp-paris", Measured: now, ProbedTTL: 3, Hops: []Hop{{TTL: 1, Address: "192.0.2.2"}}}
	entry := cacheEntry{Best: tcp, Last: icmp, Methods: map[string]snapshot{tcp.Method: tcp, icmp.Method: icmp}, ValidUntil: now.Add(time.Hour)}
	saved, err := repo.publish("key", "network", session, target{"203.0.113.9", "tcp", 443}, entry, icmp, "cached", "alternate", now)
	if err != nil {
		t.Fatal(err)
	}
	for method, value := range saved.Methods {
		if value.ObservationID == "" {
			t.Fatalf("method %s lost observation reference", method)
		}
	}
	for _, value := range entry.Methods {
		if value.ObservationID != "" {
			t.Fatal("transaction mutated the caller's map")
		}
	}
	routes, _ := app.FindAllRecords("routes")
	data, _ := json.Marshal(routes[0].Get("alternate_routes"))
	var alternatives []map[string]any
	_ = json.Unmarshal(data, &alternatives)
	if len(alternatives) != 1 || alternatives[0]["method"] != "icmp-paris" {
		t.Fatalf("alternate evidence was lost: %s", data)
	}
	if routes[0].GetString("method") != "tcp:443" || routes[0].GetString("provenance") != "cache" {
		t.Fatal("alternate attempt mislabeled the retained main path")
	}
}

type priorityProbe struct {
	starts    chan probePlan
	cancelled chan probePlan
}

func (p priorityProbe) Run(ctx context.Context, t target, plan probePlan, publish func(snapshot)) snapshot {
	p.starts <- plan
	s := snapshot{Attempt: hash(t.IP)[:24], Revision: 1, Method: t.method(), Profile: "fast", Measured: time.Now()}
	if plan.Quality {
		s.Profile = "coverage"
		<-ctx.Done()
		p.cancelled <- plan
		s.Status = "cancelled"
	} else {
		s.Reached = true
		s.Status = "reached"
		s.Hops = []Hop{{TTL: 1, Address: t.IP}}
	}
	s.Finished = time.Now()
	return s
}
func TestCoverageYieldsToNewTrafficWithoutAdvancingMethod(t *testing.T) {
	app := testApp(t)
	session := testSession(t, app)
	now := time.Now()
	tgt := target{"203.0.113.9", "tcp", 443}
	old := snapshot{Attempt: "cached", Revision: 1, Method: tgt.method(), Measured: now.Add(-time.Minute), Finished: now.Add(-time.Minute), Reached: true, ProbedTTL: 10, Hops: []Hop{{TTL: 1, Address: "192.0.2.1"}, {TTL: 10, Address: tgt.IP}}}
	repo := repository{app: app}
	_, err := repo.publish(tgt.key("network"), "network", session, tgt, cacheEntry{Best: old, Last: old, FreshUntil: now.Add(time.Minute), ValidUntil: now.Add(time.Hour)}, old, "cached", "cache", now)
	if err != nil {
		t.Fatal(err)
	}
	p := priorityProbe{starts: make(chan probePlan, 10), cancelled: make(chan probePlan, 10)}
	config := ConfigFromEnv()
	config.Workers = 1
	config.Interval = 10 * time.Millisecond
	c := &Coordinator{intake: map[string]Flow{}, reset: make(chan chan struct{}), done: make(chan struct{}), repo: repo, config: config, probe: p, session: func() string { return session }, network: func() (string, error) { return "network", nil }}
	ctx, cancel := context.WithCancel(context.Background())
	go c.run(ctx)
	t.Cleanup(func() { cancel(); <-c.done })
	eventually(t, func() bool { return c.Status().Network == "network" })
	c.Observe(Flow{ID: "warm", IP: tgt.IP, Protocol: "tcp", Port: 443, Session: session, At: time.Now(), Bytes: 1000})
	var first probePlan
	select {
	case first = <-p.starts:
	case <-time.After(3 * time.Second):
		t.Fatal("no coverage pass")
	}
	if !first.Quality || first.Method != "tcp" {
		t.Fatalf("wrong first method: %+v", first)
	}
	c.Observe(Flow{ID: "cold", IP: "203.0.113.10", Protocol: "tcp", Port: 443, Session: session, At: time.Now(), Bytes: 1_000_000})
	select {
	case <-p.cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("coverage blocked the live probe")
	}
	select {
	case plan := <-p.starts:
		if plan.Quality {
			t.Fatal("new traffic did not receive a fast probe")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fast probe did not start")
	}
	eventually(t, func() bool { entry, _ := repo.load(tgt.key("network")); return entry.Last.Status == "cancelled" })
	entry, _ := repo.load(tgt.key("network"))
	if entry.QualityIndex != 0 {
		t.Fatal("preemption consumed the method attempt")
	}
}
