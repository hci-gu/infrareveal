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

func TestStructuredIdentityRejectsOtherAttemptsAndPorts(t *testing.T) {
	data := []byte(`{"type":"trace","userid":7,"dst":"9.9.9.9","method":"tcp","sport":45000,"dport":443,"firsthop":1,"hop_count":1,"probe_count":1,"stop_reason":"COMPLETED","hops":[{"addr":"9.9.9.9","probe_ttl":1,"rtt":1,"tcp_flags":18}]}`)
	tgt := target{"9.9.9.9", "tcp", 443}
	for _, id := range []probeIdentity{{8, 45000, "tcp"}, {7, 45001, "tcp"}, {7, 45000, "udp-paris"}} {
		if _, err := decodeScamperTrace(data, tgt, 1, 32, id); err == nil {
			t.Fatal("accepted unrelated result", id)
		}
	}
	if _, err := decodeScamperTrace(data, tgt, 1, 32, probeIdentity{7, 45000, "tcp"}); err != nil {
		t.Fatal(err)
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
func TestCoverageUsesSingleTaskAndPreservesOutputOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	p := coverageProbe{run: func(ctx context.Context, args []string) ([]byte, error) {
		calls++
		cancel()
		return []byte(`{"type":"trace","dst":"9.9.9.9","firsthop":1,"hop_count":4,"probe_count":6,"stop_reason":"HOPLIMIT","hops":[{"addr":"1.1.1.1","probe_ttl":1,"rtt":1,"icmp_type":11,"icmp_code":0}]}`), context.Canceled
	}}
	result := p.Run(ctx, target{"9.9.9.9", "tcp", 443}, probePlan{Method: "tcp"}, func(snapshot) {})
	if calls != 1 || result.replies() != 1 || result.Status != "cancelled" {
		t.Fatalf("lost whole-task cancellation evidence: %+v", result)
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
func TestAlternateMethodsRemainSeparateUsefulPaths(t *testing.T) {
	app := testApp(t)
	session := testSession(t, app)
	repo := repository{app: app}
	now := time.Now()
	tgt := target{"9.9.9.9", "tcp", 443}
	for i, method := range []string{"tcp:443", "icmp-paris"} {
		s := snapshot{Attempt: method, Revision: 1, Method: method, Measured: now, Finished: now, Reached: true, Hops: []Hop{{TTL: 1, Address: []string{"1.1.1.1", "8.8.8.8"}[i]}, {TTL: 3, Address: tgt.IP}}}
		if _, err := repo.publish(tgt.key("network"), "network", session, tgt, cacheEntry{}, s, "reached", "measured", now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	records, _ := app.FindAllRecords("routes")
	if len(records) != 2 {
		t.Fatal(len(records))
	}
	for _, r := range records {
		var hops []Hop
		data, _ := json.Marshal(r.Get("hops"))
		_ = json.Unmarshal(data, &hops)
		if len(hops) != 2 {
			t.Fatal("spliced attempts")
		}
	}
}
