package routing

import (
	"fmt"
	"testing"
	"time"
)

func TestEvidenceClassificationAndFingerprint(t *testing.T) {
	tgt := target{"9.9.9.9", "tcp", 443}
	s := useful(time.Now(), "a")
	if got := classifyRouteEvidence(s, tgt, nil).Class; got != "useful_path" {
		t.Fatal(got)
	}
	s.Hops = s.Hops[3:]
	if got := classifyRouteEvidence(s, tgt, nil).Class; got != "endpoint_only" {
		t.Fatal(got)
	}
	s.Reached = false
	s.Hops = nil
	s.Status = "unavailable"
	if classifyRouteEvidence(s, tgt, nil).Class != "no_path" {
		t.Fatal("silent path counted useful")
	}
	s = useful(time.Now(), "a")
	f := pathFingerprint(s, tgt, "net")
	s.Attempt = "b"
	s.Measured = time.Now().Add(time.Hour)
	s.Hops[0].Timings = []float64{500}
	s.Hops = append(s.Hops, Hop{TTL: 14, Missing: true, State: "no_reply"})
	if f != pathFingerprint(s, tgt, "net") {
		t.Fatal("noise changed material fingerprint")
	}
	s.Hops[1].Address = "8.8.8.8"
	if f == pathFingerprint(s, tgt, "net") {
		t.Fatal("real topology change lost")
	}
}

func TestEvidencePolicyTable(t *testing.T) {
	tgt := target{"9.9.9.9", "tcp", 443}
	for _, tc := range []struct {
		name string
		s    snapshot
		want string
	}{
		{"silent", snapshot{Status: "unavailable"}, "no_path"},
		{"local", snapshot{Hops: []Hop{{TTL: 1, Address: "192.168.1.1"}}}, "access_only"},
		{"endpoint", snapshot{Reached: true, Hops: []Hop{{TTL: 13, Address: tgt.IP}}}, "endpoint_only"},
		{"reached after silent middle", snapshot{Reached: true, Hops: []Hop{{TTL: 1, Address: "192.168.1.1"}, {TTL: 13, Address: tgt.IP}}}, "access_only"},
		{"unlocated public", snapshot{Hops: []Hop{{TTL: 5, Address: "1.1.1.1"}}}, "useful_path"},
		{"cancelled", snapshot{Status: "cancelled"}, "indeterminate"},
		{"local failure", snapshot{Status: "failed"}, "indeterminate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyRouteEvidence(tc.s, tgt, nil); got.Class != tc.want {
				t.Fatal(got)
			}
		})
	}
}

// Replays the shape captured in the Pi's 17 September "testing" session:
// two shared access hops, a long silent span, then a responding TCP endpoint.
func TestDiagnosticReportsCapturedButUndecodedResponders(t *testing.T) {
	headers := "12:00:00 IP 10.0.0.1 > 10.0.0.2: ICMP time exceeded in-transit\n12:00:01 IP 9.9.9.9.443 > 10.0.0.2.45000: Flags [R.]"
	result := diagnosticReplyAccounting(headers, []Hop{{TTL: 2, Address: "9.9.9.9"}})
	if result["candidate_match_failures"] != 1 || fmt.Sprint(result["captured_not_decoded"]) != "[10.0.0.1]" {
		t.Fatal(result)
	}
}
func TestAccessConsensusNeedsThreeDistinctDestinations(t *testing.T) {
	a := accessEvidence{}
	s := useful(time.Now(), "a")
	s.Reached = false
	s.Hops = s.Hops[:2]
	for i := 0; i < 3; i++ {
		a = learnAccess(a, s, target{fmt.Sprintf("9.9.9.%d", i+1), "tcp", 443})
		if i < 2 && len(establishedAccess(a)) != 0 {
			t.Fatal("premature access consensus")
		}
	}
	if len(establishedAccess(a)) != 2 || classifyRouteEvidence(s, target{"9.9.9.9", "tcp", 443}, establishedAccess(a)).Class != "access_only" {
		t.Fatal(a)
	}
	s.Hops = append(s.Hops, Hop{TTL: 8, Address: "8.8.8.8"})
	if classifyRouteEvidence(s, target{"9.9.9.9", "tcp", 443}, establishedAccess(a)).Class != "useful_path" {
		t.Fatal("lost public interface beyond access")
	}
}
