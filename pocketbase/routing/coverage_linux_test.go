//go:build linux

package routing

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestLinuxCoverageNetwork(t *testing.T) {
	method := os.Getenv("IR_ROUTE_NETNS_CASE")
	if method == "" {
		t.Skip("run scripts/test-route-coverage-netns.sh in an isolated Linux container")
	}
	target := target{IP: "10.249.2.2", Protocol: "tcp", Port: 49999}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if method == "legacy" {
		out, err := exec.CommandContext(ctx, "traceroute", "-n", "-T", "-p", "49999", "-q", "1", "-w", "1", "-m", "2", target.IP).CombinedOutput()
		if err != nil {
			t.Fatalf("legacy traceroute: %v: %s", err, out)
		}
		hops := parseHops(out)
		if len(hops) != 2 || !hops[0].Missing || hops[1].Address != target.IP {
			t.Fatalf("loss fixture did not reproduce the missing router: %s", out)
		}
		t.Log("One-query TCP baseline: 1/2 responding hops")
		return
	}
	if method != "tcp" && method != "udp-paris" && method != "icmp-paris" {
		t.Fatal("unknown namespace test case")
	}
	probe := coverageProbe{deadline: 12 * time.Second}
	result := probe.Run(ctx, target, probePlan{Quality: true, Method: method}, func(snapshot) {})
	if !result.Reached || result.replies() != 2 || result.Hops[0].Address != "10.249.1.1" || result.ProbeCount <= 2 {
		t.Fatalf("coverage did not recover the dropped router response: %+v", result)
	}
	t.Logf("%s: 2/2 responding hops, destination reached, %d probes", method, result.ProbeCount)
	// A later segment must retain absolute TTLs (scamper's hop_count includes
	// skipped TTLs) and still recognize a terminal reply.
	data, err := probe.execute(ctx, []string{"-O", "json", "-O", "rawtcp", "-p", "5", "-c", "trace -T -P " + method + " -d 49999 -s 45000 -q 3 -w 1 -W 20 -g 32 -N 1 -f 5 -m 8", "-i", target.IP})
	if err != nil {
		t.Fatal(err)
	}
	segment, err := decodeScamperTrace(data, target, 5, 8)
	if err != nil || !segment.Reached || len(segment.Hops) != 1 || segment.Hops[0].TTL != 5 {
		t.Fatalf("later segment failed: %+v %v: %s", segment, err, data)
	}
}

func TestLinuxRouteDiagnostic(t *testing.T) {
	mode := os.Getenv("IR_ROUTE_NETNS_CASE")
	if mode != "diagnostic" && mode != "diagnostic-fast" {
		t.Skip("run scripts/test-route-coverage-netns.sh")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var output bytes.Buffer
	if err := Diagnose(ctx, "10.249.2.2", 49999, "send", 5*time.Second, 3, &output); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&output)
	comparisons := 0
	for decoder.More() {
		var row struct {
			Type         string `json:"type"`
			Profile      string `json:"profile"`
			Hops         []Hop  `json:"hops"`
			Headers      string `json:"icmp_headers"`
			CaptureError string `json:"capture_error"`
			CaptureStats string `json:"capture_stats"`
		}
		if err := decoder.Decode(&row); err != nil {
			t.Fatal(err)
		}
		if row.Type != "comparison" {
			continue
		}
		comparisons++
		if row.CaptureError != "" || !strings.Contains(row.Headers, "10.249.1.1") || !strings.Contains(row.CaptureStats, "0 packets dropped by kernel") {
			t.Fatalf("%s failed to capture the reply before INPUT dropped it: %+v", row.Profile, row)
		}
		if len(row.Hops) == 0 || row.Hops[0].Missing != (mode == "diagnostic") {
			t.Fatalf("unexpected traceroute response for %s: %+v", mode, row)
		}
	}
	if comparisons != 4 {
		t.Fatalf("got %d comparisons", comparisons)
	}
	t.Logf("All four profiles captured returning ICMP in %s", mode)
}
