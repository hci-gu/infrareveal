//go:build linux

package routing

import (
	"context"
	"os"
	"testing"
	"time"
)

// Run in the shipped proxy image with ROUTE_TEST_LINUX=1. Loopback requires
// no outside network and exercises the real executable, flags and parser.
func TestShippedLinuxTraceroute(t *testing.T) {
	if os.Getenv("ROUTE_TEST_LINUX") != "1" {
		t.Skip("requires traceroute and raw socket capability")
	}
	for _, protocol := range []string{"tcp", "udp"} {
		t.Run(protocol, func(t *testing.T) {
			s := (commandProbe{deadline: 3 * time.Second}).Run(context.Background(), target{"127.0.0.1", protocol, 49999}, probePlan{}, func(snapshot) {})
			if !s.Reached || s.replies() != 1 || s.Error != "" {
				t.Fatalf("real Linux probe: %+v", s)
			}
		})
	}
	first, err := networkContext()
	if err != nil {
		t.Fatal(err)
	}
	second, err := networkContext()
	if err != nil || first != second {
		t.Fatalf("network context unstable: %s %s %v", first, second, err)
	}
}
