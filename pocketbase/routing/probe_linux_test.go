//go:build linux

package routing

import (
	"os"
	"testing"
)

// Run in the shipped proxy image with ROUTE_TEST_LINUX=1. This reads local
// routing configuration without sending measurement traffic.
func TestLinuxNetworkFingerprintStable(t *testing.T) {
	if os.Getenv("ROUTE_TEST_LINUX") != "1" {
		t.Skip("requires Linux routing commands")
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
