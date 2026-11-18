package gateway

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"myapp/data"
)

const stationDump = `Station AA:bb:cc:00:00:01 (on wlan0)
	inactive time:	120 ms
	rx bytes:	1024
Station aa:bb:cc:00:00:02 (on wlan0)
	inactive time:	40 ms
Station aa:bb:cc:00:00:03 (on wlan0)
Station not-a-mac (on wlan0)
`

func TestParseStations(t *testing.T) {
	got := parseStations(stationDump)
	if len(got) != 3 || got[0] != "aa:bb:cc:00:00:01" || got[2] != "aa:bb:cc:00:00:03" {
		t.Fatalf("stations = %v", got)
	}
}

func TestConnectedClientsIdentifiesStationsAndCaches(t *testing.T) {
	leases := filepath.Join(t.TempDir(), "leases")
	if err := os.WriteFile(leases, []byte("0 aa:bb:cc:00:00:01 10.0.0.20 phone 01:aa\n0 AA:BB:CC:00:00:02 10.0.0.21 * *\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	arp := filepath.Join(t.TempDir(), "arp")
	if err := os.WriteFile(arp, []byte("IP address       HW type     Flags       HW address            Mask     Device\n10.0.0.30        0x1         0x2         aa:bb:cc:00:00:03     *        wlan0\n10.0.0.31        0x1         0x2         aa:bb:cc:00:00:01     *        eth0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	calls := 0
	c := connectedClients{arp: arp, now: func() time.Time { return now }, stations: func(context.Context, string) ([]string, error) {
		calls++
		return parseStations(stationDump), nil
	}}
	display := func(mac string) bool { return mac == "aa:bb:cc:00:00:02" }
	got := c.read(context.Background(), "wlan0", leases, "session", display)
	if !got.Available || got.Connected != 2 || got.Displays != 1 || len(got.Clients) != 2 {
		t.Fatalf("status = %+v", got)
	}
	// Leases name a station; without one, the AP's neighbour table supplies the address.
	if got.Clients[0] != (connectedClient{ID: data.ID("session", "10.0.0.20", "aa:bb:cc:00:00:01"), IP: "10.0.0.20", Hostname: "phone"}) ||
		got.Clients[1] != (connectedClient{ID: data.ID("session", "10.0.0.30", "aa:bb:cc:00:00:03"), IP: "10.0.0.30"}) {
		t.Fatalf("clients = %+v", got.Clients)
	}
	c.read(context.Background(), "wlan0", leases, "session", display)
	if calls != 1 {
		t.Fatalf("expected cached read, calls = %d", calls)
	}
	now = now.Add(connectedClientsTTL)
	c.stations = func(context.Context, string) ([]string, error) { calls++; return nil, errors.New("no iw") }
	if got := c.read(context.Background(), "wlan0", leases, "session", display); got.Available || calls != 2 || len(got.Clients) != 0 {
		t.Fatalf("status after failure = %+v, calls = %d", got, calls)
	}
}
