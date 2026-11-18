package gateway

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
	"myapp/data"
)

const connectedClientsTTL = 2 * time.Second

// connectedClients reports Wi-Fi stations currently associated with the
// participant access point. Unlike DHCP leases, association ends when a device
// leaves, and unlike traffic it includes idle devices. Display devices are
// connected but deliberately not observed, so they are counted separately.
type connectedClients struct {
	mu       sync.Mutex
	at       time.Time
	macs     []string
	err      error
	stations func(ctx context.Context, iface string) ([]string, error)
	arp      string
	now      func() time.Time
}

type connectedClientsStatus struct {
	Available bool              `json:"available"`
	Connected int               `json:"connected"`
	Displays  int               `json:"displays"`
	Clients   []connectedClient `json:"clients"`
	SessionID string            `json:"sessionId,omitempty"`
	ServerMS  int64             `json:"serverMs"`
}

// ID matches traffic_chunks.client_id for the current session, so the map can
// scope one device. It is empty until the device has a DHCP lease.
type connectedClient struct {
	ID       string `json:"id"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

type stationLease struct{ ip, hostname string }

func (c *connectedClients) read(ctx context.Context, iface, leasePath, session string, display func(mac string) bool) connectedClientsStatus {
	macs, err := c.stationMACs(ctx, iface)
	result := connectedClientsStatus{Available: err == nil, Clients: []connectedClient{}}
	leases := readStationLeases(leasePath)
	var neighbours map[string]string
	for _, mac := range macs {
		if display(mac) {
			result.Displays++
			continue
		}
		result.Connected++
		lease := leases[mac]
		if lease.ip == "" {
			// A static address, or a lease lost across a restart, still appears
			// in the kernel neighbour table once the device has sent traffic.
			if neighbours == nil {
				neighbours = readNeighbours(c.arpPath(), iface)
			}
			lease.ip = neighbours[mac]
		}
		client := connectedClient{IP: lease.ip, Hostname: lease.hostname}
		if lease.ip != "" && session != "" {
			client.ID = data.ID(session, lease.ip, mac)
		}
		result.Clients = append(result.Clients, client)
	}
	sort.Slice(result.Clients, func(i, j int) bool {
		a, b := result.Clients[i], result.Clients[j]
		return a.IP < b.IP || (a.IP == b.IP && a.Hostname < b.Hostname)
	})
	return result
}

func (c *connectedClients) stationMACs(ctx context.Context, iface string) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock()
	if !c.at.IsZero() && now.Sub(c.at) < connectedClientsTTL {
		return c.macs, c.err
	}
	stations := c.stations
	if stations == nil {
		stations = iwStations
	}
	c.macs, c.err = stations(ctx, iface)
	c.at = now
	return c.macs, c.err
}

// readStationLeases reads dnsmasq leases: "<expiry> <mac> <ip> <hostname> <client-id>".
func readStationLeases(path string) map[string]stationLease {
	leases := map[string]stationLease{}
	f, err := os.Open(path)
	if err != nil {
		return leases
	}
	defer f.Close()
	scanner := bufio.NewScanner(io.LimitReader(f, 1024*1024))
	for scanner.Scan() && len(leases) < 1024 {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		mac, err := net.ParseMAC(fields[1])
		ip, ipErr := netip.ParseAddr(fields[2])
		if err != nil || ipErr != nil {
			continue
		}
		lease := stationLease{ip: ip.Unmap().String()}
		if len(fields) > 3 && fields[3] != "*" {
			lease.hostname = fields[3]
		}
		leases[mac.String()] = lease
	}
	return leases
}

// readNeighbours maps MAC to IPv4 from /proc/net/arp for one interface:
// "IP address  HW type  Flags  HW address  Mask  Device". Incomplete entries have flags 0x0.
func readNeighbours(path, iface string) map[string]string {
	neighbours := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return neighbours
	}
	defer f.Close()
	scanner := bufio.NewScanner(io.LimitReader(f, 1024*1024))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 || fields[5] != iface || fields[2] == "0x0" {
			continue
		}
		mac, err := net.ParseMAC(fields[3])
		ip, ipErr := netip.ParseAddr(fields[0])
		if err != nil || ipErr != nil {
			continue
		}
		neighbours[mac.String()] = ip.Unmap().String()
	}
	return neighbours
}

func (c *connectedClients) arpPath() string {
	if c.arp != "" {
		return c.arp
	}
	return "/proc/net/arp"
}

func (c *connectedClients) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func iwStations(ctx context.Context, iface string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "iw", "dev", iface, "station", "dump").Output()
	if err != nil {
		return nil, err
	}
	return parseStations(string(output)), nil
}

// parseStations reads `iw station dump`, whose entries begin "Station <mac> (on <iface>)".
func parseStations(output string) []string {
	var macs []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || fields[0] != "Station" {
			continue
		}
		if mac, err := net.ParseMAC(fields[1]); err == nil {
			macs = append(macs, mac.String())
		}
	}
	return macs
}

func (g *Runtime) registerClientRoutes(r *router.Router[*core.RequestEvent]) {
	r.GET("/api/infrareveal/clients", func(e *core.RequestEvent) error {
		session := g.CurrentSessionID()
		result := g.clients.read(e.Request.Context(), g.config.APInterface, g.config.Observation.LeasePath, session, g.displays.ActiveMAC)
		result.SessionID = session
		result.ServerMS = time.Now().UnixMilli()
		return e.JSON(http.StatusOK, result)
	})
}
