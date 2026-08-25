package observer

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
)

const (
	destinationEnrichmentInterval = 3 * time.Second
	routeDiscoveryInterval        = 30 * time.Second
	destinationRefreshInterval    = 15 * time.Minute
)

type DestinationObservation struct {
	IP              string
	SessionID       string
	DestinationPort int
	Protocol        string
	LastSeen        time.Time
}

type RouteHop struct {
	TTL      int       `json:"ttl"`
	Address  string    `json:"address"`
	Missing  bool      `json:"missing"`
	Timings  []float64 `json:"timings"`
	City     string    `json:"city,omitempty"`
	Country  string    `json:"country,omitempty"`
	Lat      float64   `json:"lat,omitempty"`
	Lon      float64   `json:"lon,omitempty"`
	Hostname string    `json:"hostname,omitempty"`
}

type RouteResult struct {
	Method   string
	Hops     []RouteHop
	Complete bool
	Error    string
}

func StartDestinationEnricher(ctx context.Context, app *pocketbase.PocketBase, geoipDB *geoip2.Reader, sessionID func() string) {
	go func() {
		ticker := time.NewTicker(destinationEnrichmentInterval)
		defer ticker.Stop()

		for {
			activeSessionID := sessionID()
			if activeSessionID != "" {
				if err := enrichDestinationRecords(app, geoipDB, activeSessionID); err != nil {
					log.Printf("destination enricher error: %v", err)
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(routeDiscoveryInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				activeSessionID := sessionID()
				if activeSessionID == "" {
					continue
				}
				if err := traceNextDestination(ctx, app, geoipDB, activeSessionID); err != nil {
					log.Printf("route discovery error: %v", err)
				}
			}
		}
	}()
}

func sessionDestinationObservations(app *pocketbase.PocketBase, sessionID string) ([]DestinationObservation, error) {
	flowRecords, err := app.FindAllRecords("flows", dbx.HashExp{"session": sessionID})
	if err != nil {
		return nil, err
	}
	return uniqueDestinationObservations(flowRecords), nil
}

func enrichDestinationRecords(app *pocketbase.PocketBase, geoipDB *geoip2.Reader, sessionID string) error {
	observations, err := sessionDestinationObservations(app, sessionID)
	if err != nil {
		return err
	}
	for _, observation := range uniqueDestinationIPs(observations) {
		if _, err := upsertDestination(app, geoipDB, observation); err != nil {
			return err
		}
	}
	return nil
}

func uniqueDestinationIPs(observations []DestinationObservation) []DestinationObservation {
	seen := make(map[string]DestinationObservation)
	for _, observation := range observations {
		existing, ok := seen[observation.IP]
		if !ok || observation.LastSeen.After(existing.LastSeen) {
			seen[observation.IP] = observation
		}
	}
	result := make([]DestinationObservation, 0, len(seen))
	for _, observation := range seen {
		result = append(result, observation)
	}
	return result
}

func traceNextDestination(ctx context.Context, app *pocketbase.PocketBase, geoipDB *geoip2.Reader, sessionID string) error {
	observations, err := sessionDestinationObservations(app, sessionID)
	if err != nil {
		return err
	}
	for _, observation := range observations {
		exists, err := routeExists(app, observation)
		if err != nil {
			return err
		}
		if exists {
			continue
		}

		destinationRecord, err := upsertDestination(app, geoipDB, observation)
		if err != nil {
			return err
		}
		result := TraceDestination(ctx, observation)
		enrichRouteHops(result.Hops, geoipDB)
		if err := saveRoute(app, observation, destinationRecord.Id, result); err != nil {
			return err
		}
		return nil
	}
	return nil
}

func uniqueDestinationObservations(records []*core.Record) []DestinationObservation {
	seen := map[string]DestinationObservation{}
	for _, record := range records {
		observation := DestinationObservation{
			IP:              record.GetString("destination_ip"),
			SessionID:       record.GetString("session"),
			DestinationPort: record.GetInt("destination_port"),
			Protocol:        strings.ToLower(record.GetString("protocol")),
			LastSeen:        record.GetDateTime("last_seen").Time(),
		}
		if net.ParseIP(observation.IP) == nil {
			continue
		}
		key := routeKey(observation)
		existing, ok := seen[key]
		if !ok || observation.LastSeen.After(existing.LastSeen) {
			seen[key] = observation
		}
	}

	observations := make([]DestinationObservation, 0, len(seen))
	for _, observation := range seen {
		observations = append(observations, observation)
	}
	return observations
}

func upsertDestination(app *pocketbase.PocketBase, geoipDB *geoip2.Reader, observation DestinationObservation) (*core.Record, error) {
	nowTime := time.Now().UTC()
	now := nowTime.Format(time.RFC3339)
	record, err := app.FindFirstRecordByFilter("destinations", "ip={:ip}", dbx.Params{"ip": observation.IP})
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		collection, err := app.FindCollectionByNameOrId("destinations")
		if err != nil {
			return nil, err
		}
		record = core.NewRecord(collection)
		record.Set("ip", observation.IP)
		record.Set("first_seen", now)
	}

	reverseName := record.GetString("reverse_dns")
	lastEnriched := record.GetDateTime("enriched_at").Time()
	shouldRefresh := lastEnriched.IsZero() || nowTime.Sub(lastEnriched) >= destinationRefreshInterval
	if shouldRefresh {
		if refreshedName := lookupReverseDNS(observation.IP); refreshedName != "" {
			reverseName = refreshedName
		}
		record.Set("enriched_at", now)
	}
	organization, knownProvider := knownDestinationProvider(observation)
	provider := providerLabel(reverseName)
	source := "geoip_reverse_dns"
	if knownProvider != "" {
		provider = knownProvider
		source = "known_network"
	}
	record.Set("reverse_dns", reverseName)
	record.Set("provider_label", provider)
	if organization != "" {
		record.Set("organization", organization)
	}
	record.Set("last_seen", now)
	record.Set("source", source)

	if shouldRefresh && geoipDB != nil {
		if city, err := geoipDB.City(net.ParseIP(observation.IP)); err == nil {
			record.Set("city", city.City.Names["en"])
			record.Set("country", city.Country.Names["en"])
			record.Set("lat", city.Location.Latitude)
			record.Set("lon", city.Location.Longitude)
		}
	}

	if err := app.Save(record); err != nil {
		return nil, err
	}
	return record, nil
}

func knownDestinationProvider(observation DestinationObservation) (organization, provider string) {
	ip, err := netip.ParseAddr(observation.IP)
	if err != nil {
		return "", ""
	}
	appleNetwork := netip.MustParsePrefix("17.0.0.0/8")
	if appleNetwork.Contains(ip) {
		return "Apple Inc.", "Apple"
	}
	return "", ""
}

func routeExists(app *pocketbase.PocketBase, observation DestinationObservation) (bool, error) {
	_, err := app.FindFirstRecordByFilter(
		"routes",
		"session={:session} && destination_ip={:ip} && destination_port={:port} && method={:method}",
		dbx.Params{
			"session": observation.SessionID,
			"ip":      observation.IP,
			"port":    observation.DestinationPort,
			"method":  routeMethod(observation),
		},
	)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return false, err
}

func saveRoute(app *pocketbase.PocketBase, observation DestinationObservation, destinationID string, result RouteResult) error {
	collection, err := app.FindCollectionByNameOrId("routes")
	if err != nil {
		return err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	record := core.NewRecord(collection)
	record.Set("session", observation.SessionID)
	record.Set("destination", destinationID)
	record.Set("destination_ip", observation.IP)
	record.Set("destination_port", observation.DestinationPort)
	record.Set("protocol", observation.Protocol)
	record.Set("method", result.Method)
	record.Set("hops", result.Hops)
	record.Set("complete", result.Complete)
	record.Set("error", result.Error)
	record.Set("started_at", now)
	record.Set("completed_at", now)
	return app.Save(record)
}

func TraceDestination(ctx context.Context, observation DestinationObservation) RouteResult {
	method := routeMethod(observation)
	args := routeArgs(observation)

	traceCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()

	cmd := exec.CommandContext(traceCtx, "traceroute", args...)
	output, err := cmd.CombinedOutput()

	result := RouteResult{
		Method: method,
		Hops:   ParseTracerouteOutput(output),
	}
	result.Complete = routeComplete(result.Hops, observation.IP)
	if err != nil {
		result.Error = strings.TrimSpace(err.Error())
	}
	if traceCtx.Err() == context.DeadlineExceeded {
		result.Error = "traceroute timed out"
	}
	return result
}

func routeMethod(observation DestinationObservation) string {
	if strings.ToLower(observation.Protocol) == "tcp" && observation.DestinationPort > 0 {
		return fmt.Sprintf("tcp:%d", observation.DestinationPort)
	}
	return "default"
}

func routeArgs(observation DestinationObservation) []string {
	base := []string{"-n", "-w", "1", "-q", "1", "-m", "20"}
	if strings.ToLower(observation.Protocol) == "tcp" && observation.DestinationPort > 0 {
		base = append(base, "-T", "-p", strconv.Itoa(observation.DestinationPort))
	}
	return append(base, observation.IP)
}

func ParseTracerouteOutput(output []byte) []RouteHop {
	scanner := bufio.NewScanner(bytes.NewReader(output))
	hops := []RouteHop{}
	lineRE := regexp.MustCompile(`^\s*(\d+)\s+(.+)$`)
	ipRE := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	timeRE := regexp.MustCompile(`([0-9]+(?:\.[0-9]+)?)\s*ms`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		matches := lineRE.FindStringSubmatch(line)
		if len(matches) != 3 {
			continue
		}

		ttl, _ := strconv.Atoi(matches[1])
		body := matches[2]
		hop := RouteHop{TTL: ttl}

		if strings.Contains(body, "*") && !ipRE.MatchString(body) {
			hop.Missing = true
		}
		if ipMatch := ipRE.FindString(body); ipMatch != "" {
			hop.Address = ipMatch
		}
		for _, timing := range timeRE.FindAllStringSubmatch(body, -1) {
			value, err := strconv.ParseFloat(timing[1], 64)
			if err == nil {
				hop.Timings = append(hop.Timings, value)
			}
		}
		hops = append(hops, hop)
	}

	return hops
}

func routeComplete(hops []RouteHop, destinationIP string) bool {
	if len(hops) == 0 {
		return false
	}
	last := hops[len(hops)-1]
	return last.Address == destinationIP
}

func enrichRouteHops(hops []RouteHop, geoipDB *geoip2.Reader) {
	if geoipDB == nil {
		return
	}
	for i := range hops {
		if hops[i].Address == "" {
			continue
		}
		ip := net.ParseIP(hops[i].Address)
		if ip == nil {
			continue
		}
		if city, err := geoipDB.City(ip); err == nil {
			hops[i].City = city.City.Names["en"]
			hops[i].Country = city.Country.Names["en"]
			hops[i].Lat = city.Location.Latitude
			hops[i].Lon = city.Location.Longitude
		}
	}
}

func lookupReverseDNS(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(names[0]), ".")
}

func providerLabel(reverseName string) string {
	reverseName = strings.TrimSuffix(strings.ToLower(reverseName), ".")
	if reverseName == "" {
		return ""
	}
	parts := strings.Split(reverseName, ".")
	if len(parts) < 2 {
		return reverseName
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func routeKey(observation DestinationObservation) string {
	return fmt.Sprintf("%s|%s|%d", observation.IP, strings.ToLower(observation.Protocol), observation.DestinationPort)
}
