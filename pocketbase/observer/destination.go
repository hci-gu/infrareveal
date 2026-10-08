package observer

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	"myapp/debugtrace"

	"github.com/oschwald/geoip2-golang"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
)

const destinationRefreshInterval = 15 * time.Minute

type DestinationObservation struct {
	IP              string
	SessionID       string
	DestinationPort int
	Protocol        string
	LastSeen        time.Time
}

func uniqueDestinationObservations(records []*core.Record, scope ObservationScope) []DestinationObservation {
	seen := map[string]DestinationObservation{}
	for _, record := range records {
		observation := DestinationObservation{
			IP:              record.GetString("destination_ip"),
			SessionID:       record.GetString("session"),
			DestinationPort: record.GetInt("destination_port"),
			Protocol:        strings.ToLower(record.GetString("protocol")),
			LastSeen:        record.GetDateTime("last_seen").Time(),
		}
		if !scope.Includes(
			record.GetString("protocol"),
			record.GetString("client_ip"),
			observation.IP,
			observation.DestinationPort,
		) {
			continue
		}
		if net.ParseIP(observation.IP) == nil {
			continue
		}
		key := observation.IP
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

func upsertDestination(ctx context.Context, app *pocketbase.PocketBase, geoipDB *geoip2.Reader, observation DestinationObservation) (*core.Record, bool, error) {
	nowTime := time.Now().UTC()
	now := nowTime.Format(time.RFC3339)
	record, err := app.FindFirstRecordByFilter("destinations", "ip={:ip}", dbx.Params{"ip": observation.IP})
	created := false
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, false, err
		}
		collection, err := app.FindCollectionByNameOrId("destinations")
		if err != nil {
			return nil, false, err
		}
		record = core.NewRecord(collection)
		created = true
		record.Set("ip", observation.IP)
		record.Set("first_seen", now)
	}

	reverseName := record.GetString("reverse_dns")
	lastEnriched := record.GetDateTime("enriched_at").Time()
	shouldRefresh := lastEnriched.IsZero() || nowTime.Sub(lastEnriched) >= destinationRefreshInterval
	if shouldRefresh {
		if refreshedName := lookupReverseDNS(ctx, observation.IP); refreshedName != "" {
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
		return nil, false, err
	}
	return record, created || shouldRefresh, nil
}

func emitDestinationTrace(trace debugtrace.Sink, observation DestinationObservation, record *core.Record) {
	observedAt := record.GetDateTime("last_seen").Time()
	trace.TryEmit(debugtrace.Event{
		ID: traceEventID("destination-enriched", record.Id, observedAt), SessionID: observation.SessionID,
		TraceID: "destination:" + observation.IP, Kind: debugtrace.KindDestination, Stage: debugtrace.StageDestination,
		OccurredAtMs: observedAt.UnixMilli(), ProcessedAtMs: traceProcessedNow(), Timing: debugtrace.TimingDerived,
		Summary: debugtrace.Summary{
			Protocol: observation.Protocol, RemoteIP: observation.IP, RemotePort: tracePort(observation.DestinationPort),
			Hostname: record.GetString("reverse_dns"),
		},
	})
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

func lookupReverseDNS(parent context.Context, ip string) string {
	ctx, cancel := context.WithTimeout(parent, 500*time.Millisecond)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
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
