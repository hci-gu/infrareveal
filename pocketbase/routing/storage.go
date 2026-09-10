package routing

import (
	"database/sql"
	"encoding/json"
	"errors"
	"maps"
	"net"
	"sort"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

type repository struct {
	app        core.App
	geo        *geoip2.Reader
	geoVersion string
	locations  map[string]*Location
}

// Invalidate persisted bindings too: an idle demand may have left memory while
// its cached path is still visible in the active session.
func (r repository) invalidateSession(session, network string, now time.Time) error {
	if session == "" {
		return nil
	}
	return r.app.RunInTransaction(func(app core.App) error {
		var rows []*core.Record
		err := app.RecordQuery("routes").AndWhere(dbx.HashExp{"session": session, "network_context": network}).AndWhere(dbx.NewExp(`NOT EXISTS (SELECT 1 FROM routes newer WHERE newer.session=routes.session AND newer.binding_key=routes.binding_key AND (newer.available_at>routes.available_at OR (newer.available_at=routes.available_at AND newer.id>routes.id)))`)).All(&rows)
		if err != nil {
			return err
		}
		for _, old := range rows {
			if old.GetString("status") == "invalidated" {
				continue
			}
			c, err := app.FindCollectionByNameOrId("routes")
			if err != nil {
				return err
			}
			record := core.NewRecord(c)
			for _, field := range []string{"session", "binding_key", "network_context", "destination_ip", "destination_port", "protocol", "method"} {
				record.Set(field, old.Get(field))
			}
			at := now
			previous := old.GetDateTime("available_at").Time()
			if !at.Truncate(time.Millisecond).After(previous) {
				at = previous.Add(time.Millisecond)
			}
			record.Set("status", "invalidated")
			record.Set("available_at", date(at))
			record.Set("valid_until", date(at))
			record.Set("hops", []Hop{})
			if err = app.Save(record); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r repository) location(ip string) *Location {
	if cached, ok := r.locations[ip]; ok {
		return cached
	}
	if r.geo == nil {
		return nil
	}
	if len(r.locations) >= 8192 {
		clear(r.locations)
	}
	if r.locations != nil {
		r.locations[ip] = nil
	}
	c, err := r.geo.City(net.ParseIP(ip))
	if err != nil || (c.Location.Latitude == 0 && c.Location.Longitude == 0) {
		return nil
	}
	location := &Location{Lat: c.Location.Latitude, Lon: c.Location.Longitude, City: c.City.Names["en"], Country: c.Country.Names["en"], AccuracyKM: c.Location.AccuracyRadius, GeoVersion: r.geoVersion}
	if r.locations != nil {
		r.locations[ip] = location
	}
	return location
}
func (r repository) enrich(s snapshot, t target) snapshot {
	s.Hops = append([]Hop(nil), s.Hops...)
	for i := range s.Hops {
		h := &s.Hops[i]
		if loc := r.location(h.Address); loc != nil {
			h.Lat = &loc.Lat
			h.Lon = &loc.Lon
			h.City = loc.City
			h.Country = loc.Country
			h.AccuracyKM = loc.AccuracyKM
			h.GeoVersion = loc.GeoVersion
		}
	}
	s.Location = r.location(t.IP)
	return s
}
func (r repository) load(key string) (cacheEntry, error) {
	record, err := r.app.FindFirstRecordByFilter("route_cache", "cache_key={:key}", dbx.Params{"key": key})
	if errors.Is(err, sql.ErrNoRows) {
		return cacheEntry{}, nil
	}
	if err != nil {
		return cacheEntry{}, err
	}
	var e cacheEntry
	data, err := json.Marshal(record.Get("entry"))
	if err != nil {
		return e, err
	}
	err = json.Unmarshal(data, &e)
	return e, err
}

// One transaction makes the global observation, cache and session projection
// visible together. Revisions already referenced by a session are immutable.
func (r repository) publish(key, network, session string, t target, e cacheEntry, s snapshot, state, provenance string, now time.Time) (cacheEntry, error) {
	// A rolled-back transaction must not leak uncommitted observation IDs into
	// the coordinator's live cache through the shared methods map.
	e.Methods = maps.Clone(e.Methods)
	err := r.app.RunInTransaction(func(app core.App) error {
		values := []*snapshot{&s, &e.Best, &e.Last}
		methods := map[string]*snapshot{}
		for method, value := range e.Methods {
			copied := value
			methods[method] = &copied
			values = append(values, &copied)
		}
		for _, value := range values {
			if value.Attempt == "" || value.ObservationID != "" {
				continue
			}
			record, err := app.FindFirstRecordByFilter("route_observations", "attempt_id={:attempt} && revision={:revision}", dbx.Params{"attempt": value.Attempt, "revision": value.Revision})
			if err != nil {
				if !errors.Is(err, sql.ErrNoRows) {
					return err
				}
				collection, err := app.FindCollectionByNameOrId("route_observations")
				if err != nil {
					return err
				}
				record = core.NewRecord(collection)
				record.Set("cache_key", key)
				record.Set("attempt_id", value.Attempt)
				record.Set("revision", value.Revision)
				record.Set("snapshot", value)
				record.Set("measured_at", date(value.Measured))
				if err = app.Save(record); err != nil {
					return err
				}
			}
			value.ObservationID = record.Id
		}
		for method, value := range methods {
			e.Methods[method] = *value
		}
		record, err := app.FindFirstRecordByFilter("route_cache", "cache_key={:key}", dbx.Params{"key": key})
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			c, err := app.FindCollectionByNameOrId("route_cache")
			if err != nil {
				return err
			}
			record = core.NewRecord(c)
			record.Set("cache_key", key)
		}
		record.Set("entry", e)
		record.Set("last_used_at", date(now))
		if err = app.Save(record); err != nil {
			return err
		}
		if session == "" {
			return nil
		}
		active, err := app.FindRecordById("sessions", session)
		if err != nil {
			return err
		}
		if !active.GetBool("active") {
			return nil
		}
		shown := e.Best
		if shown.replies() == 0 || !now.Before(e.ValidUntil) {
			shown = s
		}
		c, err := app.FindCollectionByNameOrId("routes")
		if err != nil {
			return err
		}
		route := core.NewRecord(c)
		route.Set("session", session)
		route.Set("binding_key", t.binding())
		route.Set("network_context", network)
		route.Set("destination_ip", t.IP)
		route.Set("destination_port", t.Port)
		route.Set("protocol", t.Protocol)
		method := shown.Method
		if method == "" {
			method = t.method()
		}
		route.Set("method", method)
		route.Set("attempt_id", shown.Attempt)
		route.Set("revision", shown.Revision)
		route.Set("observation_id", shown.ObservationID)
		route.Set("status", state)
		if shown.Attempt != "" && shown.Attempt != s.Attempt {
			provenance = "cache"
		}
		route.Set("provenance", provenance)
		details := probeDetails(shown)
		details["alternate_method"] = shown.Method != "" && methodProtocol(shown.Method) != t.Protocol
		if e.Last.Attempt != "" {
			details["latest_attempt"] = map[string]any{"method": e.Last.Method, "status": e.Last.Status, "error": e.Last.Error, "measured_at": date(e.Last.Measured), "responding_hops": e.Last.replies(), "located_hops": e.Last.located(), "profile": e.Last.Profile}
		}
		route.Set("probe_details", details)
		alternatives := []map[string]any{}
		names := []string{}
		for name := range e.Methods {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			value := e.Methods[name]
			lifetime := time.Minute
			if value.Reached {
				lifetime = time.Hour
			}
			if value.Attempt == shown.Attempt || !now.Before(value.Measured.Add(lifetime)) {
				continue
			}
			alternatives = append(alternatives, map[string]any{"method": value.Method, "hops": value.Hops, "destination_reached": value.Reached, "measured_at": date(value.Measured), "probe_details": probeDetails(value), "responding_hops": value.replies(), "located_hops": value.located()})
		}
		route.Set("alternate_routes", alternatives)
		route.Set("hops", shown.Hops)
		route.Set("complete", shown.Reached)
		route.Set("destination_reached", shown.Reached)
		route.Set("error", s.Error)
		// DateFields store milliseconds; ensure two publications within one
		// millisecond retain causal order rather than sorting random record IDs.
		var previous []*core.Record
		if err := app.RecordQuery("routes").AndWhere(dbx.HashExp{"session": session, "binding_key": t.binding()}).OrderBy("available_at DESC").Limit(1).All(&previous); err != nil {
			return err
		}
		if len(previous) > 0 {
			latest := previous[0].GetDateTime("available_at").Time()
			if !now.Truncate(time.Millisecond).After(latest) {
				now = latest.Add(time.Millisecond)
			}
		}
		route.Set("available_at", date(now))
		route.Set("started_at", date(shown.Started))
		route.Set("measured_at", date(shown.Measured))
		route.Set("completed_at", date(shown.Finished))
		route.Set("fresh_until", date(e.FreshUntil))
		route.Set("valid_until", date(e.ValidUntil))
		if e.Best.replies() == 0 || !now.Before(e.ValidUntil) {
			route.Set("valid_until", "")
			route.Set("fresh_until", "")
		}
		route.Set("destination_location", shown.Location)
		route.Set("responding_hops", shown.replies())
		located := 0
		for _, h := range shown.Hops {
			if h.Lat != nil {
				located++
			}
		}
		route.Set("located_hops", located)
		if state == "invalidated" {
			route.Set("hops", []Hop{})
			route.Set("valid_until", date(now))
			route.Set("complete", false)
			route.Set("destination_reached", false)
		}
		return app.Save(route)
	})
	return e, err
}
func (r repository) prune(now time.Time) error {
	_, err := r.app.DB().NewQuery(`DELETE FROM route_cache WHERE id IN (SELECT id FROM route_cache ORDER BY last_used_at DESC LIMIT -1 OFFSET 10000) OR last_used_at < {:cutoff}`).Bind(dbx.Params{"cutoff": now.Add(-24 * time.Hour).UTC().Format("2006-01-02 15:04:05.000Z")}).Execute()
	if err != nil {
		return err
	}
	_, err = r.app.DB().NewQuery(`DELETE FROM route_observations WHERE id IN (SELECT o.id FROM route_observations o WHERE o.measured_at < {:cutoff} AND NOT EXISTS (SELECT 1 FROM routes r WHERE r.observation_id=o.id) AND NOT EXISTS (SELECT 1 FROM route_cache c WHERE json_extract(c.entry,'$.best.observation_id')=o.id OR json_extract(c.entry,'$.last.observation_id')=o.id OR EXISTS (SELECT 1 FROM json_each(c.entry,'$.methods') method WHERE json_extract(method.value,'$.observation_id')=o.id)) LIMIT 500)`).Bind(dbx.Params{"cutoff": now.Add(-24 * time.Hour).UTC().Format("2006-01-02 15:04:05.000Z")}).Execute()
	return err
}

func probeDetails(s snapshot) map[string]any {
	replies := 0
	for _, hop := range s.Hops {
		replies += len(hop.Replies)
	}
	return map[string]any{"engine": s.Engine, "profile": s.Profile, "flow_id": s.FlowID, "probe_count": s.ProbeCount, "probed_ttl": s.ProbedTTL, "hop_coverage": s.coverage(), "reply_count": replies}
}
