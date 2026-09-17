package routing

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"myapp/netmeta"
)

type repository struct {
	app        core.App
	geo        *geoip2.Reader
	geoVersion string
	locations  map[string]*Location
	config     Config
}

func (r repository) limits() Config {
	if r.config.MaxSnapshots == 0 {
		return ConfigFromEnv()
	}
	return r.config
}

func (r repository) activateNetwork(session, network string, now time.Time) error {
	if session == "" || network == "unknown" {
		return nil
	}
	return r.app.RunInTransaction(func(app core.App) error {
		value := struct {
			Network string `json:"network"`
		}{}
		record, err := loadState(app, "context:"+session, &value)
		if err != nil {
			return err
		}
		if value.Network == network {
			return nil
		}
		old := map[string]bool{}
		if value.Network != "" {
			old[value.Network] = true
		} else {
			var rows []struct {
				Network string `db:"network_context"`
			}
			if err := app.DB().NewQuery("SELECT DISTINCT network_context FROM routes WHERE session={:s} AND network_context != {:n}").Bind(dbx.Params{"s": session, "n": network}).All(&rows); err != nil {
				return err
			}
			for _, row := range rows {
				old[row.Network] = true
			}
		}
		for previous := range old {
			if err := (repository{app: app}).invalidateSession(session, previous, now); err != nil {
				return err
			}
		}
		value.Network = network
		record.Set("session", session)
		return saveState(app, record, value)
	})
}

// One epoch event invalidates all evidence from the old source context, including
// bindings no longer in the demand queue. It is never a fake empty route.
func (r repository) invalidateSession(session, network string, now time.Time) error {
	if session == "" {
		return nil
	}
	return r.app.RunInTransaction(func(app core.App) error {
		key := fmt.Sprintf("epoch:%s:%s:%d", session, network, now.UnixMilli())
		_, e := app.FindFirstRecordByFilter("route_evidence_updates", "key={:key}", dbx.Params{"key": key})
		if e == nil {
			return nil
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		c, e := app.FindCollectionByNameOrId("route_evidence_updates")
		if e != nil {
			return e
		}
		rec := core.NewRecord(c)
		rec.Set("key", key)
		rec.Set("session", session)
		rec.Set("network_context", network)
		rec.Set("kind", "network_invalidated")
		rec.Set("available_at", date(now))
		rec.Set("value", map[string]any{"network_context": network})
		return app.Save(rec)
	})
}
func (r repository) location(ip string) *Location {
	if !netmeta.PublicAddress(ip) || r.geo == nil {
		return nil
	}
	if v, ok := r.locations[ip]; ok {
		return v
	}
	if len(r.locations) >= 2048 {
		clear(r.locations)
	}
	if r.locations != nil {
		r.locations[ip] = nil
	}
	v, e := r.geo.City(net.ParseIP(ip))
	if e != nil || (v.Location.Latitude == 0 && v.Location.Longitude == 0) {
		return nil
	}
	loc := &Location{Lat: v.Location.Latitude, Lon: v.Location.Longitude, City: v.City.Names["en"], Country: v.Country.Names["en"], AccuracyKM: v.Location.AccuracyRadius, GeoVersion: r.geoVersion}
	if r.locations != nil {
		r.locations[ip] = loc
	}
	return loc
}
func (r repository) enrich(s snapshot, t target) snapshot {
	s.Hops = append([]Hop(nil), s.Hops...)
	for i := range s.Hops {
		h := &s.Hops[i]
		evidence := map[string]InterfaceEvidence{}
		for ip, v := range h.Evidence {
			evidence[ip] = v
		}
		for _, ip := range addresses(*h) {
			if loc := r.location(ip); loc != nil {
				v := evidence[ip]
				v.Geo = loc
				v.GeoAvailableAt = date(time.Now())
				v.GeoSource = "local GeoIP City database"
				if v.Confidence == "" {
					v.Confidence = "approximate"
				}
				evidence[ip] = v
			}
		}
		h.Evidence = evidence
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
	rec, e := r.app.FindFirstRecordByFilter("route_cache", "cache_key={:key}", dbx.Params{"key": key})
	if errors.Is(e, sql.ErrNoRows) {
		return cacheEntry{}, nil
	}
	if e != nil {
		return cacheEntry{}, e
	}
	var value cacheEntry
	b, e := json.Marshal(rec.Get("entry"))
	if e == nil {
		e = json.Unmarshal(b, &value)
	}
	return value, e
}
func saveCache(app core.App, key string, e cacheEntry, now time.Time) error {
	rec, err := app.FindFirstRecordByFilter("route_cache", "cache_key={:key}", dbx.Params{"key": key})
	if errors.Is(err, sql.ErrNoRows) {
		c, err := app.FindCollectionByNameOrId("route_cache")
		if err != nil {
			return err
		}
		rec = core.NewRecord(c)
		rec.Set("cache_key", key)
	} else if err != nil {
		return err
	}
	// No duplicate per-method copies or raw failed hop arrays in cache.
	e.Methods = nil
	e.Last = snapshot{}
	rec.Set("entry", e)
	rec.Set("last_used_at", date(now))
	return app.Save(rec)
}
func compactHops(hops []Hop) []Hop {
	out := []Hop{}
	for _, h := range hops {
		if len(addresses(h)) == 0 && len(out) > 0 {
			prev := &out[len(out)-1]
			end := prev.EndTTL
			if end == 0 {
				end = prev.TTL
			}
			if len(addresses(*prev)) == 0 && h.State == prev.State && h.TTL == end+1 {
				prev.EndTTL = h.TTL
				continue
			}
		}
		out = append(out, h)
	}
	return out
}

// publish is the single persistent path gate. Progress without a new useful
// path writes nothing; terminal failures get one mutable outcome, not a route.
func (r repository) publish(key, network, session string, t target, entry cacheEntry, s snapshot, state, provenance string, now time.Time) (cacheEntry, error) {
	if session == "" {
		return entry, nil
	}
	limits := r.limits()
	err := r.app.RunInTransaction(func(app core.App) error {
		active, e := app.FindRecordById("sessions", session)
		if e != nil {
			return e
		}
		if !active.GetBool("active") {
			return nil
		}
		sr, b, e := loadSessionBudget(app, session)
		if e != nil {
			return e
		}
		n := networkBudget{}
		nr, e := loadState(app, networkKey(network, t), &n)
		if e != nil {
			return e
		}
		shown := s
		if provenance == "cache" {
			shown = entry.Best
		}
		class := classifyRouteEvidence(shown, t, establishedAccess(n.Access))
		terminal := !s.Finished.IsZero()
		recordTerminal := terminal && provenance != "cache"
		if recordTerminal && s.Attempt != "" && b.Completed[s.Attempt] {
			return nil
		}
		if recordTerminal && s.Attempt != "" {
			// Engine admissions are finite. Reject unbounded direct publications too.
			if len(b.Completed) >= limits.MaxAttempts+b.ExtraAttempts+limits.ManualAttempts {
				return nil
			}
			b.Completed[s.Attempt] = true
		}
		saveBudgets := func() error {
			if e := saveState(app, nr, n); e != nil {
				return e
			}
			return saveState(app, sr, b)
		}
		if recordTerminal {
			// Idempotent terminal callbacks charge summaries/visibility only once.
			v := b.Targets[key]
			if v.Finished != s.Attempt {
				v.Finished = s.Attempt
				if class.Class == "useful_path" {
					n.NoGain = nil
					n.PausedUntil = time.Time{}
					n.Trial = ""
				} else {
					b.NoGain++
					if n.Trial == s.Attempt {
						n.PausedUntil = now.Add(limits.Cooldown)
						n.Trial = ""
					}
					if state == "failed" && capabilityFailure(s.Error) {
						n.CapabilityUntil = now.Add(5 * time.Minute)
					}
					if v.Attempts >= len(qualityMethods(t)) && !capabilityFailure(s.Error) {
						found := false
						for _, ip := range n.NoGain {
							if ip == t.IP {
								found = true
							}
						}
						if !found && len(n.NoGain) < 5 {
							n.NoGain = append(n.NoGain, t.IP)
						}
						if len(n.NoGain) >= 5 {
							n.PausedUntil = now.Add(limits.Cooldown)
						}
					}
					negKey := "negative:" + key + ":" + strings.Split(s.Method, ":")[0]
					value := struct {
						Until time.Time `json:"until"`
					}{now.Add(limits.Cooldown)}
					neg, e := loadState(app, negKey, &struct{}{})
					if e != nil {
						return e
					}
					neg.Set("available_at", date(now))
					if e = saveState(app, neg, value); e != nil {
						return e
					}
				}
				b.Targets[key] = v
				n.Access = learnAccess(n.Access, s, t)
				if e = recordOutcome(app, session, network, t, s, class, now, &b, limits); e != nil {
					return e
				}
			}
		}
		if class.Class != "useful_path" {
			if terminal {
				if e = saveState(app, nr, n); e != nil {
					return e
				}
				return saveState(app, sr, b)
			}
			return nil
		}
		if shown.Attempt == "" {
			return nil
		}
		fingerprint := pathFingerprint(shown, t, network)
		existing, e := app.FindFirstRecordByFilter("routes", "session={:s} && network_context={:n} && binding_key={:b} && fingerprint={:f} && schema_version=2", dbx.Params{"s": session, "n": network, "b": t.binding(), "f": fingerprint})
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		v := b.Targets[key]
		if e == nil {
			v.Useful = true
			b.Targets[key] = v
			if !terminal {
				return nil
			}
			// Confirmation extends knowledge through a small timestamped event; the
			// immutable original route and measurement age remain unchanged.
			b.Duplicates++
			if terminal && provenance != "cache" {
				shown = r.enrich(shown, t)
				evidence := map[string]any{}
				for _, h := range shown.Hops {
					if len(h.Evidence) > 0 {
						evidence[fmt.Sprint(h.TTL)] = h.Evidence
					}
				}
				if len(evidence) > 0 {
					if e = writeEvidenceUpdate(app, session, network, existing.Id, "enriched", shown.Attempt, evidence, now, &b, limits); e != nil {
						return e
					}
				}
			}

			if terminal && provenance != "cache" && shown.Measured.After(existing.GetDateTime("fresh_until").Time()) {
				if e = writeEvidenceUpdate(app, session, network, existing.Id, "confirmed", shown.Attempt, map[string]any{"measured_at": date(shown.Measured), "fresh_until": date(now.Add(limits.FreshTTL)), "valid_until": date(now.Add(limits.StaleTTL))}, now, &b, limits); e != nil {
					return e
				}
			}
			if terminal {
				if e = saveState(app, nr, n); e != nil {
					return e
				}
			}
			return saveState(app, sr, b)
		}
		var count struct {
			N int `db:"n"`
		}
		if e = app.DB().NewQuery("SELECT count(*) n FROM routes WHERE session={:s} AND attempt_id={:a} AND schema_version=2").Bind(dbx.Params{"s": session, "a": shown.Attempt}).One(&count); e != nil {
			return e
		}
		if count.N >= 2 || (!terminal && count.N >= 1) || b.Snapshots >= limits.MaxSnapshots {
			if recordTerminal {
				return saveBudgets()
			}
			return nil
		}
		shown = r.enrich(shown, t)
		// Path evidence has no queued/running lifecycle. Progress lives in memory.
		shown.Status = "partial"
		if shown.Reached {
			shown.Status = "reached"
		}
		shown.Hops = compactHops(shown.Hops)
		payload, e := json.Marshal(shown)
		if e != nil {
			return e
		}
		if len(payload) > 65536 {
			return fmt.Errorf("route evidence exceeds 64 KiB")
		}
		// Route projection, evidence bundle and cache copy plus metadata/references.
		cost := 3*len(payload) + 8192
		if b.Bytes+cost > limits.MaxBytes {
			if recordTerminal {
				return saveBudgets()
			}
			return nil
		}
		obsCollection, e := app.FindCollectionByNameOrId("route_observations")
		if e != nil {
			return e
		}
		obs, err := app.FindFirstRecordByFilter("route_observations", "attempt_id={:a} && revision={:r}", dbx.Params{"a": shown.Attempt, "r": shown.Revision})
		if errors.Is(err, sql.ErrNoRows) {
			obs = core.NewRecord(obsCollection)
			obs.Set("cache_key", key)
			obs.Set("attempt_id", shown.Attempt)
			obs.Set("revision", shown.Revision)
			obs.Set("snapshot", shown)
			obs.Set("measured_at", date(shown.Measured))
			if e = app.Save(obs); e != nil {
				return e
			}
		} else if err != nil {
			return err
		}
		shown.ObservationID = obs.Id
		c, e := app.FindCollectionByNameOrId("routes")
		if e != nil {
			return e
		}
		route := core.NewRecord(c)
		values := map[string]any{"schema_version": 2, "session": session, "network_context": network, "binding_key": t.binding(), "destination_ip": t.IP, "destination_port": t.Port, "protocol": t.Protocol, "fingerprint": fingerprint, "evidence_class": class.Class, "evidence_reason": class.Reason, "attempt_id": shown.Attempt, "revision": shown.Revision, "observation_id": obs.Id, "method": shown.Method, "status": shown.Status, "provenance": provenance, "hops": shown.Hops, "complete": shown.Reached, "destination_reached": shown.Reached, "responding_hops": shown.replies(), "located_hops": shown.located(), "destination_location": shown.Location, "probe_details": probeDetails(shown), "available_at": date(now), "started_at": date(shown.Started), "measured_at": date(shown.Measured), "completed_at": date(shown.Finished)}
		fresh, valid := shown.Measured.Add(limits.FreshTTL), shown.Measured.Add(limits.StaleTTL)
		values["fresh_until"] = date(fresh)
		values["valid_until"] = date(valid)
		// Millisecond storage must preserve publication ordering.
		var prev []*core.Record
		if e = app.RecordQuery("routes").AndWhere(dbx.HashExp{"session": session, "binding_key": t.binding()}).OrderBy("available_at DESC").Limit(1).All(&prev); e != nil {
			return e
		}
		if len(prev) > 0 && !now.Truncate(time.Millisecond).After(prev[0].GetDateTime("available_at").Time()) {
			values["available_at"] = date(prev[0].GetDateTime("available_at").Time().Add(time.Millisecond))
		}
		for k, v := range values {
			route.Set(k, v)
		}
		if e = app.Save(route); e != nil {
			return e
		}
		v.Useful = true
		b.Targets[key] = v
		b.Snapshots++
		b.Bytes += cost
		entry.Best = shown
		entry.FreshUntil = fresh
		entry.ValidUntil = valid
		entry.Last = snapshot{}
		if e = saveCache(app, key, entry, now); e != nil {
			return e
		}
		if e = saveState(app, nr, n); e != nil {
			return e
		}
		return saveState(app, sr, b)
	})
	return entry, err
}
func capabilityFailure(message string) bool {
	s := strings.ToLower(message)
	for _, v := range []string{"executable file not found", "permission denied", "operation not permitted", "unsupported", "invalid option", "network is unreachable"} {
		if strings.Contains(s, v) {
			return true
		}
	}
	return false
}
func recordOutcome(app core.App, session, network string, t target, s snapshot, class evidenceClass, now time.Time, b *sessionBudget, c Config) error {
	key := session + ":" + t.key(network)
	rec, e := app.FindFirstRecordByFilter("route_outcomes", "key={:k}", dbx.Params{"k": key})
	oldSize := 0
	if errors.Is(e, sql.ErrNoRows) {
		col, e := app.FindCollectionByNameOrId("route_outcomes")
		if e != nil {
			return e
		}
		rec = core.NewRecord(col)
		rec.Set("key", key)
	} else if e != nil {
		return e
	} else {
		data, _ := json.Marshal(rec.Get("value"))
		oldSize = len(data) + 512
	}
	value := outcome{t.IP, t.Protocol, t.Port, class.Class, class.Reason, s.Status, s.Method, s.Attempt, date(s.Measured), s.Reached, s.replies(), s.Error}
	if len(value.Error) > 700 {
		value.Error = value.Error[:700]
	}
	data, _ := json.Marshal(value)
	if len(data) > 4096 || b.Bytes+len(data)+512-oldSize > c.MaxBytes {
		return nil
	}
	b.Bytes += max(0, len(data)+512-oldSize)
	rec.Set("session", session)
	rec.Set("network_context", network)
	rec.Set("binding_key", t.binding())
	rec.Set("available_at", date(now))
	rec.Set("value", value)
	return app.Save(rec)
}
func writeEvidenceUpdate(app core.App, session, network, routeID, kind, identity string, value any, now time.Time, b *sessionBudget, c Config) error {
	key := hash(session + "|" + routeID + "|" + kind + "|" + identity)
	_, e := app.FindFirstRecordByFilter("route_evidence_updates", "key={:k}", dbx.Params{"k": key})
	if e == nil {
		return nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	data, _ := json.Marshal(value)
	if len(data) > 16384 || b.Updates >= c.MaxUpdates || b.Bytes+len(data)+512 > c.MaxBytes {
		return nil
	}
	col, e := app.FindCollectionByNameOrId("route_evidence_updates")
	if e != nil {
		return e
	}
	rec := core.NewRecord(col)
	rec.Set("key", key)
	rec.Set("session", session)
	rec.Set("network_context", network)
	rec.Set("binding_key", routeID)
	rec.Set("kind", kind)
	rec.Set("available_at", date(now))
	rec.Set("value", value)
	if e = app.Save(rec); e != nil {
		return e
	}
	b.Updates++
	b.Bytes += len(data) + 512
	return nil
}
func (r repository) prune(now time.Time) error {
	_, e := r.app.DB().NewQuery(`DELETE FROM route_cache WHERE id IN (SELECT id FROM route_cache ORDER BY last_used_at DESC LIMIT -1 OFFSET 1000) OR last_used_at < {:cut}`).Bind(dbx.Params{"cut": now.Add(-24 * time.Hour).UTC().Format("2006-01-02 15:04:05.000Z")}).Execute()
	if e != nil {
		return e
	}
	_, e = r.app.DB().NewQuery(`DELETE FROM route_budget_state WHERE (key LIKE 'negative:%' OR key LIKE 'network:%') AND julianday(available_at) < julianday({:cut})`).Bind(dbx.Params{"cut": date(now.Add(-24 * time.Hour))}).Execute()
	if e != nil {
		return e
	}
	_, e = r.app.DB().NewQuery(`DELETE FROM route_observations WHERE julianday(measured_at) < julianday({:cut}) AND NOT EXISTS (SELECT 1 FROM routes WHERE observation_id=route_observations.id)`).Bind(dbx.Params{"cut": date(now.Add(-24 * time.Hour))}).Execute()
	return e
}
func probeDetails(s snapshot) map[string]any {
	replies := 0
	for _, h := range s.Hops {
		replies += len(h.Replies)
	}
	return map[string]any{"engine": s.Engine, "engine_version": s.EngineVersion, "profile": s.Profile, "flow_id": s.FlowID, "source_ip": s.SourceIP, "probe_count": s.ProbeCount, "probed_ttl": s.ProbedTTL, "hop_coverage": s.coverage(), "reply_count": replies, "stop_reason": s.StopReason}
}
