package routing

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"myapp/data"
	"myapp/netmeta"
	"net"
	"os"
	"strings"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

type evidenceStore struct {
	app        core.App
	geo        *geoip2.Reader
	geoVersion string
	locations  map[string]*Location
	config     Config
}

func newEvidenceStore(app core.App, geo *geoip2.Reader, config Config) evidenceStore {
	version := "unknown"
	if f, err := os.Stat("./geoip/city.mmdb"); err == nil {
		version = fmt.Sprintf("%d/%d", f.Size(), f.ModTime().Unix())
	}
	return evidenceStore{app: app, geo: geo, geoVersion: version, locations: map[string]*Location{}, config: config}
}
func (r evidenceStore) limits() Config {
	if r.config.MaxSnapshots == 0 {
		return defaultConfig()
	}
	return r.config
}

// activateNetwork publishes the old epoch's invalidation and new current epoch
// atomically. A restart with unchanged routing inputs keeps the committed epoch.
func (r evidenceStore) activateNetwork(session, network string, now time.Time) (string, error) {
	if session == "" || network == "" || network == "unknown" {
		return "", nil
	}
	epoch := ""
	err := r.app.RunInTransaction(func(app core.App) error {
		rec, err := app.FindRecordById("sessions", session)
		if err != nil {
			return err
		}
		if !rec.GetBool("active") {
			return nil
		}
		old := rec.GetString("network_epoch")
		if old != "" && rec.GetString("network_context") == network {
			epoch = old
			return nil
		}
		if old != "" {
			count, err := app.CountRecords("route_evidence", dbx.NewExp("session={:s} AND network_epoch={:e} AND kind='path'", dbx.Params{"s": session, "e": old}))
			if err != nil {
				return err
			}
			if count > 0 {
				value := data.RouteEvidence{ID: data.ID("invalidate", session, old), Session: session, Kind: "network_invalidated", NetworkContext: rec.GetString("network_context"), NetworkEpoch: old, AvailableMS: now.UnixMilli(), Hops: []data.Hop{}, EvidenceBytes: 512}
				// Equal-millisecond enrichment may have advanced availability by one.
				// An invalidation must dominate every publication in the old epoch.
				var edge struct {
					Available int64 `db:"available"`
				}
				if err = app.DB().NewQuery("SELECT max(available_ms) available FROM route_evidence WHERE session={:s} AND network_epoch={:e}").Bind(dbx.Params{"s": session, "e": old}).One(&edge); err != nil {
					return err
				}
				value.AvailableMS = max(value.AvailableMS, edge.Available+1)
				if _, err = data.Write(app, "route_evidence", value); err != nil {
					return err
				}
			}
		}
		epoch = data.NewID()
		_, err = app.DB().NewQuery("UPDATE sessions SET network_context={:n},network_epoch={:e},revision=revision+1 WHERE id={:s}").Bind(dbx.Params{"n": network, "e": epoch, "s": session}).Execute()
		return err
	})
	return epoch, err
}

// recoverAdmissions seals interrupted physical attempts without refunding them.
func (r evidenceStore) recoverAdmissions(now time.Time) error {
	return r.app.RunInTransaction(func(app core.App) error {
		_, err := app.DB().NewQuery("UPDATE probe_runs SET status='interrupted',class='indeterminate',reason='observer restarted',finished_ms={:now},cooldown_until_ms={:until} WHERE status='admitted'").Bind(dbx.Params{"now": now.UnixMilli(), "until": now.Add(r.limits().Cooldown).UnixMilli()}).Execute()
		return err
	})
}

// finish seals one admitted attempt. Only completed useful geometry can enter
// the product stream. Progress and outcomes never masquerade as route paths.
func (r evidenceStore) finish(a admission, s snapshot, now time.Time, publish bool) error {
	if s.Finished.IsZero() {
		return nil
	}
	return r.app.RunInTransaction(func(app core.App) error {
		record, err := app.FindRecordById("probe_runs", a.Attempt)
		if err != nil {
			return err
		}
		run, err := data.Decode[data.ProbeRun](record)
		if err != nil {
			return err
		}
		if run.Status != "admitted" {
			return nil
		}
		if run.Session != a.Binding.Session || run.NetworkContext != a.Binding.Network || run.NetworkEpoch != a.Binding.Epoch || run.BindingKey != a.Binding.Target.binding() || run.Method != a.Method {
			return fmt.Errorf("probe admission does not match result")
		}
		run.FinishedMS = now.UnixMilli()
		run.Status = s.Status
		if run.Status == "" || run.Status == "probing" {
			run.Status = "interrupted"
		}
		run.Error = s.Error
		if len(run.Error) > 700 {
			run.Error = run.Error[:700]
		}
		active, err := app.FindRecordById("sessions", run.Session)
		if errors.Is(err, sql.ErrNoRows) {
			run.Status = "interrupted"
			run.Class = "indeterminate"
			run.Reason = "session deleted"
			_, err = data.Write(app, "probe_runs", run)
			return err
		}
		if err != nil {
			return err
		}
		l, err := readLedger(app, a.Binding, now)
		if err != nil {
			return err
		}
		class := classifyRouteEvidence(s, a.Binding.Target, establishedAccess(l.access))
		run.Class, run.Reason = class.Class, class.Reason
		run.Useful = class.Class == "useful_path" && run.Status != "cancelled" && run.Status != "interrupted"
		run.AccessPrefix = learnAccess(accessEvidence{}, s, a.Binding.Target).Prefix
		if run.AccessPrefix == nil {
			run.AccessPrefix = []data.AccessPosition{}
		}
		finishedMethods := map[string]bool{a.Method: true}
		for _, other := range l.runs {
			if other.Session == run.Session && other.Scope == run.Scope && other.NetworkContext == run.NetworkContext && other.BindingKey == run.BindingKey && !other.Manual && other.Status != "admitted" {
				finishedMethods[other.Method] = true
			}
		}
		run.ComparisonComplete = !run.Manual && run.Status != "cancelled" && run.Status != "interrupted" && len(finishedMethods) >= len(probeMethods(a.Binding.Target))
		if !run.Useful {
			run.CooldownUntilMS = now.Add(r.limits().Cooldown).UnixMilli()
			if capabilityFailure(s.Error) {
				run.Class = "engine_unavailable"
				run.PauseUntilMS = now.Add(5 * time.Minute).UnixMilli()
				run.ComparisonComplete = false
			} else {
				if run.ComparisonComplete {
					l.noGain[run.DestinationIP] = true
				}
				if len(l.noGain) >= 5 || (l.lastPause > 0 && run.AdmittedMS >= l.lastPause) {
					run.PauseUntilMS = now.Add(r.limits().Cooldown).UnixMilli()
				}
			}
		}
		if r.limits().Diagnostics {
			details := &data.ProbeDetails{Engine: s.Engine, EngineVersion: s.EngineVersion, SourceIP: s.SourceIP, ProbeCount: s.ProbeCount, ProbedTTL: s.ProbedTTL, StopReason: s.StopReason, Hops: s.Hops}
			encoded, _ := json.Marshal(details)
			if len(encoded) > 16384 {
				details.Hops = nil
				encoded, _ = json.Marshal(details)
			}
			if len(encoded) <= 16384 {
				run.Details = details
			}
		}
		if publish && run.Useful && active.GetBool("active") && active.GetString("network_epoch") == run.NetworkEpoch {
			shown := r.enrich(s, a.Binding.Target)
			shown.Hops = compactHops(shown.Hops)
			evidence := data.RouteEvidence{ID: data.ID(run.ID, "1"), Session: run.Session, Kind: "path", NetworkContext: run.NetworkContext, NetworkEpoch: run.NetworkEpoch, BindingKey: run.BindingKey, DestinationIP: run.DestinationIP, Protocol: run.Protocol, DestinationPort: run.DestinationPort, AttemptID: run.ID, Revision: 1, Method: s.Method, Status: s.Status, Reason: class.Reason, Fingerprint: pathFingerprint(s, a.Binding.Target, run.NetworkContext), MeasuredMS: s.Measured.UnixMilli(), AvailableMS: now.UnixMilli(), FreshUntilMS: s.Measured.Add(r.limits().FreshTTL).UnixMilli(), ValidUntilMS: s.Measured.Add(r.limits().StaleTTL).UnixMilli(), DestinationReached: s.Reached, Hops: shown.Hops, DestinationLocation: shown.Location}
			if s.Measured.IsZero() {
				evidence.MeasuredMS = run.AdmittedMS
				evidence.FreshUntilMS = run.AdmittedMS + r.limits().FreshTTL.Milliseconds()
				evidence.ValidUntilMS = run.AdmittedMS + r.limits().StaleTTL.Milliseconds()
			}
			encoded, err := json.Marshal(evidence)
			if err != nil {
				return err
			}
			evidence.EvidenceBytes = len(encoded) + 512
			if len(encoded) <= 65536 && l.paths() < r.limits().MaxSnapshots && l.bytes+evidence.EvidenceBytes <= r.limits().MaxBytes {
				if _, err = data.Write(app, "route_evidence", evidence); err != nil {
					return err
				}
				if err = data.BumpRevision(app, run.Session); err != nil {
					return err
				}
			} else {
				run.Useful = false
				run.Class = "storage_limited"
				run.Reason = "bounded evidence storage exhausted"
			}
		}
		_, err = data.Write(app, "probe_runs", run)
		return err
	})
}

// enrichPublication permits one full replacement revision with the original
// measurement/expiry. It cannot confirm freshness, mutate geometry, or resurrect
// evidence after an epoch change, clear, retention, or session closure.
func (r evidenceStore) enrichPublication(a admission, s snapshot, now time.Time) error {
	return r.app.RunInTransaction(func(app core.App) error {
		rec, err := app.FindRecordById("route_evidence", data.ID(a.Attempt, "1"))
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		original, err := data.Decode[data.RouteEvidence](rec)
		if err != nil {
			return err
		}
		newer, err := app.CountRecords("route_evidence", dbx.NewExp("session={:s} AND network_epoch={:e} AND binding_key={:b} AND kind='path' AND attempt_id!={:a} AND available_ms>={:at}", dbx.Params{"s": original.Session, "e": original.NetworkEpoch, "b": original.BindingKey, "a": original.AttemptID, "at": original.AvailableMS}))
		if err != nil {
			return err
		}
		if newer > 0 {
			return nil
		}
		session, err := app.FindRecordById("sessions", original.Session)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if !session.GetBool("active") || session.GetString("network_epoch") != original.NetworkEpoch || now.UnixMilli() >= original.ValidUntilMS {
			return nil
		}
		if _, err = app.FindRecordById("route_evidence", data.ID(a.Attempt, "2")); err == nil {
			return nil
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if pathFingerprint(s, a.Binding.Target, a.Binding.Network) != original.Fingerprint {
			return nil
		}
		shown := r.enrich(s, a.Binding.Target)
		shown.Hops = compactHops(shown.Hops)
		before := comparableHops(original.Hops)
		after := comparableHops(shown.Hops)
		if string(before) == string(after) {
			return nil
		}
		original.ID = data.ID(a.Attempt, "2")
		original.Revision = 2
		original.AvailableMS = max(now.UnixMilli(), original.AvailableMS+1)
		original.Hops = shown.Hops
		original.DestinationLocation = shown.Location
		encoded, err := json.Marshal(original)
		if err != nil {
			return err
		}
		original.EvidenceBytes = len(encoded) + 512
		l, err := readLedger(app, a.Binding, now)
		if err != nil {
			return err
		}
		if len(encoded) > 65536 || l.paths() >= r.limits().MaxSnapshots || l.bytes+original.EvidenceBytes > r.limits().MaxBytes {
			return nil
		}
		if _, err = data.Write(app, "route_evidence", original); err != nil {
			return err
		}
		return data.BumpRevision(app, original.Session)
	})
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

func (r evidenceStore) location(ip string) *Location {
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
func (r evidenceStore) enrich(s snapshot, t target) snapshot {
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
				v.GeoAvailableMS = time.Now().UnixMilli()
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

// Availability timestamps alone are not an enrichment.
func comparableHops(hops []Hop) []byte {
	copyHops := append([]Hop(nil), hops...)
	for i := range copyHops {
		copyHops[i].Evidence = map[string]InterfaceEvidence{}
		for ip, v := range hops[i].Evidence {
			v.AvailableMS = 0
			v.GeoAvailableMS = 0
			copyHops[i].Evidence[ip] = v
		}
	}
	encoded, _ := json.Marshal(copyHops)
	return encoded
}
