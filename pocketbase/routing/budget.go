package routing

import (
	"fmt"
	"hash/crc32"
	"myapp/data"
	"net/netip"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

// Keep the bounded network learning window independently of recordings. In
// particular, deleting a session never deletes its recent spending or pauses.
const networkHistory = 24 * time.Hour

type admission struct {
	Binding                 routeBinding
	Method, Attempt, Reason string
	Sequence                uint32
	SourcePort              int
}

func family(t target) string {
	ip, _ := netip.ParseAddr(t.IP)
	if ip.Is6() {
		return "ipv6"
	}
	return "ipv4"
}

func scopeFor(session *core.Record, now time.Time) string {
	if !session.GetBool("ephemeral") {
		return session.Id
	}
	start := int64(session.GetFloat("started_ms"))
	epoch := max(int64(0), (now.UnixMilli()-start)/time.Hour.Milliseconds())
	return fmt.Sprintf("%s:%d", session.Id, epoch)
}

type ledger struct {
	scope                                                          string
	runs                                                           []data.ProbeRun
	evidence                                                       []data.RouteEvidence
	access                                                         accessEvidence
	attempts, manual, targets, hourly, bytes                       int
	lastStart, pausedUntil, capabilityUntil, lastPause, lastUseful int64
	noGain                                                         map[string]bool
}

func readLedger(app core.App, b routeBinding, now time.Time) (ledger, error) {
	l := ledger{noGain: map[string]bool{}}
	session, err := app.FindRecordById("sessions", b.Session)
	if err != nil {
		return l, err
	}
	l.scope = scopeFor(session, now)
	records, err := app.FindRecordsByFilter("probe_runs", "(session={:s} && scope={:scope}) || (network_context={:n} && family={:f} && admitted_ms>={:cut})", "admitted_ms,id", 0, 0,
		dbx.Params{"s": b.Session, "scope": l.scope, "n": b.Network, "f": family(b.Target), "cut": now.Add(-networkHistory).UnixMilli()})
	if err != nil {
		return l, err
	}
	targets := map[string]bool{}
	for _, rec := range records {
		run, err := data.Decode[data.ProbeRun](rec)
		if err != nil {
			return l, err
		}
		l.runs = append(l.runs, run)
		if run.Session == b.Session && run.Scope == l.scope {
			if run.Manual {
				l.manual++
			} else {
				l.attempts++
				targets[run.NetworkContext+"|"+run.BindingKey] = true
			}
		}
		if run.NetworkContext != b.Network || run.Family != family(b.Target) || run.AdmittedMS < now.Add(-networkHistory).UnixMilli() {
			continue
		}
		l.lastStart = max(l.lastStart, run.AdmittedMS)
		if run.AdmittedMS > now.Add(-time.Hour).UnixMilli() {
			l.hourly++
		}
		if run.Useful {
			l.lastUseful = max(l.lastUseful, run.FinishedMS)
		}
		if run.Class == "engine_unavailable" {
			l.capabilityUntil = max(l.capabilityUntil, run.PauseUntilMS)
		}
		if len(run.AccessPrefix) > 0 {
			s := snapshot{Attempt: run.ID, Measured: time.UnixMilli(run.FinishedMS), Finished: time.UnixMilli(run.FinishedMS)}
			for _, p := range run.AccessPrefix {
				h := Hop{TTL: p.TTL}
				for _, ip := range p.Addresses {
					h.Replies = append(h.Replies, HopReply{Address: ip})
				}
				s.Hops = append(s.Hops, h)
			}
			l.access = learnAccess(l.access, s, target{run.DestinationIP, run.Protocol, run.DestinationPort})
		}
	}
	l.targets = len(targets)
	for _, run := range l.runs {
		if run.NetworkContext != b.Network || run.Family != family(b.Target) || run.AdmittedMS < now.Add(-networkHistory).UnixMilli() || run.FinishedMS <= l.lastUseful {
			continue
		}
		if run.Class != "engine_unavailable" {
			l.pausedUntil = max(l.pausedUntil, run.PauseUntilMS)
			l.lastPause = max(l.lastPause, run.PauseUntilMS)
		}
		if run.ComparisonComplete && !run.Useful {
			l.noGain[run.DestinationIP] = true
		}
	}
	records, err = app.FindRecordsByFilter("route_evidence", "session={:s}", "available_ms,id", 0, 0, dbx.Params{"s": b.Session})
	if err != nil {
		return l, err
	}
	for _, rec := range records {
		e, err := data.Decode[data.RouteEvidence](rec)
		if err != nil {
			return l, err
		}
		l.evidence = append(l.evidence, e)
		l.bytes += e.EvidenceBytes
	}
	return l, nil
}

func (l ledger) methods(b routeBinding) map[string]bool {
	methods := map[string]bool{}
	for _, run := range l.runs {
		if run.Session == b.Session && run.Scope == l.scope && run.NetworkContext == b.Network && run.BindingKey == b.Target.binding() && !run.Manual {
			methods[run.Method] = true
		}
	}
	return methods
}
func (l ledger) useful(b routeBinding, now time.Time) bool {
	return EvidenceAt(l.evidence, b.Epoch, b.Target.binding(), now.UnixMilli()) != nil
}
func (l ledger) automaticDone(b routeBinding) bool {
	for _, run := range l.runs {
		if run.Session == b.Session && run.Scope == l.scope && run.NetworkContext == b.Network && run.BindingKey == b.Target.binding() && run.Useful {
			return true
		}
	}
	return false
}
func (l ledger) hasTarget(b routeBinding) bool {
	for _, run := range l.runs {
		if run.Session == b.Session && run.Scope == l.scope && run.NetworkContext == b.Network && run.BindingKey == b.Target.binding() && !run.Manual {
			return true
		}
	}
	return false
}
func (l ledger) paths() int {
	n := 0
	for _, e := range l.evidence {
		if e.Kind == "path" {
			n++
		}
	}
	return n
}

// reserve is the cross-caller admission lock. The row is committed before the
// worker starts; all terminal states, including cancellation, stay charged.
func (r evidenceStore) reserve(b routeBinding, manual bool, now time.Time) (admission, error) {
	result := admission{Binding: b}
	if b.Network == "" || b.Network == "unknown" || b.Epoch == "" {
		result.Reason = "network_unavailable"
		return result, nil
	}
	err := r.app.RunInTransaction(func(app core.App) error {
		session, err := app.FindRecordById("sessions", b.Session)
		reject := func(reason string) error { result.Reason = reason; return nil }
		if err != nil {
			return err
		}
		if !session.GetBool("active") {
			return reject("session_closed")
		}
		if session.GetString("network_epoch") != b.Epoch || session.GetString("network_context") != b.Network {
			return reject("network_changed")
		}
		l, err := readLedger(app, b, now)
		if err != nil {
			return err
		}
		cfg := r.limits()
		if l.paths() >= cfg.MaxSnapshots || l.bytes >= cfg.MaxBytes {
			return reject("storage_budget")
		}
		if now.UnixMilli() < l.capabilityUntil {
			return reject("engine_unavailable")
		}
		if !manual && now.UnixMilli() < l.pausedUntil {
			return reject("visibility_paused")
		}
		if l.hourly >= cfg.HourlyAttempts {
			return reject("hourly_budget")
		}
		if now.UnixMilli()-l.lastStart < 200 {
			return reject("paced")
		}
		methods := probeMethods(b.Target)
		method := methods[0]
		if manual {
			if l.manual >= cfg.ManualAttempts {
				return reject("manual_budget")
			}
		} else {
			if l.useful(b, now) || l.automaticDone(b) {
				return reject("useful_path_saved")
			}
			tried := l.methods(b)
			method = ""
			for _, candidate := range methods {
				if !tried[candidate] {
					method = candidate
					break
				}
			}
			if method == "" {
				return reject("comparison_finished")
			}
			if l.attempts >= cfg.MaxAttempts {
				return reject("session_budget")
			}
			if !l.hasTarget(b) && l.targets >= cfg.MaxTargets {
				return reject("target_budget")
			}
			for _, run := range l.runs {
				if run.NetworkContext == b.Network && run.BindingKey == b.Target.binding() && run.Method == method && run.CooldownUntilMS > now.UnixMilli() {
					return reject("method_cooldown")
				}
			}
		}
		// Keep synthetic tuples distinct across restart and session deletion.
		// The 20,000-port range exceeds the bounded 24-hour network ledger.
		port := 40000
		for _, run := range l.runs {
			if run.NetworkContext == b.Network && run.Family == family(b.Target) && run.SourcePort >= 40000 && run.SourcePort < 60000 {
				port = 40000 + (run.SourcePort-40000+1)%20000
			}
		}
		run := data.ProbeRun{ID: data.NewID(), Session: b.Session, Scope: l.scope, NetworkContext: b.Network, NetworkEpoch: b.Epoch, Family: family(b.Target), BindingKey: b.Target.binding(), DestinationIP: b.Target.IP, Protocol: b.Target.Protocol, DestinationPort: b.Target.Port, SourcePort: port, Method: method, Manual: manual, AdmittedMS: now.UnixMilli(), Status: "admitted", AccessPrefix: []data.AccessPosition{}}
		if _, err = data.Write(app, "probe_runs", run); err != nil {
			return err
		}
		result.Attempt, result.Method = run.ID, method
		result.Sequence = crc32.ChecksumIEEE([]byte(run.ID))
		if result.Sequence == 0 {
			result.Sequence = 1
		}
		result.SourcePort = run.SourcePort
		return nil
	})
	return result, err
}
