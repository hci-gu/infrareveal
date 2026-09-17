package routing

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

type bindingBudget struct {
	Attempts    int    `json:"attempts"`
	Useful      bool   `json:"useful"`
	Manual      bool   `json:"manual"`
	LastAttempt string `json:"last_attempt"`
	Finished    string `json:"finished"`
}
type sessionBudget struct {
	Targets       map[string]bindingBudget `json:"targets"`
	Attempts      int                      `json:"attempts"`
	Manual        int                      `json:"manual"`
	Snapshots     int                      `json:"snapshots"`
	Updates       int                      `json:"updates"`
	Bytes         int                      `json:"bytes"`
	Duplicates    int                      `json:"duplicates"`
	NoGain        int                      `json:"no_gain"`
	Completed     map[string]bool          `json:"completed"`
	ExtraTargets  int                      `json:"extra_targets"`
	ExtraAttempts int                      `json:"extra_attempts"`
}
type networkBudget struct {
	Starts          []time.Time    `json:"starts"`
	NoGain          []string       `json:"no_gain"`
	PausedUntil     time.Time      `json:"paused_until"`
	CapabilityUntil time.Time      `json:"capability_until"`
	Access          accessEvidence `json:"access"`
	LastStart       time.Time      `json:"last_start"`
	Trial           string         `json:"trial,omitempty"`
}
type outcome struct {
	IP         string `json:"destination_ip"`
	Protocol   string `json:"protocol"`
	Port       int    `json:"destination_port"`
	Class      string `json:"class"`
	Reason     string `json:"reason"`
	Status     string `json:"status"`
	Method     string `json:"method"`
	Attempt    string `json:"attempt"`
	At         string `json:"measured_at"`
	Reached    bool   `json:"destination_reached"`
	Responding int    `json:"responding_hops"`
	Error      string `json:"error,omitempty"`
}
type admission struct {
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
func networkKey(network string, t target) string { return "network:" + network + ":" + family(t) }
func loadState(app core.App, key string, dst any) (*core.Record, error) {
	r, e := app.FindFirstRecordByFilter("route_budget_state", "key={:key}", dbx.Params{"key": key})
	if errors.Is(e, sql.ErrNoRows) {
		c, e := app.FindCollectionByNameOrId("route_budget_state")
		if e != nil {
			return nil, e
		}
		r = core.NewRecord(c)
		r.Set("key", key)
		return r, nil
	}
	if e != nil {
		return nil, e
	}
	b, e := json.Marshal(r.Get("value"))
	if e == nil {
		e = json.Unmarshal(b, dst)
	}
	return r, e
}
func saveState(app core.App, r *core.Record, v any) error { r.Set("value", v); return app.Save(r) }
func loadSessionBudget(app core.App, session string) (*core.Record, sessionBudget, error) {
	b := sessionBudget{}
	r, e := loadState(app, "session:"+session, &b)
	if b.Targets == nil {
		b.Targets = map[string]bindingBudget{}
	}
	if b.Completed == nil {
		b.Completed = map[string]bool{}
	}
	if r != nil {
		r.Set("session", session)
	}
	return r, b, e
}
func (r repository) budgets(session, network string, t target) (sessionBudget, networkBudget, error) {
	_, b, e := loadSessionBudget(r.app, session)
	if e != nil {
		return b, networkBudget{}, e
	}
	n := networkBudget{}
	_, e = loadState(r.app, networkKey(network, t), &n)
	return b, n, e
}

// reserve charges before starting the process. Crashes and cancelled starts never
// refund probe allowances. The transaction is also the multi-caller admission lock.
func (r repository) reserve(session, network string, t target, c Config, manual bool, now time.Time) (admission, error) {
	if network == "unknown" || network == "" {
		return admission{Reason: "network_unavailable"}, nil
	}
	result := admission{}
	err := r.app.RunInTransaction(func(app core.App) error {
		sr, b, e := loadSessionBudget(app, session)
		if e != nil {
			return e
		}
		n := networkBudget{}
		nr, e := loadState(app, networkKey(network, t), &n)
		if e != nil {
			return e
		}
		reject := func(reason string) error { result.Reason = reason; return nil }
		active, e := app.FindRecordById("sessions", session)
		if e != nil || !active.GetBool("active") {
			return reject("session_closed")
		}
		if b.Snapshots+2 > c.MaxSnapshots || b.Bytes+512*1024 > c.MaxBytes {
			return reject("storage_budget")
		}
		if now.Before(n.CapabilityUntil) {
			return reject("engine_unavailable")
		}
		if !manual && now.Before(n.PausedUntil) {
			return reject("visibility_paused")
		}
		starts := []time.Time{}
		for _, at := range n.Starts {
			if at.After(now.Add(-time.Hour)) {
				starts = append(starts, at)
			}
		}
		n.Starts = starts
		if len(starts) >= c.HourlyAttempts {
			return reject("hourly_budget")
		}
		if now.Sub(n.LastStart) < 200*time.Millisecond {
			return reject("paced")
		}
		key := t.key(network)
		v, exists := b.Targets[key]
		if manual {
			if b.Manual >= c.ManualAttempts {
				return reject("manual_budget")
			}
		} else {
			if v.Useful {
				return reject("useful_path_saved")
			}
			if v.Attempts >= len(qualityMethods(t)) {
				return reject("comparison_finished")
			}
			if b.Attempts >= c.MaxAttempts+b.ExtraAttempts {
				return reject("session_budget")
			}
			count := 0
			for _, x := range b.Targets {
				if !x.Manual {
					count++
				}
			}
			if (!exists || v.Manual) && count >= c.MaxTargets+b.ExtraTargets {
				return reject("target_budget")
			}
		}
		methods := qualityMethods(t)
		method := methods[min(v.Attempts, len(methods)-1)]
		if manual {
			method = qualityMethods(t)[0]
		}
		// Negative state outlives session changes. The alternate gets its own key.
		negative := struct {
			Until time.Time `json:"until"`
		}{}
		_, e = loadState(app, "negative:"+key+":"+method, &negative)
		if e != nil {
			return e
		}
		if !manual && now.Before(negative.Until) {
			return reject("negative_cache")
		}
		attempt := hash(fmt.Sprintf("%s/%s/%d/%d", session, key, now.UnixNano(), b.Attempts+b.Manual))[:24]
		if manual {
			b.Manual++
		} else {
			b.Attempts++
			v.Attempts++
			v.Manual = false
		}
		if !exists {
			v.Manual = manual
		}
		v.LastAttempt = attempt
		b.Targets[key] = v
		n.Starts = append(n.Starts, now)
		n.LastStart = now
		nr.Set("available_at", date(now))
		// A trial after a visibility pause counts as the next failed round if it adds nothing.
		if !n.PausedUntil.IsZero() && !now.Before(n.PausedUntil) {
			n.PausedUntil = time.Time{}
			n.Trial = attempt
		}
		if e = saveState(app, sr, b); e != nil {
			return e
		}
		if e = saveState(app, nr, n); e != nil {
			return e
		}
		// One persistent scalar allocates synthetic probe identities across
		// sessions/restarts; no per-packet ledger or rapidly reused source tuple.
		identity := struct {
			Sequence uint32 `json:"sequence"`
		}{}
		ir, err := loadState(app, "engine_sequence", &identity)
		if err != nil {
			return err
		}
		identity.Sequence++
		if identity.Sequence == 0 {
			identity.Sequence = 1
		}
		if err := saveState(app, ir, identity); err != nil {
			return err
		}
		result = admission{Method: method, Attempt: attempt, Sequence: identity.Sequence, SourcePort: 40000 + int(identity.Sequence%20000)}
		return nil
	})
	return result, err
}

func (r repository) extend(session string) error {
	return r.app.RunInTransaction(func(app core.App) error {
		active, err := app.FindRecordById("sessions", session)
		if err != nil || !active.GetBool("active") {
			return fmt.Errorf("select an active session")
		}
		sr, b, e := loadSessionBudget(app, session)
		if e != nil {
			return e
		}
		if b.ExtraTargets >= 80 {
			return fmt.Errorf("maximum session extension reached")
		}
		b.ExtraTargets += 20
		b.ExtraAttempts += 40
		return saveState(app, sr, b)
	})
}
