package routing

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/pocketbase/dbx"
)

// The scheduler sees eligibility and a status projection, never the persisted
// spending representation. Admission still rechecks all limits transactionally.
type discoveryState struct {
	budget sessionBudget
	stats  Stats
}

type bindingProgress struct {
	Useful            bool
	ComparisonPending bool
	AutomaticAllowed  bool
	IdleState         string
}

func (s discoveryState) progress(binding routeBinding) bindingProgress {
	v := s.budget.Targets[binding.key()]
	p := bindingProgress{Useful: v.Useful, ComparisonPending: v.comparisonPending(binding.Target), AutomaticAllowed: v.Attempts < len(probeMethods(binding.Target)), IdleState: "low_activity"}
	if v.Useful {
		p.IdleState = "useful_path_saved"
	} else if !p.AutomaticAllowed {
		p.IdleState = "comparison_finished"
	}
	return p
}

func (r evidenceStore) readDiscovery(session, network string, now time.Time) (discoveryState, error) {
	s := discoveryState{}
	if session != "" {
		_, b, err := loadSessionBudgetAt(r.app, session, now)
		if err != nil {
			return s, err
		}
		s.budget = b
	}
	b, c := s.budget, r.limits()
	s.stats = Stats{Session: session, Network: network, Engine: c.Engine, UpdatedAt: date(now), UsefulPaths: b.Snapshots, NoGain: b.NoGain, Duplicates: b.Duplicates, EvidenceBytes: b.Bytes,
		AttemptsRemaining: max(0, c.MaxAttempts+b.ExtraAttempts-b.Attempts), ManualRemaining: max(0, c.ManualAttempts-b.Manual), Attempts: b.Attempts + b.Manual, RouteRows: b.Snapshots, Targets: []TargetStatus{}}
	for _, v := range b.Targets {
		if v.Useful {
			s.stats.UniqueUseful++
		}
	}
	s.stats.UsefulPerAttempt = float64(s.stats.UniqueUseful) / float64(max(1, s.stats.Attempts))
	s.stats.UsefulPerKiB = float64(s.stats.UniqueUseful) * 1024 / float64(max(1, b.Bytes))
	// Outcomes remain explainable after an idle binding leaves demand memory.
	if session != "" {
		outcomes, err := r.app.FindRecordsByFilter("route_outcomes", "session={:s}", "", 120, 0, dbx.Params{"s": session})
		if err == nil {
			for _, record := range outcomes {
				var v outcome
				data, _ := json.Marshal(record.Get("value"))
				if json.Unmarshal(data, &v) == nil {
					s.stats.Targets = append(s.stats.Targets, TargetStatus{v.IP, v.Protocol, v.Port, v.Class})
				}
			}
		}
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		var n networkBudget
		if _, err := loadState(r.app, "network:"+network+":"+family, &n); err == nil && len(n.Access.Witnesses) >= 3 {
			s.stats.Access = append(s.stats.Access, n.Access)
		}
	}
	return s, nil
}

func (r evidenceStore) observedBinding(session, network, flowID string) (routeBinding, error) {
	f, err := r.app.FindRecordById("flows", flowID)
	if err != nil || session == "" || f.GetString("session") != session {
		return routeBinding{}, fmt.Errorf("select an observed flow in the active session")
	}
	t := target{f.GetString("destination_ip"), f.GetString("protocol"), f.GetInt("destination_port")}
	ip, err := netip.ParseAddr(t.IP)
	if err != nil || (t.Protocol != "tcp" && t.Protocol != "udp") || t.Port < 1 || t.Port > 65535 {
		return routeBinding{}, fmt.Errorf("unsupported flow")
	}
	t.IP = ip.Unmap().String()
	return routeBinding{Session: session, Network: network, Target: t}, nil
}

func (r evidenceStore) reusable(binding routeBinding) (cacheEntry, error) {
	entry, err := r.load(binding.key())
	// Recheck old cache geometry against today's evidence gate.
	if err == nil && classifyRouteEvidence(entry.Best, binding.Target, nil).Class != "useful_path" {
		entry = cacheEntry{}
	}
	return entry, err
}

func (r evidenceStore) bindCached(binding routeBinding, entry cacheEntry, now time.Time) (cacheEntry, error) {
	return r.publish(publication{Binding: binding, Cache: entry, Snapshot: entry.Best, Provenance: "cache"}, now)
}
