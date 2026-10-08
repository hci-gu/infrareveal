package routing

import (
	"sort"
	"time"
)

type TargetStatus struct {
	IP       string `json:"destination_ip"`
	Protocol string `json:"protocol"`
	Port     int    `json:"destination_port"`
	State    string `json:"state"`
}
type Stats struct {
	// Legacy status keys remain zero for wire compatibility with older clients.
	CoverageRunning      int              `json:"coverage_running"`
	ReachedByteCoverage  float64          `json:"reached_byte_coverage"`
	LocatedByteCoverage  float64          `json:"located_byte_coverage"`
	HopCoverage          float64          `json:"hop_coverage"`
	RecentBytes          int64            `json:"recent_bytes"`
	MeasuredByteCoverage float64          `json:"measured_byte_coverage"`
	Pending              int              `json:"pending"`
	Running              int              `json:"running"`
	Starts               int              `json:"starts"`
	CacheHits            int              `json:"cache_hits"`
	Deferred             int              `json:"deferred"`
	Failures             int              `json:"failures"`
	OldestWaitMS         int64            `json:"oldest_wait_ms"`
	LastError            string           `json:"last_error"`
	Network              string           `json:"network_context"`
	Session              string           `json:"session"`
	UpdatedAt            string           `json:"updated_at"`
	Engine               string           `json:"engine"`
	UsefulPaths          int              `json:"useful_paths"`
	UniqueUseful         int              `json:"unique_useful_bindings"`
	NoGain               int              `json:"no_gain_attempts"`
	Suppressed           int              `json:"suppressed_attempts"`
	Duplicates           int              `json:"duplicate_publications_avoided"`
	EvidenceBytes        int              `json:"evidence_bytes_written"`
	Attempts             int              `json:"attempts"`
	RouteRows            int              `json:"route_rows_written"`
	UsefulPerAttempt     float64          `json:"useful_paths_per_attempt"`
	UsefulPerKiB         float64          `json:"useful_paths_per_kib"`
	AttemptsRemaining    int              `json:"budget_remaining"`
	ManualRemaining      int              `json:"manual_remaining"`
	Targets              []TargetStatus   `json:"targets"`
	Access               []accessEvidence `json:"access_context"`
}

func (stats Stats) withDemands(demands map[string]*demand, now time.Time, disabled bool) Stats {
	outcomes := stats.Targets
	stats.Targets = []TargetStatus{}
	var measured, reached, located int64
	for _, d := range demands {
		if disabled {
			d.state = "disabled"
		}
		weight := d.weight(now)
		stats.RecentBytes += weight
		if d.cache.Best.Attempt != "" && now.Before(d.cache.ValidUntil) {
			measured += weight
			if d.cache.Best.Reached {
				reached += weight
			}
			if d.cache.Best.located() > 0 {
				located += weight
			}
		}
		stats.Targets = append(stats.Targets, TargetStatus{d.binding.Target.IP, d.binding.Target.Protocol, d.binding.Target.Port, d.state})
		if d.state == "probing" {
			continue
		}
		if d.state == "negative_cache" || d.state == "visibility_paused" || d.state == "useful_path_saved" || d.state == "comparison_finished" {
			stats.Suppressed++
		}
	}
	seen := map[string]bool{}
	for _, v := range stats.Targets {
		seen[target{v.IP, v.Protocol, v.Port}.binding()] = true
	}
	for _, outcome := range outcomes {
		if !seen[target{outcome.IP, outcome.Protocol, outcome.Port}.binding()] {
			stats.Targets = append(stats.Targets, outcome)
		}
	}
	sort.Slice(stats.Targets, func(i, j int) bool { return stats.Targets[i].IP < stats.Targets[j].IP })
	den := float64(max(1, stats.RecentBytes))
	stats.MeasuredByteCoverage = float64(measured) / den
	stats.ReachedByteCoverage = float64(reached) / den
	stats.LocatedByteCoverage = float64(located) / den

	return stats
}
