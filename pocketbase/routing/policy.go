package routing

import (
	"encoding/json"
	"fmt"
	"myapp/netmeta"
	"net/netip"
	"sort"
)

type evidenceClass struct {
	Class  string `json:"class"`
	Reason string `json:"reason"`
}
type accessWitness struct {
	IP      string `json:"ip"`
	Attempt string `json:"attempt"`
	At      string `json:"at"`
}
type accessPosition struct {
	TTL       int      `json:"ttl"`
	Addresses []string `json:"addresses"`
}
type accessEvidence struct {
	Prefix    []accessPosition `json:"prefix"`
	Witnesses []accessWitness  `json:"witnesses"`
}

func addresses(h Hop) []string {
	set := map[string]bool{}
	for _, v := range append([]HopReply{{Address: h.Address}}, h.Replies...) {
		if ip, e := netip.ParseAddr(v.Address); e == nil {
			set[ip.Unmap().String()] = true
		}
	}
	a := make([]string, 0, len(set))
	for v := range set {
		a = append(a, v)
	}
	sort.Strings(a)
	return a
}

func classifyRouteEvidence(s snapshot, t target, access []accessPosition) evidenceClass {
	intermediate, publicBeyond := 0, false
	for _, h := range s.Hops {
		aa := addresses(h)
		for _, a := range aa {
			if a == t.IP {
				continue
			}
			intermediate++
			covered := false
			for _, p := range access {
				if p.TTL == h.TTL && fmt.Sprint(p.Addresses) == fmt.Sprint(aa) {
					covered = true
					break
				}
			}
			if netmeta.PublicAddress(a) && !covered {
				publicBeyond = true
			}
		}
	}
	if (s.Reached && intermediate > 0) || publicBeyond {
		return evidenceClass{"useful_path", "Responding intermediate interfaces describe a gateway route approximation"}
	}
	if intermediate > 0 {
		return evidenceClass{"access_only", "Only local or previously observed access interfaces responded; remote path unknown"}
	}
	if s.Reached {
		return evidenceClass{"endpoint_only", "Destination responded; intermediate route unknown"}
	}
	if s.Status == "probing" || s.Status == "cancelled" || s.Status == "failed" {
		return evidenceClass{"indeterminate", "Measurement unfinished or locally unavailable"}
	}
	return evidenceClass{"no_path", "Path not observable with these probes"}
}

// Only responding positions participate. Missing spans between those positions
// follow from their TTLs; growing a timeout-only tail does not change the path.
func pathFingerprint(s snapshot, t target, network string) string {
	rows := []accessPosition{}
	for _, h := range s.Hops {
		if a := addresses(h); len(a) > 0 {
			rows = append(rows, accessPosition{h.TTL, a})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].TTL < rows[j].TTL })
	value, _ := json.Marshal([]any{t.binding(), network, s.SourceIP, s.Method, s.Reached, rows, terminalEvidence(s)})
	return hash(string(value))
}
func terminalEvidence(s snapshot) string {
	if s.Reached {
		return "responded"
	}
	for _, h := range s.Hops {
		if h.State == "unreachable" {
			return fmt.Sprintf("%d/%s/%s", h.TTL, h.Address, h.Annotation)
		}
	}
	return "not_observed"
}

// Prefix consensus is local to one network, requires distinct target IPs and
// matching uninterrupted leading positions, and never supplies missing hops.
func learnAccess(old accessEvidence, s snapshot, t target) accessEvidence {
	if s.Finished.IsZero() {
		return old
	}
	prefix := []accessPosition{}
	for _, h := range s.Hops {
		a := addresses(h)
		if h.TTL != len(prefix)+1 || len(a) == 0 {
			break
		}
		destination := false
		for _, v := range a {
			if v == t.IP {
				destination = true
			}
		}
		if destination {
			break
		}
		prefix = append(prefix, accessPosition{h.TTL, a})
		if len(prefix) == 8 {
			break
		}
	}
	if len(prefix) == 0 {
		return old
	}
	for _, w := range old.Witnesses {
		if w.IP == t.IP {
			return old
		}
	}
	if len(old.Witnesses) == 0 {
		old.Prefix = prefix
	} else {
		n := 0
		for n < len(prefix) && n < len(old.Prefix) && fmt.Sprint(prefix[n]) == fmt.Sprint(old.Prefix[n]) {
			n++
		}
		old.Prefix = old.Prefix[:n]
	}
	if len(old.Witnesses) < 3 {
		old.Witnesses = append(old.Witnesses, accessWitness{t.IP, s.Attempt, date(s.Measured)})
	}
	return old
}
func establishedAccess(a accessEvidence) []accessPosition {
	if len(a.Witnesses) < 3 {
		return nil
	}
	return a.Prefix
}
