package routing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The fast executable streams individual hops. The coverage engine uses Paris
// probes and retries unanswered TTLs. Four-TTL segments bound time-to-publication
// and preserve completed segments if a background process is cancelled.
type discoveryProbe struct {
	fast    commandProbe
	quality coverageProbe
}

func (p discoveryProbe) Run(ctx context.Context, t target, plan probePlan, publish func(snapshot)) snapshot {
	if plan.Quality {
		return p.quality.Run(ctx, t, plan, publish)
	}
	return p.fast.Run(ctx, t, plan, publish)
}

type coverageProbe struct {
	deadline   time.Duration
	executable string
	run        func(context.Context, []string) ([]byte, error)
}

func (p coverageProbe) Run(parent context.Context, t target, plan probePlan, publish func(snapshot)) snapshot {
	budget := p.deadline
	if budget <= 0 {
		budget = 45 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	now := time.Now().UTC()
	attempt := hash(fmt.Sprintf("quality/%s/%d", t.binding(), now.UnixNano()))[:24]
	sourcePort := 40000 + int(crc32.ChecksumIEEE([]byte(attempt))%20000)
	method := plan.Method
	if method == "" {
		method = qualityMethods(t)[0]
	}
	label := method
	if method != "icmp-paris" {
		label += ":" + strconv.Itoa(t.Port)
	}
	s := snapshot{Attempt: attempt, Method: label, Engine: "scamper", Profile: "coverage", FlowID: fmt.Sprintf("%d/%s/%s/%d", sourcePort, t.IP, method, t.Port), Started: now, Measured: now, Status: "probing"}
	run := p.run
	if run == nil {
		run = p.execute
	}
	for from := 1; from <= 32; from += 4 {
		if from > 1 {
			// Starting a new process resets scamper's packet clock. Preserve
			// pacing at segment boundaries too, including very short paths.
			select {
			case <-time.After(200 * time.Millisecond):
			case <-ctx.Done():
			}
			if ctx.Err() != nil {
				break
			}
		}
		to := min(32, from+3)
		// Bookworm's scamper fails to match terminal TCP replies with parallel
		// TTL queries. Keep TCP serial; UDP/ICMP retain two outstanding TTLs.
		queries := 2
		if method == "tcp" {
			queries = 1
		}
		command := fmt.Sprintf("trace -T -P %s -d %d -s %d -q 3 -w 1 -W 20 -g 32 -N %d -f %d -m %d", method, t.Port, sourcePort, queries, from, to)
		data, err := run(ctx, []string{"-O", "json", "-O", "rawtcp", "-p", "5", "-c", command, "-i", t.IP})
		if err != nil {
			s.Error = err.Error()
			break
		}
		result, err := decodeScamperTrace(data, t, from, to)
		if err != nil {
			s.Error = err.Error()
			break
		}
		s.Hops = append(s.Hops, result.Hops...)
		s.ProbeCount += result.ProbeCount
		s.ProbedTTL = result.ProbedTTL
		s.Reached = result.Reached
		s.Measured = time.Now().UTC()
		s.Revision++
		publish(s)
		if s.Reached || result.Status == "unreachable" {
			s.Status = result.Status
			break
		}
	}
	s.Revision++
	s.Finished = time.Now().UTC()
	if ctx.Err() != nil {
		s.Error = ctx.Err().Error()
	}
	if parent.Err() != nil {
		s.Status = "cancelled"
	} else if s.Reached {
		s.Status = "reached"
	} else if s.Status != "unreachable" {
		s.Status = "partial"
		if s.replies() == 0 {
			s.Status = "unavailable"
			if s.Error != "" {
				s.Status = "failed"
			}
		}
	}
	if !s.Reached && s.ProbedTTL < 32 {
		s.Hops = append(s.Hops, Hop{TTL: s.ProbedTTL + 1, Missing: true, State: "not_probed", Timings: []float64{}})
	}
	return s
}
func (p coverageProbe) execute(ctx context.Context, args []string) ([]byte, error) {
	binary := p.executable
	if binary == "" {
		binary = "scamper"
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.WaitDelay = 250 * time.Millisecond
	var out, stderr outputBuffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	data, overflow := out.copy()
	if overflow {
		return nil, errors.New("scamper output limit exceeded")
	}
	if err != nil {
		message, _ := stderr.copy()
		return data, fmt.Errorf("scamper: %w: %s", err, strings.TrimSpace(string(message[:min(len(message), 700)])))
	}
	return data, nil
}

type scamperHop struct {
	Address  string  `json:"addr"`
	TTL      int     `json:"probe_ttl"`
	ProbeID  int     `json:"probe_id"`
	RTT      float64 `json:"rtt"`
	ICMPType *int    `json:"icmp_type"`
	ICMPCode *int    `json:"icmp_code"`
	TCPFlags *int    `json:"tcp_flags"`
	TX       struct {
		Sec  int64 `json:"sec"`
		Usec int64 `json:"usec"`
	} `json:"tx"`
}

func decodeScamperTrace(data []byte, t target, from, to int) (snapshot, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var row struct {
			Type       string       `json:"type"`
			IP         string       `json:"dst"`
			Method     string       `json:"method"`
			Stop       string       `json:"stop_reason"`
			First      int          `json:"firsthop"`
			Count      int          `json:"hop_count"`
			ProbeCount int          `json:"probe_count"`
			Hops       []scamperHop `json:"hops"`
		}
		if err := decoder.Decode(&row); err != nil {
			if err == io.EOF {
				return snapshot{}, errors.New("scamper produced no completed trace segment")
			}
			return snapshot{}, err
		}
		if row.Type != "trace" {
			continue
		}
		ip, err := netip.ParseAddr(row.IP)
		targetIP, _ := netip.ParseAddr(t.IP)
		if err != nil || ip != targetIP || row.First != from || row.Count < from || row.Count > to || row.ProbeCount < 0 || row.ProbeCount > (to-from+1)*3 {
			return snapshot{}, errors.New("scamper trace does not match the requested target or TTL range")
		}
		result := snapshot{ProbeCount: row.ProbeCount, ProbedTTL: row.Count, Status: "partial"}
		hops := map[int]*Hop{}
		for ttl := from; ttl <= row.Count; ttl++ {
			hops[ttl] = &Hop{TTL: ttl, Missing: true, State: "no_reply", Timings: []float64{}}
		}
		for _, reply := range row.Hops {
			address, err := netip.ParseAddr(reply.Address)
			h := hops[reply.TTL]
			if err != nil || h == nil || reply.RTT < 0 || math.IsNaN(reply.RTT) || math.IsInf(reply.RTT, 0) || len(h.Replies) >= 16 {
				return snapshot{}, errors.New("invalid scamper hop response")
			}
			seen := ""
			// The packaged engine can underflow TCP RTTs on very short local
			// paths (~2^32 microseconds). Retain the response and original value,
			// but never turn that artifact into a latency or a future timestamp.
			var rtt, reportedRTT *float64
			if reply.RTT <= 10_000 {
				rtt = &reply.RTT
				h.Timings = append(h.Timings, reply.RTT)
			} else {
				reportedRTT = &reply.RTT
			}
			if reply.TX.Sec > 0 && rtt != nil {
				seen = date(time.Unix(reply.TX.Sec, reply.TX.Usec*1000).Add(time.Duration(reply.RTT * float64(time.Millisecond))))
			}
			h.Replies = append(h.Replies, HopReply{Address: address.String(), RTT: rtt, ReportedRTT: reportedRTT, ProbeID: reply.ProbeID, ICMPType: reply.ICMPType, ICMPCode: reply.ICMPCode, TCPFlags: reply.TCPFlags, SeenAt: seen})
			h.Missing = false
			if h.Address == "" {
				h.Address = address.String()
				h.State = "reply"
			} else if h.Address != address.String() {
				h.State = "multipath"
			}
			terminal := reply.TCPFlags != nil && (*reply.TCPFlags&0x04 != 0 || *reply.TCPFlags&0x12 == 0x12)
			if reply.ICMPType != nil && reply.ICMPCode != nil {
				ty, code := *reply.ICMPType, *reply.ICMPCode
				terminal = terminal || (address.Is4() && (ty == 0 || (ty == 3 && code == 3))) || (address.Is6() && (ty == 129 || (ty == 1 && code == 4)))
				if (address.Is4() && ty == 3) || (address.Is6() && ty == 1) {
					h.Annotation = fmt.Sprintf("ICMP %d/%d", ty, code)
					if !terminal {
						h.State = "unreachable"
					}
				}
			}
			if address == targetIP && terminal && row.Stop == "COMPLETED" {
				result.Reached = true
				result.Status = "reached"
			}
		}
		ttls := make([]int, 0, len(hops))
		for ttl := range hops {
			ttls = append(ttls, ttl)
		}
		sort.Ints(ttls)
		for _, ttl := range ttls {
			result.Hops = append(result.Hops, *hops[ttl])
		}
		if row.Stop == "UNREACH" {
			result.Status = "unreachable"
		}
		return result, nil
	}
}
