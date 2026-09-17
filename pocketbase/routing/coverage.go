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
	if plan.SourcePort > 0 {
		sourcePort = plan.SourcePort
	}
	method := plan.Method
	if method == "" {
		method = qualityMethods(t)[0]
	}
	label := method
	if method != "icmp-paris" {
		label += ":" + strconv.Itoa(t.Port)
	}
	s := snapshot{Attempt: attempt, Method: label, Engine: "scamper", Profile: "selective", EngineVersion: "20211212-1.1", FlowID: fmt.Sprintf("%d/%s/%s/%d", sourcePort, t.IP, method, t.Port), Started: now, Measured: now, Status: "probing"}
	if family(t) == "ipv6" && method == "udp-paris" {
		s.Status = "failed"
		s.Error = "unsupported probe method: UDP Paris IPv6 is unqualified in Scamper 20211212-1.1; use ICMP Paris"
		s.Finished = now
		return s
	}
	run := p.run
	if run == nil {
		run = p.execute
	}
	// A single task retains its flow and reply matching state across all TTLs.
	command := fmt.Sprintf("trace -T -P %s -d %d -s %d -q 2 -w 1 -W 20 -g 32 -N 1 -f 1 -m 32", method, t.Port, sourcePort)
	command += fmt.Sprintf(" -U %d", plan.Sequence)
	data, runErr := run(ctx, []string{"-O", "json", "-O", "rawtcp", "-p", "5", "-c", command, "-i", t.IP})
	result, decodeErr := decodeScamperTrace(data, t, 1, 32, probeIdentity{plan.Sequence, sourcePort, method})
	if decodeErr == nil {
		s.Hops = result.Hops
		s.ProbeCount = result.ProbeCount
		s.ProbedTTL = result.ProbedTTL
		s.Reached = result.Reached
		s.Status = result.Status
		s.StopReason = result.StopReason
		s.SourceIP = result.SourceIP
		s.Measured = time.Now().UTC()
	} else {
		s.Error = decodeErr.Error()
	}
	if runErr != nil {
		s.Error = runErr.Error()
	}
	if len(s.Hops) > 0 {
		s.Revision++
		publish(s)
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
		state := "not_probed"
		if decodeErr != nil {
			state = "unknown"
		}
		s.Hops = append(s.Hops, Hop{TTL: s.ProbedTTL + 1, EndTTL: 32, Missing: true, State: state, Timings: []float64{}})
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
	Address        string          `json:"addr"`
	Extensions     json.RawMessage `json:"icmpext,omitempty"`
	ICMPExtensions json.RawMessage `json:"icmp_ext,omitempty"`
	TTL            int             `json:"probe_ttl"`
	ProbeID        int             `json:"probe_id"`
	RTT            float64         `json:"rtt"`
	ICMPType       *int            `json:"icmp_type"`
	ICMPCode       *int            `json:"icmp_code"`
	TCPFlags       *int            `json:"tcp_flags"`
	TX             struct {
		Sec  int64 `json:"sec"`
		Usec int64 `json:"usec"`
	} `json:"tx"`
}

type probeIdentity struct {
	Sequence   uint32
	SourcePort int
	Method     string
}

func decodeScamperTrace(data []byte, t target, from, to int, identities ...probeIdentity) (snapshot, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var row struct {
			Sequence        uint32       `json:"userid"`
			SourcePort      int          `json:"sport"`
			DestinationPort int          `json:"dport"`
			Type            string       `json:"type"`
			Source          string       `json:"src"`
			IP              string       `json:"dst"`
			Method          string       `json:"method"`
			Stop            string       `json:"stop_reason"`
			First           int          `json:"firsthop"`
			Count           int          `json:"hop_count"`
			ProbeCount      int          `json:"probe_count"`
			Hops            []scamperHop `json:"hops"`
		}
		if err := decoder.Decode(&row); err != nil {
			if err == io.EOF {
				return snapshot{}, errors.New("scamper produced no complete measurement record")
			}
			return snapshot{}, err
		}
		if row.Type != "trace" {
			continue
		}
		if len(identities) > 0 && identities[0].Sequence != 0 {
			i := identities[0]
			method := strings.ReplaceAll(row.Method, "icmp-echo-paris", "icmp-paris")
			if row.Sequence != i.Sequence || method != i.Method || (method != "icmp-paris" && (row.SourcePort != i.SourcePort || row.DestinationPort != t.Port)) || row.ProbeCount > 64 {
				return snapshot{}, errors.New("scamper result identity or probe budget mismatch")
			}
		}
		ip, err := netip.ParseAddr(row.IP)
		targetIP, _ := netip.ParseAddr(t.IP)
		if err != nil || ip != targetIP || row.First != from || row.Count < from || row.Count > to || row.ProbeCount < 0 || row.ProbeCount > (to-from+1)*3 {
			return snapshot{}, errors.New("scamper trace does not match the requested target or TTL range")
		}
		result := snapshot{ProbeCount: row.ProbeCount, ProbedTTL: row.Count, Status: "partial", StopReason: row.Stop, SourceIP: row.Source}
		hops := map[int]*Hop{}
		for ttl := from; ttl <= row.Count; ttl++ {
			hops[ttl] = &Hop{TTL: ttl, Missing: true, State: "no_reply", Timings: []float64{}}
		}
		for _, reply := range row.Hops {
			if len(reply.Extensions) == 0 {
				reply.Extensions = reply.ICMPExtensions
			}
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
			h.Replies = append(h.Replies, HopReply{Address: address.String(), RTT: rtt, ReportedRTT: reportedRTT, ProbeID: reply.ProbeID, ICMPType: reply.ICMPType, ICMPCode: reply.ICMPCode, TCPFlags: reply.TCPFlags, SeenAt: seen, Extensions: reply.Extensions})
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
