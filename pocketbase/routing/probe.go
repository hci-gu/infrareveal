package routing

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type commandProbe struct {
	deadline   time.Duration
	executable string
}

var hopLine = regexp.MustCompile(`(?m)^\s*(\d+)\s+([^\n]*)`)
var timing = regexp.MustCompile(`([0-9]+(?:\.[0-9]+)?)\s*ms`)

// Accept only complete reply tokens; stdout can end halfway through a number.
// Reparse the bounded buffer so a hop printed without its trailing newline is
// visible immediately after its timing/timeout token is flushed.
func parseHops(output []byte) []Hop {
	var hops []Hop
	for _, m := range hopLine.FindAllSubmatch(output, -1) {
		ttl, _ := strconv.Atoi(string(m[1]))
		if ttl < 1 || ttl > 64 {
			continue
		}
		body := string(m[2])
		h := Hop{TTL: ttl, State: "pending", Timings: []float64{}}
		for _, token := range strings.Fields(body) {
			if ip, e := netip.ParseAddr(strings.Trim(token, "()")); e == nil {
				h.Address = ip.String()
				break
			}
		}
		for _, v := range timing.FindAllStringSubmatch(body, -1) {
			n, _ := strconv.ParseFloat(v[1], 64)
			h.Timings = append(h.Timings, n)
		}
		if len(h.Timings) > 0 && h.Address != "" {
			h.State = "reply"
		}
		if strings.Contains(body, "*") && h.Address == "" {
			h.State = "no_reply"
			h.Missing = true
		}
		for _, v := range strings.Fields(body) {
			if strings.HasPrefix(v, "!") {
				h.Annotation = v
				h.State = "unreachable"
			}
		}
		if h.State == "pending" {
			continue
		}
		hops = append(hops, h)
	}
	return hops
}

type outputBuffer struct {
	sync.Mutex
	b        bytes.Buffer
	overflow bool
}

func (b *outputBuffer) Write(p []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	n := len(p)
	if b.b.Len()+n > 128*1024 {
		b.overflow = true
		return n, nil
	}
	_, _ = b.b.Write(p)
	return n, nil
}
func (b *outputBuffer) copy() ([]byte, bool) {
	b.Lock()
	defer b.Unlock()
	return bytes.Clone(b.b.Bytes()), b.overflow
}

func (p commandProbe) Run(parent context.Context, t target, plan probePlan, publish func(snapshot)) snapshot {
	deadline := p.deadline
	outstanding, wait := "8", "0.5"

	ctx, cancel := context.WithTimeout(parent, deadline)
	defer cancel()
	started := time.Now().UTC()
	s := snapshot{Engine: "traceroute", Profile: "fast", Attempt: hash(fmt.Sprintf("%s/%d", t.binding(), started.UnixNano()))[:24], Method: t.method(), Started: started, Measured: started, Status: "probing"}
	args := []string{"-n", "-q", "1", "-m", "32", "-N", outstanding, "-w", wait, "-z", "0.04"}
	if t.Protocol == "tcp" {
		args = append(args, "-T", "-p", strconv.Itoa(t.Port))
	} else if t.Protocol == "udp" {
		args = append(args, "-U", "-p", strconv.Itoa(t.Port))
	} else {
		args = append(args, "-I")
		s.Method = "icmp"
	}
	args = append(args, t.IP)
	binary := p.executable
	if binary == "" {
		binary = "traceroute"
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.WaitDelay = 250 * time.Millisecond
	var out, stderr outputBuffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		s.Error = err.Error()
		s.Status = "failed"
		s.Finished = time.Now().UTC()
		return s
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	var previous string
	update := func() {
		data, _ := out.copy()
		hops := parseHops(data)
		fingerprint := fmt.Sprint(hops)
		if fingerprint == previous {
			return
		}
		previous = fingerprint
		s.Hops = hops
		s.Revision++
		s.Measured = time.Now().UTC()
		publish(s)
	}
	for {
		select {
		case <-ticker.C:
			update()
		case err := <-done:
			update()
			s.Finished = time.Now().UTC()
			s.Measured = s.Finished
			s.Revision++
			for _, h := range s.Hops {
				if h.Address == t.IP && (h.State == "reply" || h.Annotation == "!P") {
					s.Reached = true
				}
			}
			s.Status = "partial"
			if s.Reached {
				s.Status = "reached"
			}
			if err != nil {
				s.Error = err.Error()
				message, _ := stderr.copy()
				if len(message) > 0 {
					s.Error += ": " + strings.TrimSpace(string(message[:min(len(message), 700)]))
				}
				if s.replies() == 0 {
					s.Status = "failed"
				}
			}
			if ctx.Err() != nil {
				s.Error = ctx.Err().Error()
				if parent.Err() != nil {
					s.Status = "cancelled"
				}
			}
			_, overflow := out.copy()
			if overflow {
				s.Error = "traceroute output limit exceeded"
			}
			if s.replies() == 0 && s.Error == "" {
				s.Status = "unavailable"
			}
			// Missing printed TTLs after cancellation are not evidence of no reply.
			highest := 0
			for _, h := range s.Hops {
				highest = max(highest, h.TTL)
			}
			s.ProbedTTL = highest
			if !s.Reached && highest < 32 {
				s.Hops = append(s.Hops, Hop{TTL: highest + 1, Missing: true, State: "not_probed", Timings: []float64{}})
			}
			return s
		}
	}
}

var _ io.Writer = (*outputBuffer)(nil)
