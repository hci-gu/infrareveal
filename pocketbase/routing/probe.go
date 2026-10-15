package routing

import (
	"bytes"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

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

var _ io.Writer = (*outputBuffer)(nil)
