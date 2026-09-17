package routing

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Diagnose does no database or firewall writes. Returning ICMP is captured before
// INPUT filtering and compared with the same numeric traceroute output we parse.
// Only textual IP/ICMP header summaries are emitted; no pcap or packet payload.
func Diagnose(ctx context.Context, ip string, port int, iface string, budget time.Duration, maxTTL int, w io.Writer) error {
	target, err := netip.ParseAddr(ip)
	if err != nil || port < 1 || port > 65535 || budget < 5*time.Second || budget > 90*time.Second || maxTTL < 3 || maxTTL > 32 {
		return fmt.Errorf("provide a numeric target, valid port, 5–90 second deadline and 3–32 hops")
	}
	if _, err = net.InterfaceByName(iface); err != nil {
		return err
	}
	encoder := json.NewEncoder(w)
	command := func(args ...string) string {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		var out outputBuffer
		c := exec.CommandContext(cctx, args[0], args[1:]...)
		c.WaitDelay = 250 * time.Millisecond
		c.Stdout = &out
		c.Stderr = &out
		err := c.Run()
		data, _ := out.copy()
		if err != nil {
			return string(data) + "\n" + err.Error()
		}
		return string(data)
	}
	if err := encoder.Encode(map[string]any{"type": "context", "target": ip, "port": port, "interface": iface, "at": date(time.Now()), "route": command("ip", "-j", "route", "get", ip), "input_rules": command("iptables", "-nvL", "INPUT"), "output_rules": command("iptables", "-nvL", "OUTPUT"), "traceroute_version": command("traceroute", "--version"), "scamper_version": command("scamper", "-v")}); err != nil {
		return err
	}
	profiles := []struct {
		name string
		args []string
	}{
		{"legacy-tcp", []string{"-n", "-q", "1", "-w", "1", "-m", strconv.Itoa(maxTTL), "-T", "-p", strconv.Itoa(port)}},
		{"paced-tcp", []string{"-n", "-q", "3", "-w", "1", "-m", strconv.Itoa(maxTTL), "-N", "1", "-z", "0.2", "-T", "-p", strconv.Itoa(port)}},
		{"paced-icmp", []string{"-n", "-q", "3", "-w", "1", "-m", strconv.Itoa(maxTTL), "-N", "1", "-z", "0.2", "-I"}},
		{"paced-udp", []string{"-n", "-q", "3", "-w", "1", "-m", strconv.Itoa(maxTTL), "-N", "1", "-z", "0.2", "-U", "-p", strconv.Itoa(port)}},
	}
	for _, method := range []string{"tcp", "udp-paris", "icmp-paris"} {
		profiles = append(profiles, struct {
			name string
			args []string
		}{"scamper-" + method, []string{"-O", "json", "-O", "rawtcp", "-p", "5", "-c", fmt.Sprintf("trace -T -P %s -d %d -s 45000 -q 2 -w 1 -W 20 -g 32 -N 1 -f 1 -m %d", method, port, maxTTL), "-i"}})
	}
	for _, profile := range profiles {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := encoder.Encode(map[string]any{"type": "probe-start", "profile": profile.name, "at": date(time.Now())}); err != nil {
			return err
		}
		captureCtx, stopCapture := context.WithCancel(ctx)
		filter := "icmp6 and (ip6[40] = 1 or ip6[40] = 3)"
		if target.Is4() {
			addr := target.As4()
			filter = fmt.Sprintf("icmp and (icmp[0] = 11 or icmp[0] = 3) and icmp[24:4] = 0x%08x", binary.BigEndian.Uint32(addr[:]))
		} else {
			// Extension headers make fixed ICMPv6 offsets unsafe. These are
			// candidate headers for explicit diagnosis, not verified matches.
			filter = "ip6 protochain 58"
		}
		filter = fmt.Sprintf("(%s) or (host %s and (tcp port %d or udp port %d or icmp or icmp6))", filter, ip, port, port)

		capture := exec.CommandContext(captureCtx, "tcpdump", "--immediate-mode", "-i", iface, "-p", "-nn", "-l", "-v", "-s", "128", "-c", "256", filter)
		capture.WaitDelay = 250 * time.Millisecond
		var packets, stats outputBuffer
		capture.Stdout = &packets
		capture.Stderr = &stats
		captureErr := capture.Start()
		captureReady := false
		var captureDone chan error
		if captureErr == nil {
			captureDone = make(chan error, 1)
			go func() { captureDone <- capture.Wait() }()
			// Avoid losing the first reply before tcpdump has opened its capture socket.
			readyUntil := time.Now().Add(time.Second)
			for time.Now().Before(readyUntil) {
				data, _ := stats.copy()
				if strings.Contains(string(data), "listening on") {
					captureReady = true
					break
				}
				select {
				case captureErr = <-captureDone:
					captureDone = nil
				case <-time.After(20 * time.Millisecond):
				}
				if captureDone == nil {
					break
				}
			}
		}
		probeCtx, stopProbe := context.WithTimeout(ctx, budget)
		var stdout, stderr outputBuffer
		args := append(profile.args, ip)
		binary := "traceroute"
		if strings.HasPrefix(profile.name, "scamper-") {
			binary = "scamper"
		}
		probe := exec.CommandContext(probeCtx, binary, args...)
		probe.WaitDelay = 250 * time.Millisecond
		probe.Stdout = &stdout
		probe.Stderr = &stderr
		began := time.Now().UTC()
		probeErr := probe.Run()
		timedOut := probeCtx.Err() != nil
		stopProbe()
		if captureDone != nil {
			// A short trace can finish before the capture reader gets scheduled.
			// Drain received headers; libpcap's default block buffering otherwise
			// loses them at shutdown even though its receive counter increases.
			select {
			case <-time.After(100 * time.Millisecond):
			case <-ctx.Done():
			}
			_ = capture.Process.Signal(os.Interrupt)
			select {
			case captureErr = <-captureDone:
			case <-time.After(time.Second):
				stopCapture()
				captureErr = <-captureDone
			}
		}
		stopCapture()
		data, _ := stdout.copy()
		captureData, truncated := packets.copy()
		captureStats, _ := stats.copy()
		probeError, _ := stderr.copy()
		errorText := ""
		if probeErr != nil {
			errorText = probeErr.Error() + ": " + string(probeError)
		}
		captureError := ""
		if captureErr != nil {
			captureError = captureErr.Error()
		} else if !captureReady {
			captureError = "capture did not report readiness before probing"
		}
		hops := parseHops(data)
		decodeError := ""
		if binary == "scamper" {
			decoded, err := decodeScamperTrace(data, targetFromDiagnostic(ip, port), 1, maxTTL)
			if err != nil {
				decodeError = err.Error()
			} else {
				hops = decoded.Hops
			}
		}
		row := map[string]any{"type": "comparison", "profile": profile.name, "started_at": date(began), "duration_ms": time.Since(began).Milliseconds(), "args": args, "hops": hops, "decode_error": decodeError, "matching": "candidate packet headers; compare quoted probe tuple and engine probe IDs", "capture_headers": string(captureData), "stdout": string(data), "error": errorText, "deadline_reached": timedOut, "icmp_headers": string(captureData), "capture_stats": string(captureStats), "capture_error": captureError, "capture_truncated": truncated}
		row["reply_accounting"] = diagnosticReplyAccounting(string(captureData), hops)
		if err := encoder.Encode(row); err != nil {
			return err
		}
	}
	return nil
}

func targetFromDiagnostic(ip string, port int) target {
	return target{IP: ip, Protocol: "tcp", Port: port}
}

// This compares responder visibility, not individual packet identity. Quoted
// tuples, capture drops and late traffic must still be reviewed in the headers.
func diagnosticReplyAccounting(headers string, hops []Hop) map[string]any {
	captured, decoded := map[string]bool{}, map[string]bool{}
	for _, hop := range hops {
		for _, address := range addresses(hop) {
			decoded[address] = true
		}
	}
	for _, line := range strings.Split(headers, "\n") {
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "time exceeded") && !strings.Contains(lower, "unreachable") && !strings.Contains(lower, "echo reply") && !strings.Contains(line, "Flags [R") && !strings.Contains(line, "Flags [S.") {
			continue
		}
		pair := strings.SplitN(line, " > ", 2)
		if len(pair) != 2 {
			continue
		}
		fields := strings.Fields(pair[0])
		if len(fields) == 0 {
			continue
		}
		value := fields[len(fields)-1]
		ip, err := netip.ParseAddr(value)
		if err != nil {
			if i := strings.LastIndex(value, "."); i > 0 {
				ip, err = netip.ParseAddr(value[:i])
			}
		}
		if err == nil {
			captured[ip.Unmap().String()] = true
		}
	}
	candidates, missing := []string{}, []string{}
	for address := range captured {
		candidates = append(candidates, address)
		if !decoded[address] {
			missing = append(missing, address)
		}
	}
	sort.Strings(candidates)
	sort.Strings(missing)
	return map[string]any{"unit": "distinct candidate responder IPs, not packets", "captured_candidates": candidates, "captured_not_decoded": missing, "candidate_match_failures": len(missing), "decoded_responders": len(decoded)}
}
