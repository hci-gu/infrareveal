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
			// ICMPv6 errors without outer extension headers: match the quoted
			// destination, avoiding capture of unrelated neighbor/echo traffic.
			addr := target.As16()
			for i := 0; i < 4; i++ {
				filter += fmt.Sprintf(" and ip6[%d:4] = 0x%08x", 72+i*4, binary.BigEndian.Uint32(addr[i*4:i*4+4]))
			}
		}
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
		probe := exec.CommandContext(probeCtx, "traceroute", args...)
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
		row := map[string]any{"type": "comparison", "profile": profile.name, "started_at": date(began), "duration_ms": time.Since(began).Milliseconds(), "args": args, "hops": parseHops(data), "stdout": string(data), "error": errorText, "deadline_reached": timedOut, "icmp_headers": string(captureData), "capture_stats": string(captureStats), "capture_error": captureError, "capture_truncated": truncated}
		if err := encoder.Encode(row); err != nil {
			return err
		}
	}
	return nil
}
