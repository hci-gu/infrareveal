//go:build linux

package observer

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPacketOriginalLength(t *testing.T) {
	auxdata := make([]byte, unix.CmsgSpace(packetAuxdataBytes))
	// Cmsghdr is 16 bytes on 64-bit Linux, 12 on 32-bit Linux.
	if unix.CmsgLen(0) == 16 {
		binary.NativeEndian.PutUint64(auxdata[:8], uint64(unix.CmsgLen(packetAuxdataBytes)))
	} else {
		binary.NativeEndian.PutUint32(auxdata[:4], uint32(unix.CmsgLen(packetAuxdataBytes)))
	}
	header := unix.CmsgLen(0)
	binary.NativeEndian.PutUint32(auxdata[header-8:header-4], unix.SOL_PACKET)
	binary.NativeEndian.PutUint32(auxdata[header-4:header], unix.PACKET_AUXDATA)
	binary.NativeEndian.PutUint32(auxdata[header+4:header+8], 1514)
	binary.NativeEndian.PutUint32(auxdata[header+8:header+12], packetCaptureHeaderBytes)
	if length, err := packetOriginalLength(auxdata, packetCaptureHeaderBytes, 0); err != nil || length != 1514 {
		t.Fatalf("original length = %d, %v; want 1514", length, err)
	}
	for _, test := range []struct {
		name            string
		data            []byte
		received, flags int
	}{
		{"missing", nil, 256, 0},
		{"truncated", auxdata, 256, unix.MSG_CTRUNC},
		{"malformed", auxdata[:header+4], 256, 0},
		{"mismatched-snapshot", auxdata, 100, 0},
		{"invalid-original", auxdata, 1600, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := packetOriginalLength(test.data, test.received, test.flags); err == nil {
				t.Fatal("invalid auxiliary data must fail visibly")
			}
		})
	}
}

// Run inside an isolated Linux network namespace with CAP_NET_RAW. This covers
// the actual BPF -> socket receive -> parser boundary, including snap truncation.
func TestPacketCaptureCountsLargeHeaderOnlyFrames(t *testing.T) {
	if os.Getenv("INFRAREVEAL_PACKET_CAPTURE_TEST") != "1" {
		t.Skip("requires isolated Linux network namespace; set INFRAREVEAL_PACKET_CAPTURE_TEST=1")
	}
	loopback, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		frame []byte
		scope ObservationScope
	}{
		{"tcp-download", buildIPv4TCPFrame("93.184.216.34", "10.0.0.50", 443, 53000, make([]byte, 1460), 0x18, false), NewObservationScope("10.0.0.", "10.0.0.1")},
		{"udp-download", buildIPv4UDPFrame("93.184.216.34", "10.0.0.50", 443, 53000, make([]byte, 1400), false), NewObservationScope("10.0.0.", "10.0.0.1")},
		{"ipv6-download", buildIPv6UDPFrame("2606:4700:4700::1111", "fd00::50", 443, 53000, make([]byte, 1400)), NewObservationScope("fd00:", "fd00::1")},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ready, captured, failed := make(chan struct{}), make(chan PacketActivityEvent, 8), make(chan error, 1)
			go func() {
				failed <- runPacketCapture(ctx, "lo", test.scope, func() { close(ready) }, func(event PacketActivityEvent) {
					select {
					case captured <- event:
					default:
					}
				})
			}()
			select {
			case <-ready:
			case err := <-failed:
				t.Fatal(err)
			case <-time.After(3 * time.Second):
				t.Fatal("capture did not start")
			}
			fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)
			if err := unix.Sendto(fd, test.frame, 0, &unix.SockaddrLinklayer{Ifindex: loopback.Index, Protocol: htons(unix.ETH_P_ALL)}); err != nil {
				t.Fatal(err)
			}
			select {
			case event := <-captured:
				expected, ok := ParsePacketActivityFrame(test.frame, len(test.frame), event.ObservedAt, test.scope)
				if !ok || event != expected || event.PayloadBytes < 1400 || event.Direction != RemoteToClient {
					t.Fatalf("large packet metadata differs after header-only capture: got %#v, want %#v", event, expected)
				}
			case err := <-failed:
				t.Fatal(err)
			case <-time.After(time.Second):
				t.Fatal("large packet was silently discarded by header-only capture")
			}
		})
	}
}
