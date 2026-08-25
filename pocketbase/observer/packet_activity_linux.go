//go:build linux

package observer

import (
	"context"
	"errors"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

const packetCaptureHeaderBytes = 256

func runPacketCapture(
	ctx context.Context,
	interfaceName string,
	scope ObservationScope,
	onReady func(),
	emit func(PacketActivityEvent),
) error {
	networkInterface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return err
	}
	protocol := htons(unix.ETH_P_ALL)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(protocol))
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4*1024*1024); err != nil {
		return err
	}
	if err := attachPacketHeaderFilter(fd); err != nil {
		return err
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: protocol, Ifindex: networkInterface.Index}); err != nil {
		return err
	}

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = unix.Close(fd)
		case <-done:
		}
	}()
	defer close(done)
	onReady()

	buffer := make([]byte, packetCaptureHeaderBytes)
	for {
		n, _, err := unix.Recvfrom(fd, buffer, unix.MSG_TRUNC)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, unix.EBADF) {
				return ctx.Err()
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		capturedLength := n
		if capturedLength > len(buffer) {
			capturedLength = len(buffer)
		}
		if event, ok := ParsePacketActivityFrame(buffer[:capturedLength], n, time.Now().UTC(), scope); ok {
			emit(event)
		}
	}
}

func htons(value uint16) uint16 {
	return value<<8 | value>>8
}

func attachPacketHeaderFilter(fd int) error {
	filters := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_ABS, K: 12},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 6, K: etherTypeIPv4},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 5, K: etherTypeIPv6},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: etherTypeVLAN},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 4, K: etherTypeQinQ},
		{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_ABS, K: 16},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: etherTypeIPv4},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: etherTypeIPv6},
		{Code: unix.BPF_RET | unix.BPF_K, K: packetCaptureHeaderBytes},
		{Code: unix.BPF_RET | unix.BPF_K, K: 0},
	}
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{
		Len: uint16(len(filters)), Filter: &filters[0],
	})
}
