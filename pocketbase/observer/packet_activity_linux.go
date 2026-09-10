//go:build linux

package observer

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

const packetCaptureHeaderBytes = 256
const packetAuxdataBytes = 20

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
	// BPF trims the skb before recvmsg: MSG_TRUNC only reports the snapped
	// length. AUXDATA preserves the original length without copying payload.
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_AUXDATA, 1); err != nil {
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
	control := make([]byte, unix.CmsgSpace(packetAuxdataBytes))
	for {
		n, controlLength, flags, _, err := unix.Recvmsg(fd, buffer, control, unix.MSG_TRUNC)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, unix.EBADF) {
				return ctx.Err()
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		wireLength, err := packetOriginalLength(control[:controlLength], n, flags)
		if err != nil {
			return err
		}
		capturedLength := n
		if capturedLength > len(buffer) {
			capturedLength = len(buffer)
		}
		if event, ok := ParsePacketActivityFrame(buffer[:capturedLength], wireLength, time.Now().UTC(), scope); ok {
			emit(event)
		}
	}
}

func packetOriginalLength(control []byte, received, flags int) (int, error) {
	if flags&unix.MSG_CTRUNC != 0 {
		return 0, errors.New("packet capture auxiliary data truncated")
	}
	messages, err := unix.ParseSocketControlMessage(control)
	if err != nil {
		return 0, fmt.Errorf("packet capture auxiliary data: %w", err)
	}
	for _, message := range messages {
		if message.Header.Level != unix.SOL_PACKET || message.Header.Type != unix.PACKET_AUXDATA {
			continue
		}
		if len(message.Data) < packetAuxdataBytes {
			return 0, errors.New("packet capture auxiliary data too short")
		}
		// Linux tpacket_auxdata starts with native-endian status, len, snaplen.
		original := int(binary.NativeEndian.Uint32(message.Data[4:8]))
		snapped := int(binary.NativeEndian.Uint32(message.Data[8:12]))
		if original < received || snapped != received || original < snapped || original <= 0 {
			return 0, errors.New("packet capture auxiliary lengths invalid")
		}
		return original, nil
	}
	return 0, errors.New("packet capture original length unavailable")
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
