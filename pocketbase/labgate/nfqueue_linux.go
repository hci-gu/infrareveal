//go:build linux

package labgate

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	nfqueue "github.com/florianl/go-nfqueue/v2"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const nfqueueCopyRange = 256

type linuxNFQueue struct {
	config      NFQueueConfig
	mu          sync.Mutex
	handle      *nfqueue.Nfqueue
	ready       chan struct{}
	readyOnce   sync.Once
	closeOnce   sync.Once
	parseBypass atomic.Uint64
}

func NewNFQueue(config NFQueueConfig) (PacketQueue, error) {
	if config.QueueNumber == 0 || !config.ClientSubnet.IsValid() || !config.ClientSubnet.Addr().Is4() {
		return nil, fmt.Errorf("invalid NFQUEUE configuration")
	}
	if config.Mode == "" {
		config.Mode = ModeFlow
	}
	if config.Mode != ModeFlow && config.Mode != ModeStrict && config.Mode != ModeDNS {
		return nil, fmt.Errorf("invalid NFQUEUE mode")
	}
	if config.MaxQueueLength < 16 {
		config.MaxQueueLength = 1024
	}
	return &linuxNFQueue{config: config, ready: make(chan struct{})}, nil
}

func (queue *linuxNFQueue) Ready() <-chan struct{} { return queue.ready }

func (queue *linuxNFQueue) Start(ctx context.Context, handler func(QueuedPacket)) error {
	handle, err := nfqueue.Open(&nfqueue.Config{
		NfQueue: queue.config.QueueNumber, MaxPacketLen: nfqueueCopyRange,
		MaxQueueLen: queue.config.MaxQueueLength, Copymode: nfqueue.NfQnlCopyPacket,
		Flags: nfqueue.NfQaCfgFlagFailOpen, AfFamily: unix.AF_INET, WriteTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		return fmt.Errorf("open NFQUEUE %d: %w", queue.config.QueueNumber, err)
	}
	queue.mu.Lock()
	queue.handle = handle
	queue.mu.Unlock()
	defer func() { _ = handle.Close() }()
	_ = handle.SetOption(netlink.NoENOBUFS, true)
	runtimeErrors := make(chan error, 1)
	err = handle.RegisterWithErrorFunc(ctx, func(attribute nfqueue.Attribute) int {
		if attribute.PacketID == nil {
			return 0
		}
		packetID := *attribute.PacketID
		if attribute.Payload == nil {
			queue.parseBypass.Add(1)
			_ = handle.SetVerdict(packetID, nfqueue.NfAccept)
			return 0
		}
		occurredAt := time.Now()
		if attribute.Timestamp != nil {
			occurredAt = *attribute.Timestamp
		}
		capturedLength := uint32(len(*attribute.Payload))
		if attribute.CapLen != nil {
			capturedLength = *attribute.CapLen
		}
		packet, parseErr := packetMetadataForMode(packetID, *attribute.Payload, capturedLength, occurredAt, queue.config.ClientSubnet, queue.config.Mode)
		if parseErr != nil {
			queue.parseBypass.Add(1)
			_ = handle.SetVerdict(packetID, nfqueue.NfAccept)
			return 0
		}
		handler(packet)
		return 0
	}, func(receiveErr error) int {
		select {
		case runtimeErrors <- receiveErr:
		default:
		}
		return 1
	})
	if err != nil {
		return fmt.Errorf("register NFQUEUE %d: %w", queue.config.QueueNumber, err)
	}
	queue.readyOnce.Do(func() { close(queue.ready) })
	select {
	case <-ctx.Done():
		return nil
	case receiveErr := <-runtimeErrors:
		return fmt.Errorf("receive NFQUEUE %d: %w", queue.config.QueueNumber, receiveErr)
	}
}

func (queue *linuxNFQueue) SetVerdict(packetID uint32, verdict Verdict) error {
	queue.mu.Lock()
	handle := queue.handle
	queue.mu.Unlock()
	if handle == nil {
		return ErrUnavailable
	}
	kernelVerdict := nfqueue.NfAccept
	if verdict == VerdictDrop {
		kernelVerdict = nfqueue.NfDrop
	}
	return handle.SetVerdict(packetID, kernelVerdict)
}

func (queue *linuxNFQueue) Stats() QueueStats {
	stats := readNFQueueStats(queue.config.QueueNumber)
	stats.ParseBypass = queue.parseBypass.Load()
	return stats
}

func (queue *linuxNFQueue) Close() error {
	var closeErr error
	queue.closeOnce.Do(func() {
		queue.mu.Lock()
		handle := queue.handle
		queue.mu.Unlock()
		if handle != nil {
			closeErr = handle.Close()
		}
	})
	return closeErr
}

func readNFQueueStats(queueNumber uint16) QueueStats {
	file, err := os.Open("/proc/net/netfilter/nfnetlink_queue")
	if err != nil {
		return QueueStats{}
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 7 || fields[0] != strconv.Itoa(int(queueNumber)) {
			continue
		}
		depth, _ := strconv.ParseUint(fields[2], 10, 64)
		kernelDrops, _ := strconv.ParseUint(fields[5], 10, 64)
		userDrops, _ := strconv.ParseUint(fields[6], 10, 64)
		return QueueStats{QueueDepth: depth, KernelDrops: kernelDrops, UserDrops: userDrops}
	}
	return QueueStats{}
}

var _ PacketQueue = (*linuxNFQueue)(nil)
