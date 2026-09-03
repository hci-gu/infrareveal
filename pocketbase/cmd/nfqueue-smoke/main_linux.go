//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"myapp/labgate"
)

func main() {
	queueNumber := flag.Uint("queue", 42, "NFQUEUE number")
	subnetText := flag.String("client-subnet", "10.250.1.0/24", "client IPv4 subnet")
	mode := flag.String("mode", "accept", "accept, drop, or hold")
	hold := flag.Duration("hold", time.Second, "hold delay")
	queueLength := flag.Uint("queue-length", 256, "kernel queue length")
	flag.Parse()
	subnet, err := netip.ParsePrefix(*subnetText)
	if err != nil {
		fail(err)
	}
	packetQueue, err := labgate.NewNFQueue(labgate.NFQueueConfig{QueueNumber: uint16(*queueNumber), MaxQueueLength: uint32(*queueLength), ClientSubnet: subnet})
	if err != nil {
		fail(err)
	}
	readyQueue, ok := packetQueue.(labgate.ReadyPacketQueue)
	if !ok {
		fail(labgate.ErrUnsupported)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	errors := make(chan error, 1)
	go func() {
		errors <- packetQueue.Start(ctx, func(packet labgate.QueuedPacket) {
			verdict := labgate.VerdictAccept
			if *mode == "drop" {
				verdict = labgate.VerdictDrop
			}
			apply := func() { _ = packetQueue.SetVerdict(packet.ID, verdict) }
			if *mode == "hold" {
				time.AfterFunc(*hold, apply)
			} else {
				apply()
			}
		})
	}()
	select {
	case <-readyQueue.Ready():
		fmt.Println("READY")
	case err := <-errors:
		fail(err)
	case <-ctx.Done():
		return
	}
	select {
	case err := <-errors:
		if err != nil {
			fail(err)
		}
	case <-ctx.Done():
	}
	_ = packetQueue.Close()
}

func fail(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
