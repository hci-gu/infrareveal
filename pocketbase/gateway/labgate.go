package gateway

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"time"

	"myapp/debugtrace"
	"myapp/labgate"
)

func newLabGateRuntime(parent context.Context, config labgate.Config, trace debugtrace.Sink, apInterface, internetInterface, clientSubnetText string, audit labgate.AuditSink) (*labgate.Controller, error) {
	if err := labgate.ValidateConfig(config); err != nil {
		return nil, err
	}
	if !config.Enabled {
		return labgate.NewController(parent, config, nil, nil, trace, audit)
	}
	clientSubnet, err := netip.ParsePrefix(clientSubnetText)
	if err != nil || !clientSubnet.Addr().Is4() {
		return nil, fmt.Errorf("LAB_GATE_CLIENT_SUBNET must be an IPv4 prefix: %q", clientSubnetText)
	}
	rules, err := labgate.NewFirewallRules(labgate.FirewallConfig{
		APInterface: apInterface, InternetInterface: internetInterface,
		ClientSubnet: clientSubnet, QueueNumber: config.QueueNumber,
		StrictQueueNumber: config.StrictQueueNumber, DNSQueueNumber: config.DNSQueueNumber,
	}, nil)
	if err != nil {
		return nil, err
	}
	if err := rules.Prepare(parent); err != nil {
		log.Printf("lab gate firewall unavailable; continuing passive-only: %v", err)
		return labgate.NewController(parent, config, nil, nil, trace, audit)
	}
	queueLength := uint32(config.MaxHeldPackets + 256)
	queues := make(map[labgate.Mode]labgate.PacketQueue, 3)
	for mode, queueNumber := range map[labgate.Mode]uint16{
		labgate.ModeFlow: config.QueueNumber, labgate.ModeStrict: config.StrictQueueNumber, labgate.ModeDNS: config.DNSQueueNumber,
	} {
		queue, queueErr := labgate.NewNFQueue(labgate.NFQueueConfig{
			QueueNumber: queueNumber, MaxQueueLength: queueLength, ClientSubnet: clientSubnet, Mode: mode,
		})
		if queueErr != nil {
			for _, created := range queues {
				_ = created.Close()
			}
			_ = rules.Cleanup(context.Background())
			log.Printf("lab gate NFQUEUE unavailable; continuing passive-only: %v", queueErr)
			return labgate.NewController(parent, config, nil, nil, trace, audit)
		}
		queues[mode] = queue
	}
	queue, err := labgate.NewMultiplexQueue(queues)
	if err != nil {
		for _, created := range queues {
			_ = created.Close()
		}
		_ = rules.Cleanup(context.Background())
		return nil, err
	}
	controller, err := labgate.NewController(parent, config, queue, rules, trace, audit)
	if err != nil {
		_ = queue.Close()
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = rules.Cleanup(cleanupCtx)
	}
	return controller, err
}
