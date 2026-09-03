package labgate

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"myapp/netmeta"
)

const (
	labChain     = "INFRAREVEAL_LAB"
	labDNSChain  = "INFRAREVEAL_LAB_DNS"
	labClientSet = "infrareveal_lab_clients"
)

type CommandRunner interface {
	Run(context.Context, string, ...string) error
}
type ExecCommandRunner struct{}

func (ExecCommandRunner) Run(ctx context.Context, name string, arguments ...string) error {
	return exec.CommandContext(ctx, name, arguments...).Run()
}

type RuleManager interface {
	Prepare(context.Context) error
	SetClients(context.Context, []netip.Addr) error
	ClearClients(context.Context) error
	Cleanup(context.Context) error
	Ready() bool
}
type RuleSelection struct {
	Mode    Mode
	Clients []netip.Addr
	Strict  *netmeta.FlowTuple
}
type ModeRuleManager interface {
	RuleManager
	Activate(context.Context, RuleSelection) error
}

type FirewallConfig struct {
	APInterface, InternetInterface                 string
	ClientSubnet                                   netip.Prefix
	QueueNumber, StrictQueueNumber, DNSQueueNumber uint16
}

type FirewallRules struct {
	config FirewallConfig
	runner CommandRunner
	mu     sync.RWMutex
	ready  bool
}

func NewFirewallRules(config FirewallConfig, runner CommandRunner) (*FirewallRules, error) {
	if config.StrictQueueNumber == 0 {
		config.StrictQueueNumber = 43
	}
	if config.DNSQueueNumber == 0 {
		config.DNSQueueNumber = 44
	}
	if config.APInterface == "" || config.InternetInterface == "" || config.QueueNumber == 0 ||
		config.QueueNumber == config.StrictQueueNumber || config.QueueNumber == config.DNSQueueNumber || config.StrictQueueNumber == config.DNSQueueNumber ||
		!config.ClientSubnet.IsValid() || !config.ClientSubnet.Addr().Is4() {
		return nil, errors.New("invalid lab firewall configuration")
	}
	if runner == nil {
		runner = ExecCommandRunner{}
	}
	return &FirewallRules{config: config, runner: runner}, nil
}

func (rules *FirewallRules) Prepare(ctx context.Context) error {
	rules.setReady(false)
	_ = rules.runner.Run(ctx, "ipset", "create", labClientSet, "hash:ip", "family", "inet", "-exist")
	if err := rules.runner.Run(ctx, "ipset", "flush", labClientSet); err != nil {
		return fmt.Errorf("flush lab client set: %w", err)
	}
	for _, chain := range []string{labChain, labDNSChain} {
		_ = rules.runner.Run(ctx, "iptables", "-w", "-N", chain)
		if err := rules.resetChain(ctx, chain); err != nil {
			return rules.prepareFailure(ctx, err)
		}
	}
	rules.deleteJump(ctx, "FORWARD", labChain)
	rules.deleteJump(ctx, "INPUT", labDNSChain)
	if err := rules.runner.Run(ctx, "iptables", "-w", "-I", "FORWARD", "1", "-j", labChain); err != nil {
		return rules.prepareFailure(ctx, err)
	}
	if err := rules.runner.Run(ctx, "iptables", "-w", "-I", "INPUT", "1", "-j", labDNSChain); err != nil {
		return rules.prepareFailure(ctx, err)
	}
	rules.setReady(true)
	return nil
}

func (rules *FirewallRules) Activate(ctx context.Context, selection RuleSelection) error {
	if !rules.Ready() {
		return ErrUnavailable
	}
	if len(selection.Clients) == 0 {
		return ErrInvalidArmRequest
	}
	if selection.Mode == ModeStrict && (len(selection.Clients) != 1 || selection.Strict == nil || !selection.Strict.Valid()) {
		return ErrInvalidArmRequest
	}
	if selection.Mode != ModeFlow && selection.Mode != ModeStrict && selection.Mode != ModeDNS {
		return ErrInvalidArmRequest
	}
	if err := rules.runner.Run(ctx, "ipset", "flush", labClientSet); err != nil {
		return err
	}
	if err := rules.configureMode(ctx, selection); err != nil {
		_ = rules.ClearClients(ctx)
		return err
	}
	for _, client := range selection.Clients {
		client = client.Unmap()
		if !client.IsValid() || !client.Is4() || !rules.config.ClientSubnet.Contains(client) {
			_ = rules.ClearClients(ctx)
			return fmt.Errorf("client %q is outside %s", client, rules.config.ClientSubnet)
		}
		if err := rules.runner.Run(ctx, "ipset", "add", labClientSet, client.String(), "-exist"); err != nil {
			_ = rules.ClearClients(ctx)
			return err
		}
	}
	return nil
}

func (rules *FirewallRules) configureMode(ctx context.Context, selection RuleSelection) error {
	for _, chain := range []string{labChain, labDNSChain} {
		if err := rules.runner.Run(ctx, "iptables", "-w", "-F", chain); err != nil {
			return err
		}
	}
	queueRule := func(chain string, queue uint16, arguments ...string) error {
		base := []string{"-w", "-A", chain}
		base = append(base, arguments...)
		base = append(base, "-j", "NFQUEUE", "--queue-num", strconv.Itoa(int(queue)), "--queue-bypass")
		return rules.runner.Run(ctx, "iptables", base...)
	}
	switch selection.Mode {
	case ModeFlow:
		common := []string{"-i", rules.config.APInterface, "-o", rules.config.InternetInterface, "-m", "set", "--match-set", labClientSet, "src"}
		if err := queueRule(labChain, rules.config.QueueNumber, append(common, "-p", "tcp", "-m", "conntrack", "--ctstate", "NEW")...); err != nil {
			return err
		}
		if err := queueRule(labChain, rules.config.QueueNumber, append(common, "-p", "udp", "-m", "conntrack", "--ctstate", "NEW")...); err != nil {
			return err
		}
	case ModeStrict:
		tuple := *selection.Strict
		protocol, client, remote := tuple.Protocol, tuple.ClientIP.String(), tuple.RemoteIP.String()
		outbound := []string{"-i", rules.config.APInterface, "-o", rules.config.InternetInterface, "-s", client, "-d", remote, "-m", "set", "--match-set", labClientSet, "src", "-p", protocol, "--sport", strconv.Itoa(int(tuple.ClientPort)), "--dport", strconv.Itoa(int(tuple.RemotePort))}
		inbound := []string{"-i", rules.config.InternetInterface, "-o", rules.config.APInterface, "-s", remote, "-d", client, "-m", "set", "--match-set", labClientSet, "dst", "-p", protocol, "--sport", strconv.Itoa(int(tuple.RemotePort)), "--dport", strconv.Itoa(int(tuple.ClientPort))}
		if err := queueRule(labChain, rules.config.StrictQueueNumber, outbound...); err != nil {
			return err
		}
		if err := queueRule(labChain, rules.config.StrictQueueNumber, inbound...); err != nil {
			return err
		}
	case ModeDNS:
		common := []string{"-i", rules.config.APInterface, "-m", "set", "--match-set", labClientSet, "src"}
		if err := queueRule(labDNSChain, rules.config.DNSQueueNumber, append(common, "-p", "udp", "--dport", "53")...); err != nil {
			return err
		}
		if err := queueRule(labDNSChain, rules.config.DNSQueueNumber, append(common, "-p", "tcp", "--dport", "53", "-m", "conntrack", "--ctstate", "NEW")...); err != nil {
			return err
		}
	}
	if err := rules.runner.Run(ctx, "iptables", "-w", "-A", labChain, "-j", "RETURN"); err != nil {
		return err
	}
	return rules.runner.Run(ctx, "iptables", "-w", "-A", labDNSChain, "-j", "RETURN")
}

func (rules *FirewallRules) SetClients(ctx context.Context, clients []netip.Addr) error {
	return rules.Activate(ctx, RuleSelection{Mode: ModeFlow, Clients: clients})
}
func (rules *FirewallRules) ClearClients(ctx context.Context) error {
	return rules.runner.Run(ctx, "ipset", "flush", labClientSet)
}

func (rules *FirewallRules) Cleanup(ctx context.Context) error {
	rules.setReady(false)
	rules.deleteJump(ctx, "FORWARD", labChain)
	rules.deleteJump(ctx, "INPUT", labDNSChain)
	for _, chain := range []string{labChain, labDNSChain} {
		_ = rules.runner.Run(ctx, "iptables", "-w", "-F", chain)
		_ = rules.runner.Run(ctx, "iptables", "-w", "-X", chain)
	}
	_ = rules.runner.Run(ctx, "ipset", "flush", labClientSet)
	_ = rules.runner.Run(ctx, "ipset", "destroy", labClientSet)
	return nil
}

func (rules *FirewallRules) resetChain(ctx context.Context, chain string) error {
	if err := rules.runner.Run(ctx, "iptables", "-w", "-F", chain); err != nil {
		return err
	}
	return rules.runner.Run(ctx, "iptables", "-w", "-A", chain, "-j", "RETURN")
}
func (rules *FirewallRules) Ready() bool {
	rules.mu.RLock()
	defer rules.mu.RUnlock()
	return rules.ready
}
func (rules *FirewallRules) setReady(ready bool) {
	rules.mu.Lock()
	rules.ready = ready
	rules.mu.Unlock()
}
func (rules *FirewallRules) deleteJump(ctx context.Context, parent, chain string) {
	for attempts := 0; attempts < 32; attempts++ {
		if err := rules.runner.Run(ctx, "iptables", "-w", "-D", parent, "-j", chain); err != nil {
			return
		}
	}
}
func (rules *FirewallRules) prepareFailure(ctx context.Context, cause error) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	_ = rules.Cleanup(cleanupCtx)
	return fmt.Errorf("prepare lab firewall rules: %w", cause)
}
