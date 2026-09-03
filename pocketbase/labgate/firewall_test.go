package labgate

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"

	"myapp/netmeta"
)

type recordedCommand struct {
	name      string
	arguments []string
}
type recordingRunner struct {
	mu              sync.Mutex
	commands        []recordedCommand
	failContains    string
	deleteSuccesses int
}

func (runner *recordingRunner) Run(_ context.Context, name string, arguments ...string) error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.commands = append(runner.commands, recordedCommand{name, append([]string(nil), arguments...)})
	joined := name + " " + strings.Join(arguments, " ")
	if strings.Contains(joined, "-D FORWARD") {
		if runner.deleteSuccesses > 0 {
			runner.deleteSuccesses--
			return nil
		}
		return errors.New("not found")
	}
	if runner.failContains != "" && strings.Contains(joined, runner.failContains) {
		return errors.New("injected failure")
	}
	return nil
}

func TestFirewallPrepareIsIdempotentAndOrdered(t *testing.T) {
	runner := &recordingRunner{deleteSuccesses: 2}
	rules := newTestRules(t, runner)
	if err := rules.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := rules.Activate(context.Background(), RuleSelection{Mode: ModeFlow, Clients: []netip.Addr{netip.MustParseAddr("10.0.0.2")}}); err != nil {
		t.Fatal(err)
	}
	if !rules.Ready() {
		t.Fatal("rules not ready")
	}
	commands := runner.commands
	jumpInsert := findCommand(commands, "iptables", []string{"-w", "-I", "FORWARD", "1", "-j", labChain})
	tcpQueue := findContaining(commands, "--ctstate NEW -j NFQUEUE --queue-num 42 --queue-bypass")
	udpQueue := findContaining(commands, "-p udp")
	if jumpInsert < 0 || tcpQueue < 0 || udpQueue < 0 || jumpInsert > tcpQueue || jumpInsert > udpQueue {
		t.Fatalf("unsafe command order: %#v", commands)
	}
	if countContaining(commands, "-I FORWARD 1 -j "+labChain) != 1 {
		t.Fatal("expected exactly one jump insertion")
	}
}

func TestFirewallClientValidationUsesArgumentArrays(t *testing.T) {
	runner := &recordingRunner{}
	rules := newTestRules(t, runner)
	if err := rules.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	clients := []netip.Addr{netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.3")}
	if err := rules.SetClients(context.Background(), clients); err != nil {
		t.Fatal(err)
	}
	if findCommand(runner.commands, "ipset", []string{"add", labClientSet, "10.0.0.2", "-exist"}) < 0 {
		t.Fatal("client was not added as a distinct argument")
	}
	before := len(runner.commands)
	if err := rules.SetClients(context.Background(), []netip.Addr{netip.MustParseAddr("192.168.1.2")}); err == nil {
		t.Fatal("out-of-subnet client accepted")
	}
	if !reflect.DeepEqual(runner.commands[len(runner.commands)-1], recordedCommand{"ipset", []string{"flush", labClientSet}}) || len(runner.commands) <= before {
		t.Fatal("invalid selection was not cleared")
	}
}

func TestFirewallCleanupIsRepeatableAndPrepareFailureCleans(t *testing.T) {
	runner := &recordingRunner{failContains: "-p udp"}
	rules := newTestRules(t, runner)
	if err := rules.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := rules.Activate(context.Background(), RuleSelection{Mode: ModeFlow, Clients: []netip.Addr{netip.MustParseAddr("10.0.0.2")}}); err == nil {
		t.Fatal("injected failure ignored")
	}
	runner.failContains = ""
	if err := rules.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := rules.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if countContaining(runner.commands, "ipset destroy "+labClientSet) < 2 {
		t.Fatal("cleanup was not repeatable")
	}
}

func TestFirewallStrictAndDNSRulesAreIsolated(t *testing.T) {
	runner := &recordingRunner{}
	rules := newTestRules(t, runner)
	if err := rules.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	tuple, _ := netmeta.NewFlowTuple("tcp", netip.MustParseAddr("10.0.0.2"), 50000, netip.MustParseAddr("1.1.1.1"), 443)
	if err := rules.Activate(context.Background(), RuleSelection{Mode: ModeStrict, Clients: []netip.Addr{tuple.ClientIP}, Strict: &tuple}); err != nil {
		t.Fatal(err)
	}
	if countContaining(runner.commands, "--queue-num 43 --queue-bypass") != 2 {
		t.Fatal("strict mode must install exact rules in both directions")
	}
	if findContaining(runner.commands, "-s 10.0.0.2 -d 1.1.1.1 -m set --match-set "+labClientSet+" src -p tcp --sport 50000 --dport 443") < 0 {
		t.Fatal("strict outbound tuple is incomplete")
	}
	if findContaining(runner.commands, "--match-set "+labClientSet+" src") < 0 || findContaining(runner.commands, "--match-set "+labClientSet+" dst") < 0 {
		t.Fatal("strict rules must be disabled by the emptied client set on drain/disarm")
	}
	start := len(runner.commands)
	if err := rules.Activate(context.Background(), RuleSelection{Mode: ModeDNS, Clients: []netip.Addr{tuple.ClientIP}}); err != nil {
		t.Fatal(err)
	}
	if findContaining(runner.commands[start:], "-A INFRAREVEAL_LAB_DNS -i wlan0") < 0 || countContaining(runner.commands[start:], "--queue-num 44 --queue-bypass") != 2 {
		t.Fatal("DNS queue rules are missing")
	}
}

func newTestRules(t *testing.T, runner CommandRunner) *FirewallRules {
	t.Helper()
	rules, err := NewFirewallRules(FirewallConfig{APInterface: "wlan0", InternetInterface: "eth0", ClientSubnet: netip.MustParsePrefix("10.0.0.0/24"), QueueNumber: 42, StrictQueueNumber: 43, DNSQueueNumber: 44}, runner)
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func findCommand(commands []recordedCommand, name string, arguments []string) int {
	for index, command := range commands {
		if command.name == name && reflect.DeepEqual(command.arguments, arguments) {
			return index
		}
	}
	return -1
}
func findContaining(commands []recordedCommand, fragment string) int {
	for index, command := range commands {
		if strings.Contains(command.name+" "+strings.Join(command.arguments, " "), fragment) {
			return index
		}
	}
	return -1
}
func countContaining(commands []recordedCommand, fragment string) int {
	count := 0
	for _, command := range commands {
		if strings.Contains(command.name+" "+strings.Join(command.arguments, " "), fragment) {
			count++
		}
	}
	return count
}
