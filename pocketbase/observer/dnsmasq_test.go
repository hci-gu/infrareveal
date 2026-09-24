package observer

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestParseDNSMasqExtraLogKeepsQuerySerialAcrossCNAMEChain(t *testing.T) {
	lines := []string{
		"Aug 25 08:45:57 dnsmasq[123]: 42 10.0.0.96/53001 query[A] www.svt.se from 10.0.0.96",
		"Aug 25 08:45:57 dnsmasq[123]: 42 10.0.0.96/53001 reply www.svt.se is <CNAME>",
		"Aug 25 08:45:57 dnsmasq[123]: 42 10.0.0.96/53001 reply e6703.dscb.akamaiedge.net is 92.122.72.194",
	}

	for index, line := range lines {
		event, ok := parseDNSMasqLine(line)
		if !ok {
			t.Fatalf("expected line %d to parse", index)
		}
		if event.serial != "42" {
			t.Fatalf("expected serial 42 for line %d, got %q", index, event.serial)
		}
		if index == 0 && (!event.isQuery || event.queryName != "www.svt.se" || event.clientIP != "10.0.0.96") {
			t.Fatalf("unexpected query event: %#v", event)
		}
		if index == 2 && (event.isQuery || event.queryName != "e6703.dscb.akamaiedge.net" || event.answer != "92.122.72.194") {
			t.Fatalf("unexpected terminal reply event: %#v", event)
		}
	}
}

func TestParseDNSMasqLegacyLogStillWorks(t *testing.T) {
	event, ok := parseDNSMasqLine("dnsmasq[123]: query[A] example.com from 10.0.0.50")
	if !ok || !event.isQuery || event.serial != "" || event.queryName != "example.com" {
		t.Fatalf("unexpected legacy query event: %#v", event)
	}
}

func TestApplyDNSReplyCarriesTerminalCNAMEAddressToOriginalQuery(t *testing.T) {
	answers, aliases, changed := applyDNSReply(
		"www.svt.se",
		nil,
		nil,
		"e6703.dscb.akamaiedge.net",
		"92.122.72.194",
		true,
	)
	if !changed || len(answers) != 1 || answers[0] != "92.122.72.194" {
		t.Fatalf("expected terminal address on original query, got %#v", answers)
	}
	if len(aliases) != 1 || aliases[0] != "e6703.dscb.akamaiedge.net" {
		t.Fatalf("expected CNAME alias on original query, got %#v", aliases)
	}
}

func TestApplyDNSReplyDoesNotStoreCNAMEMarkerAsAddress(t *testing.T) {
	answers, _, changed := applyDNSReply("www.svt.se", nil, nil, "www.svt.se", "<CNAME>", true)
	if changed || len(answers) != 0 {
		t.Fatalf("expected CNAME marker to be ignored as an address, got %#v", answers)
	}
}

// Admin and upstream DNS must never reach storage or the trace stream. A nil
// app/session callback makes accidental processing fail immediately.
func TestDNSMasqIgnoresQueriesOutsideObservationScope(t *testing.T) {
	ingestor := &DNSMasqIngestor{scope: NewObservationScope("10.0.0.0/24", "10.0.0.1")}
	for _, ip := range []string{"10.77.0.50", "192.168.10.50", "not-an-ip"} {
		ingestor.handleLine("dnsmasq[123]: 42 " + ip + "/53001 query[A] example.com from " + ip)
	}
}

func TestDNSLogRotationWaitsForBacklogAndResumesNewWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dnsmasq.log")
	writer, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := writer.Truncate(8*1024*1024 + 1); err != nil {
		t.Fatal(err)
	}
	readerFile, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer readerFile.Close()
	reader := bufio.NewReader(readerFile)
	if err := resetDNSLogAtEOF(readerFile, reader); err != nil {
		t.Fatal(err)
	}
	info, _ := readerFile.Stat()
	if info.Size() == 0 {
		t.Fatal("unread backlog discarded")
	}
	if _, err := readerFile.Seek(0, io.SeekEnd); err != nil {
		t.Fatal(err)
	}
	if err := resetDNSLogAtEOF(readerFile, reader); err != nil {
		t.Fatal(err)
	}
	info, _ = readerFile.Stat()
	if info.Size() != 0 {
		t.Fatal("consumed spool not rotated")
	}
	if _, err := writer.WriteString("next query\n"); err != nil {
		t.Fatal(err)
	}
	line, err := reader.ReadString('\n')
	if err != nil || line != "next query\n" {
		t.Fatalf("did not resume: %q %v", line, err)
	}
	if err := writer.Truncate(0); err != nil {
		t.Fatal(err)
	}
	if err := resetDNSLogAtEOF(readerFile, reader); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.WriteString("after external rotation\n"); err != nil {
		t.Fatal(err)
	}
	line, err = reader.ReadString('\n')
	if err != nil || line != "after external rotation\n" {
		t.Fatalf("external rotation: %q %v", line, err)
	}
}
