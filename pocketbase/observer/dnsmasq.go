package observer

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
)

var (
	dnsQueryRE       = regexp.MustCompile(`\bquery\[([^\]]+)\]\s+(\S+)\s+from\s+(\S+)`)
	dnsReplyRE       = regexp.MustCompile(`\b(?:reply|cached)\s+(\S+)\s+is\s+(\S+)`)
	dnsExtraPrefixRE = regexp.MustCompile(`(?:^|:\s)(\d+)\s+\S+\s+(?:query\[|reply\b|cached\b)`)
)

type dnsLogEvent struct {
	serial    string
	queryType string
	queryName string
	clientIP  string
	answer    string
	isQuery   bool
}

type DNSMasqIngestor struct {
	path string
	emit func(dnsLogEvent)
}

func (d *DNSMasqIngestor) run(ctx context.Context) {
	for {
		if err := d.follow(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("dnsmasq observer waiting for %s: %v", d.path, err)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (d *DNSMasqIngestor) follow(ctx context.Context) error {
	file, err := os.Open(d.path)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		return err
	}

	reader := bufio.NewReader(file)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				if err := resetDNSLogAtEOF(file, reader); err != nil {
					log.Printf("DNS spool rotation: %v", err)
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(300 * time.Millisecond):
				}
				continue
			}
			return err
		}
		if event, ok := parseDNSMasqLine(strings.TrimSpace(line)); ok {
			d.emit(event)
		}
	}
}

// Rotate only after consuming the spool, so backlog is not discarded. dnsmasq
// opens its log with O_APPEND and continues writing to the same inode.
func resetDNSLogAtEOF(file *os.File, reader *bufio.Reader) error {
	position, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	truncated := info.Size() < position
	if info.Size() > 8*1024*1024 && position >= info.Size() {
		if err := os.Truncate(file.Name(), 0); err != nil {
			return err
		}
		truncated = true
	}
	if truncated {
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return err
		}
		reader.Reset(file)
	}
	return nil
}

func parseDNSMasqLine(line string) (dnsLogEvent, bool) {
	serial := ""
	if matches := dnsExtraPrefixRE.FindStringSubmatch(line); len(matches) == 2 {
		serial = matches[1]
	}
	if matches := dnsQueryRE.FindStringSubmatch(line); len(matches) == 4 {
		return dnsLogEvent{
			serial: serial, queryType: matches[1], queryName: matches[2],
			clientIP: matches[3], isQuery: true,
		}, true
	}
	if matches := dnsReplyRE.FindStringSubmatch(line); len(matches) == 3 {
		return dnsLogEvent{serial: serial, queryName: matches[1], answer: matches[2]}, true
	}
	return dnsLogEvent{}, false
}

func applyDNSReply(originalName string, answers, aliases []string, replyName, answer string, transactionAware bool) ([]string, []string, bool) {
	changed := false
	if net.ParseIP(answer) != nil && !slices.Contains(answers, answer) {
		answers = append(answers, answer)
		changed = true
	}
	if transactionAware && replyName != "" && replyName != originalName && !slices.Contains(aliases, replyName) {
		aliases = append(aliases, replyName)
		changed = true
	}
	return answers, aliases, changed
}

func normalizeDNSName(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".")
}
