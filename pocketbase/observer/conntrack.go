package observer

import (
	"bufio"
	"myapp/netmeta"
	"os"
	"strconv"
	"strings"
)

type FlowSample struct {
	Protocol        string
	State           string
	ClientIP        string
	DestinationIP   string
	SourcePort      int
	DestinationPort int
	PacketsOut      int64
	PacketsIn       int64
	BytesOut        int64
	BytesIn         int64
}

func (f FlowSample) Key() string {
	tuple, ok := netmeta.ParseFlowTuple(f.Protocol, f.ClientIP, f.SourcePort, f.DestinationIP, f.DestinationPort)
	if !ok {
		return ""
	}
	return tuple.Key()
}

func ensureConntrackAccounting(path string) (bool, error) {
	if path == "" {
		return false, nil
	}

	value, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(string(value)) == "1" {
		return false, nil
	}

	if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
		return false, err
	}
	return true, nil
}

func ReadConntrackSamples(path string, scope ObservationScope) ([]FlowSample, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	samples := make([]FlowSample, 0, 128)
	scanner := bufio.NewScanner(file)
	for len(samples) < maxConnections && scanner.Scan() {
		sample, ok := parseConntrackLine(scanner.Text(), scope)
		if ok {
			samples = append(samples, sample)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return samples, nil
}

func ParseConntrackLine(line string, clientPrefix string) (FlowSample, bool) {
	return parseConntrackLine(line, NewObservationScope(clientPrefix, ""))
}

func parseConntrackLine(line string, scope ObservationScope) (FlowSample, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return FlowSample{}, false
	}

	protocol := ""
	protocolIndex := -1
	for i, field := range fields {
		switch field {
		case "tcp", "udp", "icmp":
			protocol = field
			protocolIndex = i
		}
	}
	if protocol == "" {
		return FlowSample{}, false
	}

	state := ""
	if protocol == "tcp" && protocolIndex+3 < len(fields) && !strings.Contains(fields[protocolIndex+3], "=") {
		state = fields[protocolIndex+3]
	}

	original := map[string]string{}
	reply := map[string]string{}
	current := original
	for _, field := range fields[protocolIndex+1:] {
		if !strings.Contains(field, "=") {
			continue
		}
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		if key == "src" && len(original) > 0 {
			current = reply
		}
		current[key] = value
	}

	clientIP := original["src"]
	destinationIP := original["dst"]
	destinationPort := parseInt(original["dport"])
	if protocol != "icmp" && destinationPort == 0 {
		return FlowSample{}, false
	}
	if !scope.Includes(protocol, clientIP, destinationIP, destinationPort) {
		return FlowSample{}, false
	}

	return FlowSample{
		Protocol:        protocol,
		State:           state,
		ClientIP:        clientIP,
		DestinationIP:   destinationIP,
		SourcePort:      parseInt(original["sport"]),
		DestinationPort: destinationPort,
		PacketsOut:      parseInt64(original["packets"]),
		PacketsIn:       parseInt64(reply["packets"]),
		BytesOut:        parseInt64(original["bytes"]),
		BytesIn:         parseInt64(reply["bytes"]),
	}, true
}

func parseInt(value string) int {
	n, _ := strconv.Atoi(value)
	return n
}

func parseInt64(value string) int64 {
	n, _ := strconv.ParseInt(value, 10, 64)
	return n
}
