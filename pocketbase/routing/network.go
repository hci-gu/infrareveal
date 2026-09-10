package routing

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"time"
)

// Fingerprint routing inputs, excluding counters and expiring lifetimes. The
// cache remains a gateway approximation; upstream changes are bounded by TTL.
func networkContext() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var parts []string
	for _, args := range [][]string{{"-j", "route", "show", "table", "all"}, {"-j", "-6", "route", "show", "table", "all"}, {"-j", "rule", "show"}, {"-j", "-6", "rule", "show"}} {
		data, err := exec.CommandContext(ctx, "ip", args...).Output()
		if err != nil {
			return "", err
		}
		var rows []map[string]any
		if err = json.Unmarshal(data, &rows); err != nil {
			return "", err
		}
		for _, row := range rows {
			for _, key := range []string{"expires", "cache", "used", "age", "lastuse", "refcnt"} {
				delete(row, key)
			}
			b, _ := json.Marshal(row)
			parts = append(parts, string(b))
		}
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range interfaces {
		addrs, _ := iface.Addrs()
		parts = append(parts, fmt.Sprintf("%s|%s|%d", iface.Name, iface.HardwareAddr, iface.Flags))
		for _, addr := range addrs {
			parts = append(parts, iface.Name+"|"+addr.String())
		}
	}
	sort.Strings(parts)
	return hash(fmt.Sprint(parts)), nil
}
