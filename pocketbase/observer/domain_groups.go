package observer

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

//go:embed domain_groups.json
var activityDomainAliasesJSON []byte

var activityDomainAliases = mustLoadActivityDomainAliases(activityDomainAliasesJSON)

func mustLoadActivityDomainAliases(data []byte) map[string]string {
	aliases, err := parseActivityDomainAliases(data)
	if err != nil {
		panic(fmt.Sprintf("invalid embedded domain_groups.json: %v", err))
	}
	return aliases
}

func parseActivityDomainAliases(data []byte) (map[string]string, error) {
	var aliases map[string]string
	if err := json.Unmarshal(data, &aliases); err != nil {
		return nil, err
	}
	if aliases == nil {
		return nil, fmt.Errorf("expected an object mapping alias domains to canonical domains")
	}
	for alias, canonical := range aliases {
		ascii, err := idna.Lookup.ToASCII(alias)
		if err != nil || alias != ascii || alias != normalizeActivityHostname(alias) || registeredActivityDomain(alias) == "" || canonical == "" || registeredActivityDomain(canonical) != canonical {
			return nil, fmt.Errorf("%q → %q must map a normalized hostname or registered domain to a registered domain", alias, canonical)
		}
		if _, chained := aliases[canonical]; chained {
			return nil, fmt.Errorf("%q → %q must point directly to a canonical domain, without chains or cycles", alias, canonical)
		}
	}
	return aliases, nil
}

// Exact hostname rules take precedence over the registered-domain fallback.
// A hostname rule does not capture siblings or descendants of that hostname.
func activityGroupAlias(hostname, domain string) (canonical, matched string, ok bool) {
	ascii, err := idna.Lookup.ToASCII(normalizeActivityHostname(hostname))
	if err == nil {
		if canonical, ok := activityDomainAliases[ascii]; ok {
			return canonical, ascii, true
		}
	}
	canonical, ok = activityDomainAliases[domain]
	return canonical, domain, ok
}

func normalizeActivityHostname(hostname string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname)), ".")
}

func registeredActivityDomain(hostname string) string {
	hostname = normalizeActivityHostname(hostname)
	if hostname == "" || net.ParseIP(hostname) != nil {
		return ""
	}
	ascii, err := idna.Lookup.ToASCII(hostname)
	if err != nil || len(ascii) > 253 {
		return ""
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 {
			return ""
		}
	}
	domain, err := publicsuffix.EffectiveTLDPlusOne(ascii)
	if err != nil {
		return ""
	}
	return domain
}
