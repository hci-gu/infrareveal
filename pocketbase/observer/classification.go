package observer

import (
	"myapp/data"
	"myapp/netmeta"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

type DNSRecord struct {
	ID         string   `json:"id"`
	Session    string   `json:"session"`
	ClientIP   string   `json:"client_ip"`
	QueryName  string   `json:"query_name"`
	QueryType  string   `json:"query_type"`
	Answers    []string `json:"answers"`
	Aliases    []string `json:"aliases"`
	ObservedMS int64    `json:"observed_ms"`
	Source     string   `json:"source"`
	serial     string
}

type dnsCache struct {
	entries []*DNSRecord
	answers map[string][]*DNSRecord
	pruned  int64
}

func (d *dnsCache) reindex() {
	d.answers = map[string][]*DNSRecord{}
	for _, q := range d.entries {
		for _, ip := range q.Answers {
			k := q.Session + "|" + q.ClientIP + "|" + ip
			d.answers[k] = append(d.answers[k], q)
		}
	}
}
func (d *dnsCache) forgetClient(ip string) {
	d.entries = slices.DeleteFunc(d.entries, func(q *DNSRecord) bool { return q.ClientIP == ip })
	d.reindex()
}
func (d *dnsCache) add(session string, e dnsLogEvent, at int64, scope ObservationScope) []DNSRecord {
	if at-d.pruned > 1000 || len(d.entries) >= 8192 {
		d.entries = slices.DeleteFunc(d.entries, func(q *DNSRecord) bool { return q.ObservedMS < at-300000 || q.Session != session })
		if len(d.entries) >= 8192 {
			d.entries = d.entries[len(d.entries)-8191:]
		}
		d.reindex()
		d.pruned = at
	}
	if e.isQuery {
		if !scope.ContainsClient(e.clientIP) {
			return nil
		}
		q := &DNSRecord{ID: data.NewID(), Session: session, ClientIP: e.clientIP, QueryName: normalizeDNSName(e.queryName), QueryType: e.queryType, ObservedMS: at, Source: "dnsmasq", serial: e.serial, Answers: []string{}, Aliases: []string{}}
		d.entries = append(d.entries, q)
		return []DNSRecord{*q}
	}
	updated := []DNSRecord{}
	for _, q := range d.entries {
		if q.Session != session || at-q.ObservedMS > 45000 {
			continue
		}
		if e.serial != "" {
			if q.serial != e.serial {
				continue
			}
		} else if q.QueryName != normalizeDNSName(e.queryName) {
			continue
		}
		if len(q.Answers) >= 16 || len(q.Aliases) >= 8 {
			continue
		}
		answers, aliases, changed := applyDNSReply(q.QueryName, q.Answers, q.Aliases, normalizeDNSName(e.queryName), e.answer, e.serial != "")
		if changed {
			q.Answers = answers
			q.Aliases = aliases
			updated = append(updated, *q)
		}
	}
	if len(updated) > 0 {
		d.reindex()
	}
	return updated
}

func canonicalService(host string, policy data.Policy) string {
	host = normalizeActivityHostname(host)
	domain := registeredActivityDomain(host)
	if v := policy.Aliases[host]; v != "" {
		return v
	}
	if v := policy.Aliases[domain]; v != "" {
		return v
	}
	return domain
}

func (d *dnsCache) resolve(session string, tuple netmeta.FlowTuple, started, now int64, p data.Policy, previous data.Attribution) (string, string, data.Attribution) {
	ip := tuple.RemoteIP.String()
	endpoint := "endpoint:" + ip + "|" + tuple.Protocol + "|" + strconv.Itoa(int(tuple.RemotePort))
	e := data.Attribution{Source: "destination_ip", MatchedIP: ip, Confidence: "low", PolicyVersion: p.Version}
	if tuple.RemotePort == 853 || tuple.RemotePort == 51820 || (tuple.Protocol == "udp" && (tuple.RemotePort == 443 || tuple.RemotePort == 500 || tuple.RemotePort == 4500)) {
		e.Confidence = "hidden"
	}
	service := ""
	for _, q := range d.answers[session+"|"+tuple.ClientIP.String()+"|"+ip] {
		if q.ObservedMS < now-300000 || q.ObservedMS < started-300000 {
			continue
		}
		candidate := canonicalService(q.QueryName, p)
		if candidate == "" {
			continue
		}
		// Later contradictory names retract a provisional label; encrypted
		// connection reuse must never split the same bytes between sites.
		if previous.Hostname != "" && canonicalService(previous.Hostname, p) != candidate {
			e.Ambiguous = true
			continue
		}
		if q.ObservedMS > started+p.CorrectionMS {
			continue
		}
		if service != "" && service != candidate {
			e.Ambiguous = true
			continue
		}
		service = candidate
		if q.ObservedMS >= e.ObservedMS {
			e.Hostname = q.QueryName
			e.ObservedMS = q.ObservedMS
			e.Source = "dns_answer"
			e.Confidence = "medium"
		}
	}
	if previous.Ambiguous {
		e.Ambiguous = true
	}
	if e.Ambiguous {
		e.Hostname = ""
		e.Source = "ambiguous_dns"
		e.Confidence = "low"
		return endpoint, ip, e
	}
	if service == "" && previous.Hostname != "" {
		return canonicalService(previous.Hostname, p), canonicalService(previous.Hostname, p), previous
	}
	if service == "" {
		return endpoint, ip, e
	}
	return service, service, e
}

func tupleFromKey(key string) (netmeta.FlowTuple, bool) {
	p := strings.Split(key, "|")
	if len(p) != 5 {
		return netmeta.FlowTuple{}, false
	}
	cp, e1 := strconv.Atoi(p[2])
	rp, e2 := strconv.Atoi(p[4])
	if e1 != nil || e2 != nil {
		return netmeta.FlowTuple{}, false
	}
	return netmeta.ParseFlowTuple(p[0], p[1], cp, p[3], rp)
}

func normalizedIP(ip string) string {
	v, e := netip.ParseAddr(ip)
	if e != nil {
		return ""
	}
	return v.Unmap().String()
}
