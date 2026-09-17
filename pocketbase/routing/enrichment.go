package routing

import (
	"context"
	"fmt"
	"github.com/oschwald/maxminddb-golang"
	"myapp/netmeta"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type InterfaceEvidence struct {
	Geo            *Location `json:"geo,omitempty"`
	GeoAvailableAt string    `json:"geo_available_at,omitempty"`
	GeoSource      string    `json:"geo_source,omitempty"`
	PTRSource      string    `json:"ptr_source,omitempty"`
	ASNSource      string    `json:"asn_source,omitempty"`
	PTR            string    `json:"ptr,omitempty"`
	ASN            uint      `json:"origin_asn,omitempty"`
	Organization   string    `json:"organization,omitempty"`
	Prefix         string    `json:"prefix,omitempty"`
	Source         string    `json:"source"`
	Version        string    `json:"version"`
	AvailableAt    string    `json:"available_at"`
	Confidence     string    `json:"confidence"`
}
type interfaceEnricher struct {
	mu      sync.Mutex
	asn     *maxminddb.Reader
	version string
	cache   map[string]InterfaceEvidence
}

func newInterfaceEnricher() *interfaceEnricher {
	e := &interfaceEnricher{cache: map[string]InterfaceEvidence{}, version: "unavailable"}
	path := os.Getenv("ROUTE_ASN_DB")
	if path == "" {
		path = "./geoip/asn.mmdb"
	}
	if db, err := maxminddb.Open(path); err == nil {
		e.asn = db
		if info, err := os.Stat(path); err == nil {
			e.version = fmt.Sprintf("%d/%d", info.Size(), info.ModTime().Unix())
		}
	}
	return e
}
func (e *interfaceEnricher) close() {
	if e != nil && e.asn != nil {
		_ = e.asn.Close()
	}
}
func (e *interfaceEnricher) lookup(ctx context.Context, ip string) InterfaceEvidence {
	e.mu.Lock()
	v, ok := e.cache[ip]
	e.mu.Unlock()
	if ok {
		return v
	}
	v = InterfaceEvidence{Source: "local-asn/ptr", Version: e.version, AvailableAt: date(time.Now()), Confidence: "inferred"}
	if !netmeta.PublicAddress(ip) {
		v.Source = "special-address"
		v.Confidence = "unknown"
		return v
	}
	if e.asn != nil {
		var data struct {
			ASN          uint   `maxminddb:"autonomous_system_number"`
			Organization string `maxminddb:"autonomous_system_organization"`
		}
		if prefix, ok, err := e.asn.LookupNetwork(net.ParseIP(ip), &data); err == nil && ok {
			v.ASN = data.ASN
			v.Organization = data.Organization
			v.Prefix = prefix.String()
			v.ASNSource = "local prefix-origin database"
		}
	}
	lookup, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	if names, err := net.DefaultResolver.LookupAddr(lookup, ip); err == nil && len(names) > 0 {
		v.PTR = strings.TrimSuffix(names[0], ".")
		v.PTRSource = "DNS PTR"
	}
	e.mu.Lock()
	if len(e.cache) >= 2048 {
		clear(e.cache)
	}
	e.cache[ip] = v
	e.mu.Unlock()
	return v
}
func (e *interfaceEnricher) enrich(ctx context.Context, s snapshot) snapshot {
	if e == nil {
		return s
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	s.Hops = append([]Hop(nil), s.Hops...)
	// One bounded lookup sequence per accepted measurement; repeated IPs reuse cache.
	for i := range s.Hops {
		h := &s.Hops[i]
		h.Evidence = map[string]InterfaceEvidence{}
		for _, ip := range addresses(*h) {
			if ctx.Err() != nil {
				return s
			}
			h.Evidence[ip] = e.lookup(ctx, ip)
		}
	}
	return s
}
