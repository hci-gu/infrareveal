package data

import "github.com/pocketbase/pocketbase/core"

type HopReply struct {
	Address     string   `json:"address"`
	RTT         *float64 `json:"rtt_ms,omitempty"`
	ReportedRTT *float64 `json:"reported_rtt_ms,omitempty"`
	ProbeID     int      `json:"probe_id"`
	ICMPType    *int     `json:"icmp_type,omitempty"`
	ICMPCode    *int     `json:"icmp_code,omitempty"`
	TCPFlags    *int     `json:"tcp_flags,omitempty"`
	SeenMS      int64    `json:"seen_ms,omitempty"`
}

type RouteLocation struct {
	Lat        float64 `json:"lat"`
	Lon        float64 `json:"lon"`
	City       string  `json:"city,omitempty"`
	Country    string  `json:"country,omitempty"`
	AccuracyKM uint16  `json:"accuracy_km,omitempty"`
	GeoVersion string  `json:"geo_version,omitempty"`
}

type InterfaceEvidence struct {
	Geo            *RouteLocation `json:"geo,omitempty"`
	GeoAvailableMS int64          `json:"geo_available_ms,omitempty"`
	GeoSource      string         `json:"geo_source,omitempty"`
	PTRSource      string         `json:"ptr_source,omitempty"`
	ASNSource      string         `json:"asn_source,omitempty"`
	PTR            string         `json:"ptr,omitempty"`
	ASN            uint           `json:"origin_asn,omitempty"`
	Organization   string         `json:"organization,omitempty"`
	Prefix         string         `json:"prefix,omitempty"`
	Source         string         `json:"source"`
	Version        string         `json:"version"`
	AvailableMS    int64          `json:"available_ms"`
	Confidence     string         `json:"confidence"`
}

type Hop struct {
	EndTTL     int                          `json:"end_ttl,omitempty"`
	Evidence   map[string]InterfaceEvidence `json:"interface_evidence,omitempty"`
	Replies    []HopReply                   `json:"replies,omitempty"`
	TTL        int                          `json:"ttl"`
	Address    string                       `json:"address"`
	Missing    bool                         `json:"missing"`
	State      string                       `json:"state"`
	Timings    []float64                    `json:"timings"`
	Annotation string                       `json:"annotation,omitempty"`
	City       string                       `json:"city,omitempty"`
	Country    string                       `json:"country,omitempty"`
	Lat        *float64                     `json:"lat,omitempty"`
	Lon        *float64                     `json:"lon,omitempty"`
	AccuracyKM uint16                       `json:"accuracy_km,omitempty"`
	GeoVersion string                       `json:"geo_version,omitempty"`
}

// RouteEvidence is a path publication or a network epoch invalidation. Paths
// are self-contained and immutable; enrichment creates at most revision two.
type RouteEvidence struct {
	ID                  string         `json:"id"`
	Session             string         `json:"session"`
	Kind                string         `json:"kind"`
	NetworkContext      string         `json:"network_context"`
	NetworkEpoch        string         `json:"network_epoch"`
	BindingKey          string         `json:"binding_key"`
	DestinationIP       string         `json:"destination_ip"`
	Protocol            string         `json:"protocol"`
	DestinationPort     int            `json:"destination_port"`
	AttemptID           string         `json:"attempt_id"`
	Revision            int            `json:"revision"`
	Method              string         `json:"method"`
	Status              string         `json:"status"`
	Reason              string         `json:"reason"`
	Fingerprint         string         `json:"fingerprint"`
	MeasuredMS          int64          `json:"measured_ms"`
	AvailableMS         int64          `json:"available_ms"`
	FreshUntilMS        int64          `json:"fresh_until_ms"`
	ValidUntilMS        int64          `json:"valid_until_ms"`
	DestinationReached  bool           `json:"destination_reached"`
	Hops                []Hop          `json:"hops"`
	DestinationLocation *RouteLocation `json:"destination_location,omitempty"`
	EvidenceBytes       int            `json:"evidence_bytes"`
}

type AccessPosition struct {
	TTL       int      `json:"ttl"`
	Addresses []string `json:"addresses"`
}

type ProbeDetails struct {
	Engine        string `json:"engine"`
	EngineVersion string `json:"engine_version"`
	SourceIP      string `json:"source_ip"`
	ProbeCount    int    `json:"probe_count"`
	ProbedTTL     int    `json:"probed_ttl"`
	StopReason    string `json:"stop_reason"`
	Hops          []Hop  `json:"hops,omitempty"`
}

// ProbeRun is the durable admission ledger. Session is deliberately text: its
// quota charge and suppression can outlive deletion of the recording.
type ProbeRun struct {
	ID                 string           `json:"id"`
	Session            string           `json:"session"`
	Scope              string           `json:"scope"`
	NetworkContext     string           `json:"network_context"`
	NetworkEpoch       string           `json:"network_epoch"`
	Family             string           `json:"family"`
	BindingKey         string           `json:"binding_key"`
	DestinationIP      string           `json:"destination_ip"`
	Protocol           string           `json:"protocol"`
	DestinationPort    int              `json:"destination_port"`
	SourcePort         int              `json:"source_port"`
	Method             string           `json:"method"`
	Manual             bool             `json:"manual"`
	AdmittedMS         int64            `json:"admitted_ms"`
	FinishedMS         int64            `json:"finished_ms"`
	Status             string           `json:"status"`
	Class              string           `json:"class"`
	Reason             string           `json:"reason"`
	Error              string           `json:"error"`
	Useful             bool             `json:"useful"`
	ComparisonComplete bool             `json:"comparison_complete"`
	PauseUntilMS       int64            `json:"pause_until_ms"`
	CooldownUntilMS    int64            `json:"cooldown_until_ms"`
	AccessPrefix       []AccessPosition `json:"access_prefix"`
	Details            *ProbeDetails    `json:"details,omitempty"`
}

func routeCollections() []*core.Collection {
	evidence := NewCollection("route_evidence",
		&core.SelectField{Name: "kind", Required: true, MaxSelect: 1, Values: []string{"path", "network_invalidated"}},
		&core.JSONField{Name: "hops", MaxSize: 65536},
		&core.JSONField{Name: "destination_location", MaxSize: 2048},
		&core.BoolField{Name: "destination_reached"},
	)
	for _, name := range []string{"session", "network_context", "network_epoch", "binding_key", "destination_ip", "protocol", "attempt_id", "method", "status", "reason", "fingerprint"} {
		evidence.Fields.Add(&core.TextField{Name: name, Max: 1000})
	}
	for _, name := range []string{"destination_port", "revision", "measured_ms", "available_ms", "fresh_until_ms", "valid_until_ms", "evidence_bytes"} {
		evidence.Fields.Add(&core.NumberField{Name: name, OnlyInt: true})
	}
	evidence.AddIndex("idx_route_evidence_window", false, "session, network_epoch, binding_key, available_ms", "")
	evidence.AddIndex("idx_route_evidence_revision", true, "attempt_id, revision", "kind = 'path'")
	evidence.AddIndex("idx_route_evidence_session_time", false, "session, available_ms", "")
	runs := NewCollection("probe_runs",
		&core.BoolField{Name: "manual"}, &core.BoolField{Name: "useful"}, &core.BoolField{Name: "comparison_complete"},
		&core.JSONField{Name: "access_prefix", MaxSize: 8192}, &core.JSONField{Name: "details", MaxSize: 16384},
	)
	for _, name := range []string{"session", "scope", "network_context", "network_epoch", "family", "binding_key", "destination_ip", "protocol", "method", "status", "class", "reason", "error"} {
		runs.Fields.Add(&core.TextField{Name: name, Max: 1000})
	}
	for _, name := range []string{"destination_port", "source_port", "admitted_ms", "finished_ms", "pause_until_ms", "cooldown_until_ms"} {
		runs.Fields.Add(&core.NumberField{Name: name, OnlyInt: true})
	}
	runs.AddIndex("idx_probe_runs_network_time", false, "network_context, family, admitted_ms", "")
	runs.AddIndex("idx_probe_runs_scope", false, "session, scope", "")
	runs.AddIndex("idx_probe_runs_binding", false, "network_context, family, binding_key, method, admitted_ms", "")
	return []*core.Collection{evidence, runs}
}
