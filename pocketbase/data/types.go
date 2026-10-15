// Package data defines InfraReveal's persisted product facts and map contract.
// Time is Unix milliseconds; byte counts are captured wire bytes, not content.
package data

type Policy struct {
	Version      string            `json:"version"`
	BucketMS     int64             `json:"bucket_ms"`
	ChunkMS      int64             `json:"chunk_ms"`
	CorrectionMS int64             `json:"correction_ms"`
	QuietGapMS   int64             `json:"quiet_gap_ms"`
	Aliases      map[string]string `json:"aliases"`
}

type CaptureHealth struct {
	Epoch       string `json:"epoch"`
	Generation  int64  `json:"generation"`
	Running     bool   `json:"running"`
	ConfirmedMS int64  `json:"confirmed_ms"`
	Quality     string `json:"quality"`
	Error       string `json:"error"`
	Dropped     int64  `json:"dropped"`
}

type Session struct {
	GateAuditComplete bool          `json:"gate_audit_complete"`
	GateAuditDrops    uint64        `json:"gate_audit_drops"`
	ID                string        `json:"id"`
	Name              string        `json:"name"`
	Active            bool          `json:"active"`
	Ephemeral         bool          `json:"ephemeral"`
	Demo              bool          `json:"demo"`
	StartedMS         int64         `json:"started_ms"`
	EndedMS           int64         `json:"ended_ms"`
	RetentionMinutes  int           `json:"retention_minutes"`
	RetainedFromMS    int64         `json:"retained_from_ms"`
	Revision          int64         `json:"revision"`
	NetworkContext    string        `json:"network_context"`
	NetworkEpoch      string        `json:"network_epoch"`
	Policy            Policy        `json:"policy"`
	Capture           CaptureHealth `json:"capture"`
	Diagnostics       Diagnostics   `json:"diagnostics"`
}

type Diagnostics struct {
	Flows bool `json:"flows"`
	DNS   bool `json:"dns"`
	Gate  bool `json:"gate"`
}

type Manifest struct {
	Session
	ServerMS int64 `json:"server_ms"`
}

// Sample is [offset_ms, wire_sent, wire_received, payload_sent,
// payload_received, packets_sent, packets_received]. It covers a half-open bin.
type Sample [7]int64

type Attribution struct {
	Hostname      string `json:"hostname"`
	Source        string `json:"source"`
	MatchedIP     string `json:"matched_ip"`
	ObservedMS    int64  `json:"observed_ms"`
	Confidence    string `json:"confidence"`
	Ambiguous     bool   `json:"ambiguous"`
	PolicyVersion string `json:"policy_version"`
}

type TrafficChunk struct {
	ID              string      `json:"id"`
	Session         string      `json:"session"`
	CaptureEpoch    string      `json:"capture_epoch"`
	ClientID        string      `json:"client_id"`
	ClientIP        string      `json:"client_ip"`
	ServiceKey      string      `json:"service_key"`
	ServiceLabel    string      `json:"service_label"`
	DestinationID   string      `json:"destination_id"`
	DestinationIP   string      `json:"destination_ip"`
	Protocol        string      `json:"protocol"`
	DestinationPort int         `json:"destination_port"`
	NetworkEpoch    string      `json:"network_epoch"`
	StartMS         int64       `json:"start_ms"`
	BucketMS        int64       `json:"bucket_ms"`
	ChunkMS         int64       `json:"chunk_ms"`
	Generation      int64       `json:"generation"`
	Sealed          bool        `json:"sealed"`
	Evidence        Attribution `json:"evidence"`
	Samples         []Sample    `json:"samples"`
}

type CaptureInterval struct {
	ID           string `json:"id"`
	Session      string `json:"session"`
	CaptureEpoch string `json:"capture_epoch"`
	StartMS      int64  `json:"start_ms"`
	EndMS        int64  `json:"end_ms"`
	Quality      string `json:"quality"`
	Dropped      int64  `json:"dropped"`
	Reason       string `json:"reason"`
}

type ActivityBlock struct {
	ID              string `json:"id"`
	Session         string `json:"session"`
	ClientID        string `json:"client_id"`
	ClientIP        string `json:"client_ip"`
	ServiceKey      string `json:"service_key"`
	ServiceLabel    string `json:"service_label"`
	OriginalStartMS int64  `json:"original_start_ms"`
	StartMS         int64  `json:"start_ms"`
	EndMS           int64  `json:"end_ms"`
	ActiveMS        int64  `json:"active_ms"`
	Sent            int64  `json:"sent"`
	Received        int64  `json:"received"`
	Confidence      string `json:"confidence"`
	Quality         string `json:"quality"`
	Provisional     bool   `json:"provisional"`
	Clipped         bool   `json:"clipped"`
	Revision        int64  `json:"revision"`
}

type Destination struct {
	ID          string   `json:"id"`
	IP          string   `json:"ip"`
	Version     string   `json:"version"`
	ObservedMS  int64    `json:"observed_ms"`
	Country     string   `json:"country"`
	CountryCode string   `json:"country_code"`
	City        string   `json:"city"`
	Lat         *float64 `json:"lat"`
	Lon         *float64 `json:"lon"`
	AccuracyKM  int      `json:"accuracy_km"`
	Precision   string   `json:"precision"`
	Provider    string   `json:"provider"`
	ASN         int      `json:"asn"`
	PTR         string   `json:"ptr"`
}

type MapWindow struct {
	SessionID    string            `json:"session_id"`
	Revision     int64             `json:"revision"`
	FromMS       int64             `json:"from_ms"`
	ToMS         int64             `json:"to_ms"`
	ResolutionMS int64             `json:"resolution_ms"`
	Complete     bool              `json:"complete"`
	NextCursor   string            `json:"next_cursor,omitempty"`
	Series       []TrafficChunk    `json:"series"`
	Coverage     []CaptureInterval `json:"coverage"`
	Blocks       []ActivityBlock   `json:"blocks"`
	Destinations []Destination     `json:"destinations"`
	Routes       []RouteEvidence   `json:"routes"`
}

type BlockPage struct {
	SessionID  string          `json:"session_id"`
	Revision   int64           `json:"revision"`
	Items      []ActivityBlock `json:"items"`
	NextCursor string          `json:"next_cursor,omitempty"`
}
