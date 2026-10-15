package routing

type TargetStatus struct {
	IP       string `json:"destination_ip"`
	Protocol string `json:"protocol"`
	Port     int    `json:"destination_port"`
	State    string `json:"state"`
}

type Stats struct {
	Session           string         `json:"session"`
	Network           string         `json:"network_context"`
	NetworkEpoch      string         `json:"network_epoch"`
	Engine            string         `json:"engine"`
	UpdatedMS         int64          `json:"updated_ms"`
	Running           int            `json:"running"`
	Pending           int            `json:"pending"`
	Starts            int            `json:"starts"`
	Deferred          int            `json:"deferred"`
	LastError         string         `json:"last_error"`
	RecentBytes       int64          `json:"recent_bytes"`
	Attempts          int            `json:"attempts"`
	AttemptsRemaining int            `json:"attempts_remaining"`
	ManualRemaining   int            `json:"manual_remaining"`
	UsefulPaths       int            `json:"useful_paths"`
	EvidenceBytes     int            `json:"evidence_bytes"`
	Targets           []TargetStatus `json:"targets"`
}
