// Package proto is the wire contract between the agent and ingest (JSON, v1).
//
// Agents in the field run old versions for a long time, so changes here must
// stay backward compatible: add optional fields, never rename or repurpose one.
package proto

// RegisterRequest is sent once, by `pulsegrid-agent register`, with the install key.
type RegisterRequest struct {
	InstallKey      string `json:"install_key"`
	MachineID       string `json:"machine_id"`
	Hostname        string `json:"hostname"`
	OS              string `json:"os"`
	Platform        string `json:"platform"`
	PlatformVersion string `json:"platform_version"`
	Arch            string `json:"arch"`
	AgentVersion    string `json:"agent_version"`
	// Tags are added to the host's tags (install.sh --tags web,production).
	Tags []string `json:"tags,omitempty"`
}

// RegisterResponse gives the agent its own token. The install key is not used again.
type RegisterResponse struct {
	HostID    string      `json:"host_id"`
	HostToken string      `json:"host_token"`
	Config    AgentConfig `json:"config"`
}

// AgentConfig is fetched periodically, so endpoints and the interval can be
// changed server-side without touching installed agents.
type AgentConfig struct {
	IngestURL       string `json:"ingest_url"`
	IntervalSeconds int    `json:"interval_seconds"`
	// LatestVersion and DownloadURL drive `pulsegrid-agent update`. Binaries
	// live at <DownloadURL>/agent/<LatestVersion>/pulsegrid-agent-<os>-<arch>.
	LatestVersion string `json:"latest_version,omitempty"`
	DownloadURL   string `json:"download_url,omitempty"`
	// Processes and services to report on even when absent or stopped. They
	// come from the host's alert rules, so adding a rule configures agents.
	WatchProcesses []string `json:"watch_processes,omitempty"`
	WatchServices  []string `json:"watch_services,omitempty"`
}

// Sample is one measurement. Names follow Prometheus conventions
// (pulsegrid_<thing>_<unit>, counters end in _total).
type Sample struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
	Value  float64           `json:"value"`
}

// Batch is everything collected in one tick.
type Batch struct {
	TimestampMs int64    `json:"ts"`
	Samples     []Sample `json:"samples"`
}

// MetricsRequest may carry several batches when the agent is replaying its
// offline buffer.
type MetricsRequest struct {
	AgentVersion string    `json:"agent_version"`
	Batches      []Batch   `json:"batches"`
	Host         *HostMeta `json:"host,omitempty"`
}

// HostMeta is what the agent currently knows about its machine. It's sent
// with every push so the dashboard follows hostname, IP and OS changes.
type HostMeta struct {
	Hostname        string   `json:"hostname,omitempty"`
	PlatformVersion string   `json:"platform_version,omitempty"`
	IPAddresses     []string `json:"ip_addresses,omitempty"`
	CPUCores        int      `json:"cpu_cores,omitempty"`
	MemoryBytes     uint64   `json:"memory_bytes,omitempty"`
}
