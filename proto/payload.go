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
	// Checks the agent runs on its own schedule: ports, URLs, files and log
	// patterns on this host, or public uptime checks when the host is a probe.
	Checks []Check `json:"checks,omitempty"`
	// Version identifies this config. Ingest returns the current one with
	// every metrics push, and the agent refetches when it differs, so changes
	// arrive within one push instead of at the next periodic refresh.
	Version string `json:"version,omitempty"`
	// Actions waiting to run on this host. The agent only runs actions its
	// local actions file allows; anything else is reported as refused.
	Actions []ActionRequest `json:"actions,omitempty"`
	// Collect the software inventory (packages, listening ports) this often.
	// Zero means the agent's default.
	InventoryIntervalSeconds int `json:"inventory_interval_seconds,omitempty"`
}

// Check is one resource or uptime check.
//
//	tcp:   Target "host:port"
//	http:  Target URL; Params method, expect_status ("200-399"), keyword,
//	       keyword_absent ("true"), timeout_seconds, tls_skip_verify ("true")
//	tls:   Target "host:port"; reports certificate expiry
//	dns:   Target name; Params record_type (A, AAAA, MX, TXT, CNAME), expect
//	file:  Target path; Params mode: exists | absent | changed | max_age_seconds | max_size_bytes, value
//	log:   Target path; Params pattern (RE2), threshold (matches per run that count as failing)
//	ping:  Target host; TCP connect to port 80/443 as a reachability probe (no raw sockets: the agent is unprivileged)
type Check struct {
	ID              string            `json:"id"`
	Type            string            `json:"type"`
	Target          string            `json:"target"`
	Params          map[string]string `json:"params,omitempty"`
	IntervalSeconds int               `json:"interval_seconds,omitempty"`
}

// CheckResult is the outcome of one check run. Status is also sent as the
// samples pulsegrid_check_up / pulsegrid_check_latency_seconds; this carries
// the human-readable detail for alert messages and the dashboard.
type CheckResult struct {
	ID          string  `json:"id"`
	OK          bool    `json:"ok"`
	Detail      string  `json:"detail,omitempty"`
	LatencyMs   float64 `json:"latency_ms,omitempty"`
	TimestampMs int64   `json:"ts"`
}

// ActionRequest asks the agent to run a named action from its local allow-list.
type ActionRequest struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ActionResult reports how an action went.
type ActionResult struct {
	ID       string `json:"id"`
	Status   string `json:"status"` // succeeded | failed | refused
	ExitCode int    `json:"exit_code"`
	Output   string `json:"output,omitempty"` // truncated
}

// Inventory is the host's software and network inventory.
type Inventory struct {
	Packages       []Package    `json:"packages,omitempty"`
	ListeningPorts []ListenPort `json:"listening_ports,omitempty"`
	KernelVersion  string       `json:"kernel_version,omitempty"`
	BootTime       int64        `json:"boot_time,omitempty"`
	CPUModel       string       `json:"cpu_model,omitempty"`
	Virtualization string       `json:"virtualization,omitempty"`
	// Actions the local allow-list permits, so the dashboard can offer them.
	AllowedActions []string `json:"allowed_actions,omitempty"`
	// Plugins configured locally and whether their last run worked.
	Plugins []PluginStatus `json:"plugins,omitempty"`
	// Log shipping as configured in logs.conf; nil when it's off.
	Logs *LogsStatus `json:"logs,omitempty"`
}

// LogsStatus is what the agent ships and what it couldn't read.
type LogsStatus struct {
	Files    []string `json:"files,omitempty"`
	Journal  bool     `json:"journal,omitempty"`
	Problems []string `json:"problems,omitempty"`
}

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type ListenPort struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     uint32 `json:"port"`
	Process  string `json:"process,omitempty"`
}

type PluginStatus struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// MetricsResponse answers a push.
type MetricsResponse struct {
	Accepted      int    `json:"accepted"`
	Dropped       int    `json:"dropped"`
	ConfigVersion string `json:"config_version,omitempty"`
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
	// Latest result of each check run since the last push.
	CheckResults []CheckResult `json:"check_results,omitempty"`
	// Results of actions finished since the last push.
	ActionResults []ActionResult `json:"action_results,omitempty"`
	// Sent when collected (every few hours), not with every push.
	Inventory *Inventory `json:"inventory,omitempty"`
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

// LogsRequest carries new log lines from the files and journal the server's
// administrator chose to ship (logs.conf). Sent apart from metrics, at most
// every few seconds.
type LogsRequest struct {
	Entries []LogEntry `json:"entries"`
}

// LogEntry is one log line. Level is detected by the agent (journal
// priority, or a level word in the line) and may be empty.
type LogEntry struct {
	TimestampNs int64  `json:"ts"`
	Source      string `json:"source"`
	Level       string `json:"level,omitempty"`
	Line        string `json:"line"`
}

// LogsResponse says how many lines were kept. Ingest drops lines over the
// host's rate limit rather than failing the request.
type LogsResponse struct {
	Accepted int `json:"accepted"`
	Dropped  int `json:"dropped"`
}
