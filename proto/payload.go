// Package proto is the wire contract between the agent and ingest (JSON, v1).
//
// Agents in the field run old versions for a long time, so changes here must
// stay backward compatible: add optional fields, never rename or repurpose one.
package proto

// RegisterRequest is sent once, by `sentinel-agent register`, with the install key.
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
	// LatestVersion and DownloadURL drive `sentinel-agent update`. Binaries
	// live at <DownloadURL>/agent/<LatestVersion>/sentinel-agent-<os>-<arch>.
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
	// Network devices this agent polls over SNMP for its site. Their
	// credentials are in here: the agent keeps config in memory only.
	Devices []NetworkDevice `json:"devices,omitempty"`
	// Address ranges to scan once for SNMP devices.
	Discoveries []NetworkDiscovery `json:"discoveries,omitempty"`
	// IPDR receivers, on the organisation's evidence collector only.
	Evidence *EvidenceConfig `json:"evidence,omitempty"`
}

// NetworkDiscovery asks the agent to look for SNMP devices in a range.
type NetworkDiscovery struct {
	ID         string         `json:"id"`
	CIDR       string         `json:"cidr"`
	Port       int            `json:"port,omitempty"` // 161 unless given
	Credential SNMPCredential `json:"credential"`
}

// DiscoveryResult is a scan's progress; Done marks the last one.
type DiscoveryResult struct {
	ID      string             `json:"id"`
	Scanned int                `json:"scanned"`
	Total   int                `json:"total"`
	Done    bool               `json:"done,omitempty"`
	Error   string             `json:"error,omitempty"`
	Found   []DiscoveredDevice `json:"found,omitempty"`
}

type DiscoveredDevice struct {
	Address  string `json:"address"`
	SysName  string `json:"sys_name,omitempty"`
	SysDescr string `json:"sys_descr,omitempty"`
	ObjectID string `json:"object_id,omitempty"`
	Profile  string `json:"profile,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
}

// NetworkDevice is a switch, firewall or other device this agent polls.
type NetworkDevice struct {
	ID         string         `json:"id"`
	Address    string         `json:"address"`           // host or host:port (161)
	Profile    string         `json:"profile,omitempty"` // pinned; empty detects it
	Credential SNMPCredential `json:"credential"`
}

// SNMPCredential is a v1/v2c community, a v3 user, or (Version "proxmox")
// a Proxmox VE API token.
type SNMPCredential struct {
	Version      string `json:"version"` // 1, 2c, 3, proxmox
	Community    string `json:"community,omitempty"`
	Username     string `json:"username,omitempty"`
	AuthProtocol string `json:"auth_protocol,omitempty"`
	AuthPassword string `json:"auth_password,omitempty"`
	PrivProtocol string `json:"priv_protocol,omitempty"`
	PrivPassword string `json:"priv_password,omitempty"`
	Context      string `json:"context,omitempty"`
	// Proxmox VE: PVEAPIToken=<TokenUser>!<TokenName>=<TokenValue>.
	TokenUser   string `json:"token_user,omitempty"`
	TokenName   string `json:"token_name,omitempty"`
	TokenValue  string `json:"token_value,omitempty"`
	InsecureTLS bool   `json:"insecure_tls,omitempty"` // Proxmox's default self-signed certificate
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
// samples sentinel_check_up / sentinel_check_latency_seconds; this carries
// the human-readable detail for alert messages and the dashboard.
type CheckResult struct {
	ID          string     `json:"id"`
	OK          bool       `json:"ok"`
	Detail      string     `json:"detail,omitempty"`
	LatencyMs   float64    `json:"latency_ms,omitempty"`
	TimestampMs int64      `json:"ts"`
	Diagnosis   *Diagnosis `json:"diagnosis,omitempty"`
	// Browser checks: a JPEG of the page when it starts failing (and every
	// few minutes while it keeps failing).
	Screenshot []byte `json:"screenshot,omitempty"`
}

// Diagnosis is what the agent found out when a network check failed: how
// the name resolved, whether each address accepts a connection, and the
// network path towards it. Summary is one line for alerts.
type Diagnosis struct {
	Summary  string        `json:"summary"`
	DNS      *DNSStep      `json:"dns,omitempty"`
	Connect  []ConnectStep `json:"connect,omitempty"`
	Path     []Hop         `json:"path,omitempty"`
	PathNote string        `json:"path_note,omitempty"`
}

type DNSStep struct {
	Host      string   `json:"host"`
	Addresses []string `json:"addresses,omitempty"`
	ElapsedMs float64  `json:"elapsed_ms"`
	Error     string   `json:"error,omitempty"`
}

type ConnectStep struct {
	Address   string  `json:"address"`
	OK        bool    `json:"ok"`
	ElapsedMs float64 `json:"elapsed_ms"`
	Error     string  `json:"error,omitempty"`
}

// Hop is one router on the path; Address is empty when it didn't answer.
type Hop struct {
	TTL     int     `json:"ttl"`
	Address string  `json:"address,omitempty"`
	RttMs   float64 `json:"rtt_ms,omitempty"`
	Reached bool    `json:"reached,omitempty"`
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
	EventLog []string `json:"eventlog,omitempty"`
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
// (sentinel_<thing>_<unit>, counters end in _total).
type Sample struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
	Value  float64           `json:"value"`
}

// Batch is everything collected in one tick.
type Batch struct {
	TimestampMs int64    `json:"ts"`
	Samples     []Sample `json:"samples"`
	// Network device polls in this tick. Their samples are in Samples,
	// labelled device_id; ingest files them under the device.
	Network []NetworkPoll `json:"network,omitempty"`
	// Progress of network discoveries.
	Discoveries []DiscoveryResult `json:"discoveries,omitempty"`
	// SNMP traps received from the devices this agent polls.
	Traps []Trap `json:"traps,omitempty"`
}

// Trap is one SNMP trap or inform. The community or v3 credentials it came
// with were checked by the agent and are never sent on.
type Trap struct {
	TimeMs   int64             `json:"ts"`
	Source   string            `json:"source"`  // the sender's IP address
	Version  string            `json:"version"` // 1, 2c, 3
	OID      string            `json:"oid"`     // snmpTrapOID (v1 traps converted per RFC 3584)
	Varbinds map[string]string `json:"varbinds,omitempty"`
}

// NetworkPoll is what one poll of a device found besides its samples.
type NetworkPoll struct {
	DeviceID   string            `json:"device_id"`
	OK         bool              `json:"ok"` // the device answered SNMP
	Error      string            `json:"error,omitempty"`
	Profile    string            `json:"profile,omitempty"`
	DurationMs int64             `json:"duration_ms,omitempty"`
	System     *NetworkSystem    `json:"system,omitempty"`
	Inventory  map[string]string `json:"inventory,omitempty"`
	// Full is an inventory poll: Interfaces and Neighbors are complete and
	// replace what ingest had (on other polls they're absent).
	Full       bool               `json:"full,omitempty"`
	Interfaces []NetworkInterface `json:"interfaces,omitempty"`
	Neighbors  []NetworkNeighbor  `json:"neighbors,omitempty"`
}

type NetworkSystem struct {
	Descr     string  `json:"descr,omitempty"`
	ObjectID  string  `json:"object_id,omitempty"`
	Name      string  `json:"name,omitempty"`
	Contact   string  `json:"contact,omitempty"`
	Location  string  `json:"location,omitempty"`
	UptimeSec float64 `json:"uptime_sec,omitempty"`
	Vendor    string  `json:"vendor,omitempty"`
}

type NetworkInterface struct {
	Index      int    `json:"index"`
	Name       string `json:"name"`
	Descr      string `json:"descr,omitempty"`
	Alias      string `json:"alias,omitempty"`
	Type       int    `json:"type,omitempty"`
	SpeedBps   uint64 `json:"speed_bps,omitempty"`
	MTU        int    `json:"mtu,omitempty"`
	MAC        string `json:"mac,omitempty"`
	AdminUp    bool   `json:"admin_up"`
	OperStatus int    `json:"oper_status,omitempty"`
}

type NetworkNeighbor struct {
	LocalPort      string `json:"local_port"`
	RemoteSysName  string `json:"remote_sys_name,omitempty"`
	RemotePortID   string `json:"remote_port_id,omitempty"`
	RemotePortDesc string `json:"remote_port_desc,omitempty"`
	RemoteChassis  string `json:"remote_chassis_id,omitempty"`
	RemoteMgmtAddr string `json:"remote_mgmt_addr,omitempty"`
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
	// Hardware addresses of the real interfaces (lowercase, colon
	// separated), so a switch's LLDP neighbour can be matched to the server.
	MACs        []string `json:"macs,omitempty"`
	CPUCores    int      `json:"cpu_cores,omitempty"`
	MemoryBytes uint64   `json:"memory_bytes,omitempty"`
	// TrapPort is the UDP port the agent receives SNMP traps on (162, or
	// 1162 without the right to bind it); 0 when it isn't listening.
	TrapPort int `json:"trap_port,omitempty"`
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
