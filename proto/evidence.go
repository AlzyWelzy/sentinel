package proto

import "time"

// IPDR evidence: what a site agent receives from its network gear (syslog,
// sFlow, NetFlow, IPFIX) and reads from it (MAC and ARP tables), sent to
// ingest's /v1/evidence apart from metrics. Ingest parses it and stores it
// per organisation in ClickHouse.

// EvidenceConfig turns the agent's receivers on. It comes with the agent
// config only for the server an organisation chose as its evidence
// collector, while IPDR is on. A zero port is off.
type EvidenceConfig struct {
	SyslogUDP int `json:"syslog_udp,omitempty"`
	SyslogTCP int `json:"syslog_tcp,omitempty"`
	SFlow     int `json:"sflow,omitempty"`
	NetFlow   int `json:"netflow,omitempty"` // v5, v9 (IPFIX accepted too)
	IPFIX     int `json:"ipfix,omitempty"`
	// Senders accepted besides the devices this agent polls (CIDRs).
	Allow []string `json:"allow,omitempty"`
	// MAC/ARP table snapshots of the polled devices, every this many
	// seconds (0: off).
	FDBIntervalSeconds int `json:"fdb_interval_seconds,omitempty"`
}

// EvidenceBatch is one delivery. Records keep the time the agent received
// them: that, never the device's own clock, is what evidence is filed by.
type EvidenceBatch struct {
	ID    string        `json:"id"` // dedupes a batch delivered twice
	Logs  []LogRecord   `json:"logs,omitempty"`
	Flows []FlowRecord  `json:"flows,omitempty"`
	FDB   []FDBEntry    `json:"fdb,omitempty"`
	Stats EvidenceStats `json:"stats"`
}

type LogRecord struct {
	At    time.Time `json:"at"`
	Src   string    `json:"src"`   // sender IP
	Proto string    `json:"proto"` // udp, tcp
	Line  string    `json:"line"`
}

type FlowRecord struct {
	At       time.Time `json:"at"`
	Start    time.Time `json:"start,omitzero"`
	End      time.Time `json:"end,omitzero"`
	Exporter string    `json:"exporter"`
	Type     string    `json:"type"` // sflow, netflow5, netflow9, ipfix
	Sampling uint32    `json:"sampling,omitempty"`
	Proto    uint8     `json:"proto"`
	SrcIP    string    `json:"src_ip"`
	DstIP    string    `json:"dst_ip"`
	SrcPort  uint16    `json:"src_port,omitempty"`
	DstPort  uint16    `json:"dst_port,omitempty"`
	InIf     uint32    `json:"in_if,omitempty"`
	OutIf    uint32    `json:"out_if,omitempty"`
	Bytes    uint64    `json:"bytes"`
	Packets  uint64    `json:"packets"`
	TCPFlags uint8     `json:"tcp_flags,omitempty"`
	VLAN     uint16    `json:"vlan,omitempty"`
	SrcMAC   string    `json:"src_mac,omitempty"`
	DstMAC   string    `json:"dst_mac,omitempty"`
}

// FDBEntry is one row of a device's forwarding (MAC) or ARP table.
type FDBEntry struct {
	At       time.Time `json:"at"`
	DeviceID string    `json:"device_id"`
	Port     string    `json:"port,omitempty"`
	IfIndex  uint32    `json:"if_index,omitempty"`
	VLAN     uint16    `json:"vlan,omitempty"`
	MAC      string    `json:"mac"`
	IP       string    `json:"ip,omitempty"`
	Source   string    `json:"source"` // fdb, arp
}

// EvidenceStats is the receiver's health since the last batch.
type EvidenceStats struct {
	Listening []string `json:"listening,omitempty"`
	Dropped   uint64   `json:"dropped,omitempty"`  // full spool (UDP) or unknown senders
	Refused   uint64   `json:"refused,omitempty"`  // senders not allowed
	FlowErrs  uint64   `json:"flow_errs,omitempty"`
	SpoolMB   float64  `json:"spool_mb,omitempty"` // waiting for ingest
}

type EvidenceResponse struct {
	Accepted int `json:"accepted"`
}
