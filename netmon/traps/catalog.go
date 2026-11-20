// Package traps knows what SNMP traps mean: which ones open an alert, which
// close it, and which are only recorded. Ingest classifies each trap with it;
// the alerter turns the classified traps into alerts; the API lists the rules
// as network conditions (keys must match services/netconditions.py).
//
//   - Paired traps open an alert and their "up" trap closes it (VPN tunnel
//     down/up, AP down/up, BGP backward transition/established, ...). The
//     identity labels (tunnel, AP, peer) tell one tunnel from another.
//   - Single traps (CPU high, fan failure, ...) have no clearing trap: their
//     alert clears after the rule's ClearsAfter without a repeat.
//
// OIDs are from FORTINET-CORE-MIB / FORTINET-FORTIGATE-MIB (2025-04) and the
// standard MIBs; FortiGate titles match FortiOS's SNMP event list.
package traps

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Action is what a trap does to its rule's alert.
type Action string

const (
	Event Action = "event" // recorded only
	Open  Action = "open"  // opens (or refreshes) the alert for its identity
	Clear Action = "clear" // closes it
)

// Rule is an alert condition driven by traps.
type Rule struct {
	Key         string        // network condition key ("trap_vpn_tunnel_down")
	Name        string        // shown in the rule form and alerts
	Severity    string        // default when recommended
	ClearsAfter time.Duration // 0: only its clearing trap closes it
	Off         bool          // not recommended: noisy on busy firewalls
	Help        string
}

// Var is a varbind kept as a label. Key labels are part of the alert's
// identity (one per tunnel, AP, peer). Index means the value is the varbind's
// OID suffix (a table index such as a BGP peer address), not its value.
type Var struct {
	Label, OID string
	Key, Index bool
}

// Type is one trap OID.
type Type struct {
	OID, Name, Title string // Name: MIB name; Title: plain-English name
	Vendor           string
	Rule             string // Rule.Key it opens/clears ("" = event only)
	Action           Action
	Vars             []Var
	// Classify overrides Action from the trap's values (one OID used for both
	// failure and recovery).
	Classify func(vb map[string]string) Action
	Severity string // event severity when it changes no alert
}

const (
	fgTrap = "1.3.6.1.4.1.12356.101.2.0."
	fnTrap = "1.3.6.1.4.1.12356.100.1.3.0."
	fmTrap = "1.3.6.1.4.1.12356.101.6.0."

	vbSysName   = "1.3.6.1.2.1.1.5.0"
	vbSerial    = "1.3.6.1.4.1.12356.100.1.1.1"
	vbGenMsg    = "1.3.6.1.4.1.12356.100.1.3.1.1"
	vbIfIndex   = "1.3.6.1.2.1.2.2.1.1"
	vbFdbPort   = "1.3.6.1.2.1.17.7.1.2.2.1.2" // dot1qTpFdbPort.<fdb id>.<MAC as 6 numbers>
	vbIfName    = "1.3.6.1.2.1.31.1.1.1.1"
	vbVPNPhase1 = "1.3.6.1.4.1.12356.101.12.3.4"
	vbVPNRemote = "1.3.6.1.4.1.12356.101.12.3.3"

	// SNMPv2 notification header varbinds (RFC 3416).
	SysUpTime = "1.3.6.1.2.1.1.3.0"
	TrapOID   = "1.3.6.1.6.3.1.1.4.1.0"
	// snmpTrapCommunity: never stored or shown.
	trapCommunity = "1.3.6.1.6.3.18.1.4.0"
)

// Rules lists every trap-driven condition.
var Rules = []Rule{
	{Key: "trap_vpn_tunnel_down", Name: "VPN tunnel down (trap)", Severity: "critical",
		Help: "FortiGate “VPN tunnel is down”; closes on “VPN tunnel is up”."},
	{Key: "trap_ha_member_down", Name: "HA cluster member down", Severity: "critical",
		Help: "FortiGate “HA cluster member down”; closes on “HA cluster member up”."},
	{Key: "trap_ha_failover", Name: "HA failover", Severity: "warning", ClearsAfter: time.Hour,
		Help: "FortiGate “HA cluster status change”: the primary unit changed."},
	{Key: "trap_ha_heartbeat", Name: "HA heartbeat failure", Severity: "critical", ClearsAfter: time.Hour,
		Help: "FortiGate “HA heartbeat interface failure”."},
	{Key: "trap_ap_down", Name: "Wireless AP down", Severity: "warning",
		Help: "FortiGate “AP is down”; closes on “AP is up”."},
	{Key: "trap_fortiswitch_down", Name: "FortiSwitch down", Severity: "warning",
		Help: "FortiGate “FortiSwitch controller session is down”; closes on “… is up”."},
	{Key: "trap_bgp_down", Name: "BGP session down (trap)", Severity: "critical",
		Help: "BGP4-MIB bgpBackwardTransition; closes on bgpEstablished."},
	{Key: "trap_ospf_down", Name: "OSPF neighbour down (trap)", Severity: "warning",
		Help: "OSPF-MIB neighbour state change (normal and virtual); closes when the neighbour is Full again."},
	{Key: "trap_lb_real_server_down", Name: "Load balancer real server down", Severity: "warning", ClearsAfter: 30 * time.Minute,
		Help: "FortiGate “Load balance real-server is down” (FortiOS sends no “up” trap)."},
	{Key: "trap_power_supply", Name: "Power supply failure", Severity: "critical",
		Help: "FortiGate power-supply event; closes when the unit reports the supply restored."},
	{Key: "trap_fan_failure", Name: "Fan failure", Severity: "critical", ClearsAfter: time.Hour, Help: "FortiGate fan failure."},
	{Key: "trap_temperature_high", Name: "Temperature too high", Severity: "critical", ClearsAfter: time.Hour,
		Help: "FortiGate “snmp-event::temperature-high”."},
	{Key: "trap_voltage", Name: "Voltage out of range", Severity: "critical", ClearsAfter: time.Hour,
		Help: "FortiGate “snmp-event::voltage-alert”."},
	{Key: "trap_bypass_mode", Name: "Interface bypass mode", Severity: "critical",
		Help: "FortiGate bypass mode (traffic isn't inspected); closes when it leaves bypass mode."},
	{Key: "trap_cpu_high", Name: "CPU usage too high (trap)", Severity: "warning", ClearsAfter: 30 * time.Minute,
		Help: "FortiGate “CPU usage too high” and “Per CPU usage is high”."},
	{Key: "trap_memory_low", Name: "Memory low (trap)", Severity: "warning", ClearsAfter: 30 * time.Minute,
		Help: "FortiGate “Available memory is low”."},
	{Key: "trap_log_disk_low", Name: "Log disk space low", Severity: "warning", ClearsAfter: 6 * time.Hour,
		Help: "FortiGate “Available log space is low”."},
	{Key: "trap_conserve_mode", Name: "Conserve mode", Severity: "critical", ClearsAfter: 30 * time.Minute,
		Help: "FortiGate “AV system enters conserve mode” (memory exhausted)."},
	{Key: "trap_inspection_bypassed", Name: "Inspection bypassed", Severity: "critical", ClearsAfter: 30 * time.Minute,
		Help: "FortiGate “AV bypass happens” and “IPS network buffer is full” (fail-open)."},
	{Key: "trap_faz_disconnected", Name: "FortiAnalyzer disconnected", Severity: "warning", ClearsAfter: time.Hour,
		Help: "FortiGate “Disconnected from FortiAnalyzer”."},
	{Key: "trap_dhcp", Name: "DHCP problem", Severity: "warning", ClearsAfter: time.Hour,
		Help: "FortiGate “DHCP addresses at limit” (also IP conflicts and NAKs)."},
	{Key: "trap_ip_pool", Name: "IP pool usage high", Severity: "warning",
		Help: "FortiGate “About IP pool usage”; closes on its clear trap."},
	{Key: "trap_ip_conflict", Name: "IP address conflict", Severity: "warning", ClearsAfter: time.Hour,
		Help: "FortiGate “snmp-event::interface” (IP conflict)."},
	{Key: "trap_restart", Name: "Device restarted (trap)", Severity: "warning", ClearsAfter: 30 * time.Minute,
		Help: "coldStart / warmStart. Polling also notices reboots."},
	{Key: "trap_auth_failure", Name: "SNMP authentication failure", Severity: "warning", ClearsAfter: 30 * time.Minute, Off: true,
		Help: "authenticationFailure. Often scanners; not recommended by default."},
	{Key: "trap_link_down", Name: "Interface down (trap)", Severity: "warning", Off: true,
		Help: "linkDown, closes on linkUp. The polled “Interface down” condition covers this without alarms from unused ports."},
	{Key: "trap_ips_attack", Name: "IPS attack detected", Severity: "warning", ClearsAfter: 30 * time.Minute, Off: true,
		Help: "FortiGate “IPS detected an attack / an anomaly”. Very frequent on busy firewalls; always recorded as events."},
	{Key: "trap_virus", Name: "Virus detected", Severity: "warning", ClearsAfter: 30 * time.Minute, Off: true,
		Help: "FortiGate “AV detected virus”. Always recorded as events."},
	{Key: "trap_security_level", Name: "Security level changed", Severity: "warning", ClearsAfter: time.Hour, Off: true,
		Help: "FortiGate “snmp-event::security_level_change”."},
}

var (
	vVPN    = []Var{{Label: "tunnel", OID: vbVPNPhase1, Key: true}, {Label: "remote", OID: vbVPNRemote, Key: true}}
	vSerial = []Var{{Label: "serial", OID: vbSerial}}
	vAP     = []Var{{Label: "ap", OID: "1.3.6.1.4.1.12356.101.14.1.3"}, {Label: "ap_serial", OID: "1.3.6.1.4.1.12356.101.14.1.2", Key: true}}
	vSwitch = []Var{{Label: "switch", OID: "1.3.6.1.4.1.12356.101.15.1.3"}, {Label: "switch_serial", OID: "1.3.6.1.4.1.12356.101.15.1.2", Key: true}}
	vIPS    = []Var{{Label: "signature", OID: "1.3.6.1.4.1.12356.101.9.3.1"}, {Label: "source", OID: "1.3.6.1.4.1.12356.101.9.3.2"},
		{Label: "message", OID: "1.3.6.1.4.1.12356.101.9.3.3"}}
	vMsg  = []Var{{Label: "message", OID: vbGenMsg}}
	vBGP  = []Var{{Label: "peer", OID: "1.3.6.1.2.1.15.3.1", Key: true, Index: true}}
	vOSPF = []Var{{Label: "neighbor", OID: "1.3.6.1.2.1.14.10.1.6", Key: true, Index: true}}
	vFdb  = []Var{{Label: "mac", OID: vbFdbPort, Index: true}, {Label: "port", OID: vbFdbPort}}
	vLink = []Var{{Label: "ifindex", OID: vbIfIndex, Key: true}, {Label: "ifname", OID: vbIfName}}
)

func with(vs []Var, extra ...Var) []Var { return append(append([]Var{}, vs...), extra...) }

func fixed(label, value string) Var { return Var{Label: label, OID: "=" + value} }

// Catalog lists every known trap.
var Catalog = []Type{
	// FortiGate (FORTINET-FORTIGATE-MIB)
	{OID: fgTrap + "301", Name: "fgTrapVpnTunUp", Title: "VPN tunnel is up", Vendor: "fortinet", Rule: "trap_vpn_tunnel_down", Action: Clear, Vars: vVPN},
	{OID: fgTrap + "302", Name: "fgTrapVpnTunDown", Title: "VPN tunnel is down", Vendor: "fortinet", Rule: "trap_vpn_tunnel_down", Action: Open, Vars: vVPN},
	{OID: fgTrap + "401", Name: "fgTrapHaSwitch", Title: "HA cluster status change", Vendor: "fortinet", Rule: "trap_ha_failover", Action: Open, Vars: vSerial},
	{OID: fgTrap + "402", Name: "fgTrapHaStateChange", Title: "HA state change", Vendor: "fortinet", Severity: "warning", Vars: vSerial},
	{OID: fgTrap + "403", Name: "fgTrapHaHBFail", Title: "HA heartbeat interface failure", Vendor: "fortinet", Rule: "trap_ha_heartbeat", Action: Open, Vars: vSerial},
	{OID: fgTrap + "404", Name: "fgTrapHaMemberDown", Title: "HA cluster member down", Vendor: "fortinet", Rule: "trap_ha_member_down", Action: Open, Vars: vSerial},
	{OID: fgTrap + "405", Name: "fgTrapHaMemberUp", Title: "HA cluster member up", Vendor: "fortinet", Rule: "trap_ha_member_down", Action: Clear, Vars: vSerial},
	{OID: fgTrap + "503", Name: "fgTrapIpsSignature", Title: "IPS detected an attack", Vendor: "fortinet", Rule: "trap_ips_attack", Action: Open,
		Vars: with(vIPS, fixed("what", "attack"))},
	{OID: fgTrap + "504", Name: "fgTrapIpsAnomaly", Title: "IPS detected an anomaly", Vendor: "fortinet", Rule: "trap_ips_attack", Action: Open,
		Vars: with(vIPS, fixed("what", "anomaly"))},
	{OID: fgTrap + "505", Name: "fgTrapIpsPkgUpdate", Title: "IPS package updated", Vendor: "fortinet", Severity: "info"},
	{OID: fgTrap + "506", Name: "fgTrapIpsFailOpen", Title: "IPS network buffer is full", Vendor: "fortinet", Rule: "trap_inspection_bypassed", Action: Open,
		Vars: []Var{fixed("what", "IPS network buffer is full: traffic passes uninspected"), {Label: "kind", OID: "=ips", Key: true}}},
	{OID: fgTrap + "601", Name: "fgTrapAvVirus", Title: "AV detected virus", Vendor: "fortinet", Rule: "trap_virus", Action: Open,
		Vars: []Var{{Label: "virus", OID: "1.3.6.1.4.1.12356.101.8.3.1"}}},
	{OID: fgTrap + "602", Name: "fgTrapAvOversize", Title: "AV detected oversized file", Vendor: "fortinet", Severity: "info"},
	{OID: fgTrap + "603", Name: "fgTrapAvPattern", Title: "AV detected file matching pattern", Vendor: "fortinet", Severity: "info"},
	{OID: fgTrap + "604", Name: "fgTrapAvFragmented", Title: "AV detected fragmented file", Vendor: "fortinet", Severity: "info"},
	{OID: fgTrap + "605", Name: "fgTrapAvEnterConserve", Title: "AV system enters conserve mode", Vendor: "fortinet", Rule: "trap_conserve_mode", Action: Open},
	{OID: fgTrap + "606", Name: "fgTrapAvBypass", Title: "AV bypass happens", Vendor: "fortinet", Rule: "trap_inspection_bypassed", Action: Open,
		Vars: []Var{fixed("what", "antivirus bypassed: files pass unscanned"), {Label: "kind", OID: "=av", Key: true}}},
	{OID: fgTrap + "607", Name: "fgTrapAvOversizePass", Title: "AV oversized files passed", Vendor: "fortinet", Severity: "info"},
	{OID: fgTrap + "608", Name: "fgTrapAvOversizeBlock", Title: "AV oversized files blocked", Vendor: "fortinet", Severity: "info"},
	{OID: fgTrap + "701", Name: "fgTrapFazDisconnect", Title: "Disconnected from FortiAnalyzer", Vendor: "fortinet", Rule: "trap_faz_disconnected", Action: Open},
	{OID: fgTrap + "702", Name: "fgTrapFaz", Title: "FortiAnalyzer failover (snmp-event::faz)", Vendor: "fortinet", Severity: "warning",
		Vars: []Var{{Label: "type", OID: "1.3.6.1.4.1.12356.101.6.2.4"}}},
	{OID: fgTrap + "801", Name: "fgTrapWcApUp", Title: "AP is up", Vendor: "fortinet", Rule: "trap_ap_down", Action: Clear, Vars: vAP},
	{OID: fgTrap + "802", Name: "fgTrapWcApDown", Title: "AP is down", Vendor: "fortinet", Rule: "trap_ap_down", Action: Open, Vars: vAP},
	{OID: fgTrap + "901", Name: "fgTrapFcSwUp", Title: "FortiSwitch controller session is up", Vendor: "fortinet", Rule: "trap_fortiswitch_down", Action: Clear, Vars: vSwitch},
	{OID: fgTrap + "902", Name: "fgTrapFcSwDown", Title: "FortiSwitch controller session is down", Vendor: "fortinet", Rule: "trap_fortiswitch_down", Action: Open, Vars: vSwitch},
	{OID: fgTrap + "1101", Name: "fgTrapServerLoadBalanceRealServerDown", Title: "Load balance real-server is down", Vendor: "fortinet",
		Rule: "trap_lb_real_server_down", Action: Open,
		Vars: []Var{{Label: "server", OID: "1.3.6.1.4.1.12356.101.16.1.1", Key: true}, {Label: "vserver", OID: "1.3.6.1.4.1.12356.101.16.1.2", Key: true}}},
	{OID: fgTrap + "1102", Name: "fgTrapPerCpuHigh", Title: "Per CPU usage is high", Vendor: "fortinet", Rule: "trap_cpu_high", Action: Open,
		Vars: []Var{{Label: "details", OID: "1.3.6.1.4.1.12356.101.4.4.4.1"}}},
	{OID: fgTrap + "1201", Name: "fgTrapDeviceNew", Title: "A new device is found", Vendor: "fortinet", Severity: "info",
		Vars: []Var{{Label: "mac", OID: "1.3.6.1.4.1.12356.101.18.1.1"}}},
	{OID: fgTrap + "1301", Name: "fgTrapDhcp", Title: "DHCP addresses at limit", Vendor: "fortinet", Rule: "trap_dhcp", Action: Open,
		Vars: []Var{{Label: "ifname", OID: vbIfName, Key: true}, {Label: "what", OID: "1.3.6.1.4.1.12356.101.23.3.1", Key: true},
			{Label: "message", OID: "1.3.6.1.4.1.12356.101.23.3.2"}}},
	{OID: fgTrap + "1401", Name: "fgTrapPoolUsage", Title: "About IP pool usage", Vendor: "fortinet", Rule: "trap_ip_pool",
		Vars: []Var{{Label: "pool", OID: "1.3.6.1.4.1.12356.101.5.3.2.1.1.1", Key: true}, {Label: "usage", OID: "1.3.6.1.4.1.12356.101.5.3.3.2"}},
		Classify: func(vb map[string]string) Action {
			if v, ok := varValue(vb, "1.3.6.1.4.1.12356.101.5.3.3.1"); ok && enumValue(v) == 2 {
				return Clear
			}
			return Open
		}},
	{OID: fgTrap + "1501", Name: "fgTrapSlbc", Title: "Chassis (SLBC) event", Vendor: "fortinet", Severity: "warning",
		Vars: []Var{{Label: "message", OID: "1.3.6.1.4.1.12356.101.25.2.2"}}},
	{OID: fgTrap + "1601", Name: "fgTrapInterface", Title: "snmp-event::interface (IP conflict)", Vendor: "fortinet", Rule: "trap_ip_conflict", Action: Open,
		Vars: []Var{{Label: "ifname", OID: vbIfName, Key: true}, {Label: "message", OID: vbGenMsg}}},
	{OID: fgTrap + "1701", Name: "fgTrapDio", Title: "Digital I/O event", Vendor: "fortinet", Severity: "info", Vars: vMsg},
	// FortiManager-related (fgMgmt)
	{OID: fmTrap + "1000", Name: "fgFmTrapDeployComplete", Title: "FortiManager deploy complete", Vendor: "fortinet", Severity: "info"},
	{OID: fmTrap + "1002", Name: "fgFmTrapDeployInProgress", Title: "FortiManager deploy in progress", Vendor: "fortinet", Severity: "info"},
	{OID: fmTrap + "1003", Name: "fgFmTrapConfChange", Title: "Configuration change (FM trap)", Vendor: "fortinet", Severity: "info"},
	{OID: fmTrap + "1004", Name: "fgFmTrapIfChange", Title: "Interface IP change (FM trap)", Vendor: "fortinet", Severity: "info",
		Vars: []Var{{Label: "ifname", OID: vbIfName}, {Label: "ip", OID: "1.3.6.1.4.1.12356.101.6.2.1"}}},
	// Fortinet common (FORTINET-CORE-MIB)
	{OID: fnTrap + "101", Name: "fnTrapCpuThreshold", Title: "CPU usage too high", Vendor: "fortinet", Rule: "trap_cpu_high", Action: Open},
	{OID: fnTrap + "102", Name: "fnTrapMemThreshold", Title: "Available memory is low", Vendor: "fortinet", Rule: "trap_memory_low", Action: Open, Vars: vMsg},
	{OID: fnTrap + "103", Name: "fnTrapLogDiskThreshold", Title: "Available log space is low", Vendor: "fortinet", Rule: "trap_log_disk_low", Action: Open},
	{OID: fnTrap + "104", Name: "fnTrapTempHigh", Title: "snmp-event::temperature-high", Vendor: "fortinet", Rule: "trap_temperature_high", Action: Open},
	{OID: fnTrap + "105", Name: "fnTrapVoltageOutOfRange", Title: "snmp-event::voltage-alert", Vendor: "fortinet", Rule: "trap_voltage", Action: Open},
	{OID: fnTrap + "106", Name: "fnTrapPowerSupply", Title: "snmp-event::power-supply", Vendor: "fortinet", Rule: "trap_power_supply", Vars: vMsg,
		Classify: func(vb map[string]string) Action {
			if v, ok := varValue(vb, vbGenMsg); ok && powerRestored.MatchString(v) {
				return Clear
			}
			return Open
		}},
	{OID: fnTrap + "107", Name: "fnTrapAmcIfBypassMode", Title: "AMC interface bypass mode", Vendor: "fortinet", Rule: "trap_bypass_mode", Action: Open},
	{OID: fnTrap + "108", Name: "fnTrapFanFailure", Title: "Fan failure", Vendor: "fortinet", Rule: "trap_fan_failure", Action: Open},
	{OID: fnTrap + "109", Name: "fnTrapIfEnterBypassMode", Title: "Interfaces entered bypass mode", Vendor: "fortinet", Rule: "trap_bypass_mode", Action: Open},
	{OID: fnTrap + "110", Name: "fnTrapIfExitBypassMode", Title: "Interfaces left bypass mode", Vendor: "fortinet", Rule: "trap_bypass_mode", Action: Clear},
	{OID: fnTrap + "111", Name: "fnTrapSecurityLevelChange", Title: "snmp-event::security_level_change", Vendor: "fortinet", Rule: "trap_security_level", Action: Open, Vars: vMsg},
	{OID: fnTrap + "201", Name: "fnTrapIpChange", Title: "Interface IP address changed", Vendor: "fortinet", Severity: "info",
		Vars: []Var{{Label: "ifindex", OID: vbIfIndex}}},
	{OID: fnTrap + "999", Name: "fnTrapTest", Title: "Test trap", Vendor: "fortinet", Severity: "info"},

	// Arista (ARISTA-BRIDGE-EXT-MIB): MAC table notifications, normal switch
	// chatter, kept as info events.
	{OID: "1.3.6.1.4.1.30065.3.2.0.1", Name: "aristaMacMove", Title: "MAC address moved to another port", Vendor: "arista", Severity: "info", Vars: vFdb},
	{OID: "1.3.6.1.4.1.30065.3.2.0.2", Name: "aristaMacLearn", Title: "MAC address learned", Vendor: "arista", Severity: "info", Vars: vFdb},
	{OID: "1.3.6.1.4.1.30065.3.2.0.3", Name: "aristaMacAge", Title: "MAC address aged out", Vendor: "arista", Severity: "info", Vars: vFdb},

	// Standard
	{OID: "1.3.6.1.6.3.1.1.5.1", Name: "coldStart", Title: "Device restarted (cold start)", Rule: "trap_restart", Action: Open, Vars: []Var{fixed("trap", "cold start")}},
	{OID: "1.3.6.1.6.3.1.1.5.2", Name: "warmStart", Title: "Device restarted (warm start)", Rule: "trap_restart", Action: Open, Vars: []Var{fixed("trap", "warm start")}},
	{OID: "1.3.6.1.6.3.1.1.5.3", Name: "linkDown", Title: "Interface went down", Rule: "trap_link_down", Action: Open, Vars: vLink},
	{OID: "1.3.6.1.6.3.1.1.5.4", Name: "linkUp", Title: "Interface came up", Rule: "trap_link_down", Action: Clear, Vars: vLink},
	{OID: "1.0.8802.1.1.2.0.0.1", Name: "lldpRemTablesChange", Title: "LLDP neighbours changed", Severity: "info"},
	{OID: "1.3.6.1.6.3.1.1.5.5", Name: "authenticationFailure", Title: "SNMP authentication failure", Rule: "trap_auth_failure", Action: Open},
	{OID: "1.3.6.1.2.1.15.0.1", Name: "bgpEstablished", Title: "BGP session established", Rule: "trap_bgp_down", Action: Clear, Vars: vBGP},
	{OID: "1.3.6.1.2.1.15.0.2", Name: "bgpBackwardTransition", Title: "BGP session left Established", Rule: "trap_bgp_down", Action: Open, Vars: vBGP},
	// SNMPv1-style BGP4-MIB numbering, still sent by some devices.
	{OID: "1.3.6.1.2.1.15.7.1", Name: "bgpEstablished", Title: "BGP session established", Rule: "trap_bgp_down", Action: Clear, Vars: vBGP},
	{OID: "1.3.6.1.2.1.15.7.2", Name: "bgpBackwardTransition", Title: "BGP session left Established", Rule: "trap_bgp_down", Action: Open, Vars: vBGP},
	{OID: "1.3.6.1.2.1.14.16.2.2", Name: "ospfNbrStateChange", Title: "OSPF neighbour state change", Rule: "trap_ospf_down",
		Vars: with(vOSPF, Var{Label: "state", OID: "1.3.6.1.2.1.14.10.1.6"}), Classify: ospfClassify("1.3.6.1.2.1.14.10.1.6")},
	{OID: "1.3.6.1.2.1.14.16.2.3", Name: "ospfVirtNbrStateChange", Title: "OSPF virtual neighbour state change", Rule: "trap_ospf_down",
		Vars:     []Var{{Label: "neighbor", OID: "1.3.6.1.2.1.14.11.1.5", Key: true, Index: true}, {Label: "state", OID: "1.3.6.1.2.1.14.11.1.5"}},
		Classify: ospfClassify("1.3.6.1.2.1.14.11.1.5")},
	{OID: "1.3.6.1.2.1.47.2.0.1", Name: "entConfigChange", Title: "Entity configuration changed", Severity: "info"},
}

var powerRestored = regexp.MustCompile(`(?i)restor|recover|normal|\bok\b|back`)

// ospfClassify: neighbour state 8 = full (healthy); 1 = down. Other states
// are transitions and change nothing.
func ospfClassify(stateOID string) func(map[string]string) Action {
	return func(vb map[string]string) Action {
		v, ok := varValue(vb, stateOID)
		if !ok {
			return Event
		}
		switch enumValue(v) {
		case 8:
			return Clear
		case 1:
			return Open
		}
		return Event
	}
}

var ospfStates = map[int]string{1: "down", 2: "attempt", 3: "init", 4: "two-way", 5: "exchange start", 6: "exchange", 7: "loading", 8: "full"}

var (
	byOID  = map[string]*Type{}
	byRule = map[string]*Rule{}
)

func init() {
	for i := range Catalog {
		byOID[Catalog[i].OID] = &Catalog[i]
	}
	for i := range Rules {
		byRule[Rules[i].Key] = &Rules[i]
	}
}

// RuleByKey finds a trap rule.
func RuleByKey(key string) (Rule, bool) {
	r, ok := byRule[key]
	if !ok {
		return Rule{}, false
	}
	return *r, true
}

// Normalize drops a leading dot.
func Normalize(oid string) string { return strings.TrimPrefix(strings.TrimSpace(oid), ".") }

// Lookup finds a trap by OID (v2c form, or a FortiGate v1 trap's
// <model enterprise>.0.<specific> form).
func Lookup(oid string) *Type {
	oid = Normalize(oid)
	if t, ok := byOID[oid]; ok {
		return t
	}
	// A FortiGate's v1 traps carry the model's sysObjectID as enterprise
	// (1.3.6.1.4.1.12356.101.1.<model>); RFC 3584 makes that
	// <enterprise>.0.<specific>, and the specific number is the trap's
	// number under fgTrap, fnTrap or fmTrap (they don't overlap).
	const models = "1.3.6.1.4.1.12356.101.1."
	if strings.HasPrefix(oid, models) {
		if i := strings.LastIndex(oid, ".0."); i >= len(models) {
			n := oid[i+3:]
			for _, p := range []string{fgTrap, fnTrap, fmTrap} {
				if t, ok := byOID[p+n]; ok {
					return t
				}
			}
		}
	}
	return nil
}

var enumRe = regexp.MustCompile(`(-?\d+)\)?\s*$`)

// enumValue reads an integer however it was printed: "2", "clear(2)".
func enumValue(v string) int {
	m := enumRe.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return -1
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// varFind finds a varbind by object OID. Notification objects come as the
// object itself, with ".0", or with a table index, so prefixes match too.
func varFind(vb map[string]string, oid string) (value, index string, ok bool) {
	keys := make([]string, 0, len(vb))
	for k := range vb {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic when several match
	for _, k := range keys {
		n := Normalize(k)
		if n == oid {
			return vb[k], "", true
		}
		if strings.HasPrefix(n, oid+".") {
			idx := strings.TrimPrefix(n, oid+".")
			if idx == "0" {
				idx = ""
			}
			return vb[k], idx, true
		}
	}
	return "", "", false
}

func varValue(vb map[string]string, oid string) (string, bool) {
	v, _, ok := varFind(vb, oid)
	return v, ok
}

// tableIndex: BGP4-MIB trap objects are bgpPeerTable columns
// (1.3.6.1.2.1.15.3.1.<column>.<peer IP>); OSPF neighbour columns are
// indexed by <IP>.<ifindex>.
func tableIndex(index string, ospf bool) string {
	parts := strings.Split(index, ".")
	if !ospf && len(parts) >= 5 {
		return strings.Join(parts[1:5], ".")
	}
	if ospf && len(parts) >= 4 {
		return strings.Join(parts[:4], ".")
	}
	return index
}

// fdbIndex splits a dot1qTpFdbTable index ("<fdb id>.<6 MAC octets>").
func fdbIndex(index string) (mac, vlan string) {
	parts := strings.Split(index, ".")
	if len(parts) != 7 {
		return index, ""
	}
	oct := make([]string, 6)
	for i, p := range parts[1:] {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return index, ""
		}
		oct[i] = fmt.Sprintf("%02x", n)
	}
	return strings.Join(oct, ":"), parts[0]
}

// Result is what one trap means.
type Result struct {
	Type     *Type // nil: not in the catalog
	Name     string
	Title    string
	Action   Action
	Rule     string // rule key, when Action isn't Event
	Severity string
	Labels   map[string]string // shown in the event and the alert's detail
	Identity string            // key labels, "tunnel=x remote=y": one alert line per identity
}

// Classify reads one trap: its OID and varbinds (OID -> printed value).
func Classify(oid string, vb map[string]string) Result {
	delete(vb, trapCommunity)
	delete(vb, "."+trapCommunity)
	t := Lookup(oid)
	if t == nil {
		return Result{Name: Normalize(oid), Title: "Trap " + Normalize(oid), Action: Event, Severity: "info", Labels: map[string]string{}}
	}
	labels, keys := map[string]string{}, []string{}
	for _, v := range t.Vars {
		var val string
		switch {
		case strings.HasPrefix(v.OID, "="):
			val = v.OID[1:]
		case v.Index:
			_, idx, ok := varFind(vb, v.OID)
			if !ok {
				continue
			}
			if v.OID == vbFdbPort {
				var vlan string
				val, vlan = fdbIndex(idx)
				if vlan != "" {
					labels["vlan"] = vlan
				}
				break
			}
			val = tableIndex(idx, strings.HasPrefix(v.OID, "1.3.6.1.2.1.14.10."))
		default:
			raw, ok := varValue(vb, v.OID)
			if !ok {
				continue
			}
			val = strings.Trim(strings.TrimSpace(raw), `"`)
		}
		if v.Label == "state" {
			if s, ok := ospfStates[enumValue(val)]; ok {
				val = s
			}
		}
		if v.Label == "what" && t.Name == "fgTrapDhcp" {
			val = map[int]string{1: "address pool exhausted", 2: "IP address conflict", 3: "NAK received"}[enumValue(val)]
		}
		labels[v.Label] = val
		if v.Key {
			keys = append(keys, v.Label+"="+val)
		}
	}
	action := t.Action
	if t.Classify != nil {
		action = t.Classify(vb)
	}
	if t.Rule == "" {
		action = Event
	}
	sev := t.Severity
	if sev == "" {
		sev = "info"
	}
	r := Result{Type: t, Name: t.Name, Title: t.Title, Action: action, Severity: sev, Labels: labels, Identity: strings.Join(keys, " ")}
	if action != Event {
		r.Rule = t.Rule
		if rule, ok := RuleByKey(t.Rule); ok && action == Open {
			r.Severity = rule.Severity
		}
	}
	return r
}

// Describe puts the labels in a readable order for messages.
func Describe(l map[string]string) string {
	var parts []string
	for _, k := range []string{"tunnel", "remote", "ap", "switch", "peer", "neighbor", "state", "server", "vserver", "pool", "usage", "ifname",
		"virus", "signature", "source", "message", "serial", "mac", "vlan", "port", "ip", "details", "type", "what", "trap"} {
		if v := strings.TrimSpace(l[k]); v != "" {
			parts = append(parts, k+" "+v)
		}
	}
	return strings.Join(parts, ", ")
}
