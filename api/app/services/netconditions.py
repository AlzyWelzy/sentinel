"""Network rule conditions: the catalog the alerter evaluates (alerter/
network.go). Built-in interface conditions, plus each vendor profile's
alerts, keyed by their name in snake_case. Keep the built-ins in step with
the Go list; a test on each side checks the shared keys."""

import re
from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class Condition:
    key: str
    name: str
    unit: str = ""  # the threshold's unit; "" takes none
    default: float | None = None
    minimum: float = 0
    maximum: float = 1e12
    about: str = ""
    vendor: str = ""
    severity: str = "warning"
    duration_seconds: int = 120
    recommended: bool = True  # added with an organisation's first device


BUILTIN = [
    Condition(
        "interface_down",
        "Interface down",
        about="Ports that were up in the last day and went down while enabled",
    ),
    Condition(
        "interface_utilisation",
        "Interface utilisation",
        "%",
        90,
        1,
        100,
        about="Traffic in either direction above this share of the port's speed",
    ),
    Condition(
        "interface_errors",
        "Interface errors",
        "errors/s",
        1,
        0.001,
        1e9,
        about="Input plus output errors per second on a port",
    ),
    Condition(
        "lag_member_down", "LAG member down", about="A port-channel runs degraded on fewer links"
    ),
    Condition("device_rebooted", "Device rebooted", about="Uptime under 10 minutes"),
    Condition(
        "proxmox_node_offline",
        "Proxmox node offline",
        about="A node of the cluster is offline",
        vendor="Proxmox",
        severity="critical",
    ),
    Condition(
        "proxmox_quorum_lost",
        "Proxmox cluster lost quorum",
        vendor="Proxmox",
        severity="critical",
        duration_seconds=60,
    ),
    Condition(
        "proxmox_guest_stopped",
        "Proxmox guest stopped",
        about="A VM or container that was running in the last day stopped",
        vendor="Proxmox",
        duration_seconds=300,
    ),
    Condition(
        "proxmox_node_memory",
        "Proxmox node memory",
        "%",
        95,
        1,
        100,
        vendor="Proxmox",
        duration_seconds=600,
    ),
    Condition(
        "proxmox_node_cpu",
        "Proxmox node CPU",
        "%",
        90,
        1,
        100,
        vendor="Proxmox",
        duration_seconds=900,
    ),
    Condition(
        "proxmox_storage_full",
        "Proxmox storage",
        "%",
        90,
        1,
        100,
        vendor="Proxmox",
        duration_seconds=600,
    ),
]

# SNMP trap conditions (netmon/traps/catalog.go): a device's trap opens the
# alert and its clearing trap (or time, for one-off traps) closes it. Keep in
# step with the Go list.
TRAPS = [
    Condition(
        "trap_vpn_tunnel_down",
        "VPN tunnel down (trap)",
        about='FortiGate "VPN tunnel is down"; closes on "VPN tunnel is up".',
        vendor="SNMP trap",
        severity="critical",
        duration_seconds=0,
        recommended=True,
    ),
    Condition(
        "trap_ha_member_down",
        "HA cluster member down",
        about='FortiGate "HA cluster member down"; closes on "HA cluster member up".',
        vendor="SNMP trap",
        severity="critical",
        duration_seconds=0,
        recommended=True,
    ),
    Condition(
        "trap_ha_failover",
        "HA failover",
        about='FortiGate "HA cluster status change": the primary unit changed.',
        vendor="SNMP trap",
        severity="warning",
        duration_seconds=0,
        recommended=True,
    ),
    Condition(
        "trap_ha_heartbeat",
        "HA heartbeat failure",
        about='FortiGate "HA heartbeat interface failure".',
        vendor="SNMP trap",
        severity="critical",
        duration_seconds=0,
        recommended=True,
    ),
    Condition(
        "trap_ap_down",
        "Wireless AP down",
        about='FortiGate "AP is down"; closes on "AP is up".',
        vendor="SNMP trap",
        severity="warning",
        duration_seconds=0,
        recommended=True,
    ),
    Condition(
        "trap_fortiswitch_down",
        "FortiSwitch down",
        about='FortiGate "FortiSwitch controller session is down"; closes on "… is up".',
        vendor="SNMP trap",
        severity="warning",
        duration_seconds=0,
        recommended=True,
    ),
    Condition(
        "trap_bgp_down",
        "BGP session down (trap)",
        about="BGP4-MIB bgpBackwardTransition; closes on bgpEstablished.",
        vendor="SNMP trap",
        severity="critical",
        duration_seconds=0,
        recommended=True,
    ),
    Condition(
        "trap_ospf_down",
        "OSPF neighbour down (trap)",
        about="OSPF-MIB neighbour state change (normal and virtual);"
        " closes when the neighbour is Full again.",
        vendor="SNMP trap",
        severity="warning",
        duration_seconds=0,
        recommended=True,
    ),
    Condition(
        "trap_lb_real_server_down",
        "Load balancer real server down",
        about='FortiGate "Load balance real-server is down" (FortiOS sends no "up" trap).',
        vendor="SNMP trap",
        severity="warning",
        duration_seconds=0,
        recommended=True,
    ),
    Condition(
        "trap_power_supply",
        "Power supply failure",
        about="FortiGate power-supply event; closes when the unit reports the supply restored.",
        vendor="SNMP trap",
        severity="critical",
        duration_seconds=0,
        recommended=True,
    ),
    Condition(
        "trap_fan_failure",
        "Fan failure",
        about="FortiGate fan failure.",
        vendor="SNMP trap",
        severity="critical",
        duration_seconds=0,
        recommended=True,
    ),
    Condition(
        "trap_temperature_high",
        "Temperature too high",
        about='FortiGate "snmp-event::temperature-high".',
        vendor="SNMP trap",
        severity="critical",
        duration_seconds=0,
        recommended=True,
    ),
    Condition(
        "trap_voltage",
        "Voltage out of range",
        about='FortiGate "snmp-event::voltage-alert".',
        vendor="SNMP trap",
        severity="critical",
        duration_seconds=0,
        recommended=True,
    ),
    Condition(
        "trap_bypass_mode",
        "Interface bypass mode",
        about="FortiGate bypass mode (traffic isn't inspected); closes when it leaves bypass mode.",
        vendor="SNMP trap",
        severity="critical",
        duration_seconds=0,
        recommended=True,
    ),
    Condition(
        "trap_cpu_high",
        "CPU usage too high (trap)",
        about='FortiGate "CPU usage too high" and "Per CPU usage is high".',
        vendor="SNMP trap",
        severity="warning",
        duration_seconds=0,
        recommended=True,
    ),
    Condition(
        "trap_memory_low",
        "Memory low (trap)",
        about='FortiGate "Available memory is low".',
        vendor="SNMP trap",
        severity="warning",
        duration_seconds=0,
        recommended=True,
    ),
    Condition(
        "trap_log_disk_low",
        "Log disk space low",
        about='FortiGate "Available log space is low".',
        vendor="SNMP trap",
        severity="warning",
        duration_seconds=0,
        recommended=True,
    ),
    Condition(
        "trap_conserve_mode",
        "Conserve mode",
        about='FortiGate "AV system enters conserve mode" (memory exhausted).',
        vendor="SNMP trap",
        severity="critical",
        duration_seconds=0,
        recommended=True,
    ),
    Condition(
        "trap_inspection_bypassed",
        "Inspection bypassed",
        about='FortiGate "AV bypass happens" and "IPS network buffer is full" (fail-open).',
        vendor="SNMP trap",
        severity="critical",
        duration_seconds=0,
        recommended=True,
    ),
    Condition(
        "trap_faz_disconnected",
        "FortiAnalyzer disconnected",
        about='FortiGate "Disconnected from FortiAnalyzer".',
        vendor="SNMP trap",
        severity="warning",
        duration_seconds=0,
        recommended=True,
    ),
    Condition(
        "trap_dhcp",
        "DHCP problem",
        about='FortiGate "DHCP addresses at limit" (also IP conflicts and NAKs).',
        vendor="SNMP trap",
        severity="warning",
        duration_seconds=0,
        recommended=True,
    ),
    Condition(
        "trap_ip_pool",
        "IP pool usage high",
        about='FortiGate "About IP pool usage"; closes on its clear trap.',
        vendor="SNMP trap",
        severity="warning",
        duration_seconds=0,
        recommended=True,
    ),
    Condition(
        "trap_ip_conflict",
        "IP address conflict",
        about='FortiGate "snmp-event::interface" (IP conflict).',
        vendor="SNMP trap",
        severity="warning",
        duration_seconds=0,
        recommended=True,
    ),
    Condition(
        "trap_restart",
        "Device restarted (trap)",
        about="coldStart / warmStart. Polling also notices reboots.",
        vendor="SNMP trap",
        severity="warning",
        duration_seconds=0,
        recommended=True,
    ),
    Condition(
        "trap_auth_failure",
        "SNMP authentication failure",
        about="authenticationFailure. Often scanners; not recommended by default.",
        vendor="SNMP trap",
        severity="warning",
        duration_seconds=0,
        recommended=False,
    ),
    Condition(
        "trap_link_down",
        "Interface down (trap)",
        about='linkDown, closes on linkUp. The polled "Interface down" condition'
        " covers this without alarms from unused ports.",
        vendor="SNMP trap",
        severity="warning",
        duration_seconds=0,
        recommended=False,
    ),
    Condition(
        "trap_ips_attack",
        "IPS attack detected",
        about='FortiGate "IPS detected an attack / an anomaly". Very frequent on'
        " busy firewalls; always recorded as events.",
        vendor="SNMP trap",
        severity="warning",
        duration_seconds=0,
        recommended=False,
    ),
    Condition(
        "trap_virus",
        "Virus detected",
        about='FortiGate "AV detected virus". Always recorded as events.',
        vendor="SNMP trap",
        severity="warning",
        duration_seconds=0,
        recommended=False,
    ),
    Condition(
        "trap_security_level",
        "Security level changed",
        about='FortiGate "snmp-event::security_level_change".',
        vendor="SNMP trap",
        severity="warning",
        duration_seconds=0,
        recommended=False,
    ),
]


def _seconds(value: str | None, default: int = 120) -> int:
    m = re.fullmatch(r"(\d+)([smh])", (value or "").strip())
    if not m:
        return default
    return min(int(m.group(1)) * {"s": 1, "m": 60, "h": 3600}[m.group(2)], 86400)


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def _profiles_dir() -> Path:
    for p in (
        Path("/app/netmon-profiles"),
        Path(__file__).resolve().parents[3] / "netmon" / "profiles",
    ):
        if p.is_dir():
            return p
    return Path("/nonexistent")


def load() -> dict[str, Condition]:
    out = {c.key: c for c in BUILTIN + TRAPS}
    # Concrete profiles in name order, as the alerter does; mixin alerts
    # (_routing) count once.
    raw = {}
    for f in sorted(_profiles_dir().glob("*.yaml")):
        doc = yaml.safe_load(f.read_text()) or {}
        if doc.get("name"):
            raw[doc["name"]] = doc

    def alerts(doc: dict, seen: set) -> list[dict]:
        found = list(doc.get("alerts") or [])
        for parent in doc.get("extends") or []:
            if parent in raw and parent not in seen:
                found += alerts(raw[parent], seen | {parent})
        return found

    for name in sorted(n for n in raw if not n.startswith("_")):
        for a in alerts(raw[name], {name}):
            key = _slug(a.get("name", ""))
            if key and key not in out:
                sev = str(a.get("severity") or "warning")
                if sev not in ("critical", "warning", "info"):
                    sev = "warning"
                out[key] = Condition(
                    key,
                    a["name"],
                    vendor=raw[name].get("vendor", ""),
                    severity=sev,
                    duration_seconds=_seconds(a.get("for")),
                )
    return out


CONDITIONS = load()


# Added once, with an organisation's first network device.
STARTER = [
    ("interface_down", "warning", 120),
    ("interface_utilisation", "warning", 900),
    ("interface_errors", "warning", 600),
    ("lag_member_down", "warning", 120),
]


def starter_rules() -> list[dict]:
    rules = []
    for key, severity, duration in STARTER:
        c = CONDITIONS[key]
        name = (
            f"{c.name} above {c.default:g}{'' if c.unit == '%' else ' '}{c.unit}"
            if c.unit
            else c.name
        )
        rules.append(
            {
                "name": name,
                "kind": "network",
                "target": key,
                "severity": severity,
                "duration_seconds": duration,
                "threshold": c.default,
            }
        )
    for c in CONDITIONS.values():
        if c.vendor and c.unit:  # Proxmox thresholds
            rules.append(
                {
                    "name": f"{c.name} above {c.default:g}%",
                    "kind": "network",
                    "target": c.key,
                    "severity": c.severity,
                    "duration_seconds": c.duration_seconds,
                    "threshold": c.default,
                }
            )
        elif (
            c.vendor and c.recommended
        ):  # profile alerts and traps: only fire on gear that has them
            rules.append(
                {
                    "name": c.name,
                    "kind": "network",
                    "target": c.key,
                    "severity": c.severity,
                    "duration_seconds": c.duration_seconds,
                }
            )
    return rules
