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
    out = {c.key: c for c in BUILTIN}
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
        elif c.vendor:  # the profiles' own alerts: only fire on that vendor's gear
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
