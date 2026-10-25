"""Rule preview: replay a metric or custom rule over recent history and
count how often it would have fired, per host, before anyone saves it.

The query mirrors the alerter's (alerter/queries.go): the same metric,
aggregation and per-host fold, evaluated every minute. Breach, duration
and recovery follow the alerter's state machine closely enough to answer
"would this page me ten times a night?"; it's an estimate, not a replay of
every edge case (maintenance windows and dependencies aren't applied).
"""

import time
import uuid
from dataclasses import dataclass, field

from app.services import logs as logstore
from app.services.metrics import query_series

STEP = 60

# metric: (series name, fixed matcher, is counter, scale, fold)
METRICS: dict[str, tuple[str, str, bool, float, str]] = {
    "cpu": ("pulsegrid_cpu_usage_percent", "", False, 1, "max"),
    "memory": ("pulsegrid_memory_used_percent", "", False, 1, "max"),
    "swap": ("pulsegrid_swap_used_percent", "", False, 1, "max"),
    "disk": ("pulsegrid_disk_used_percent", "", False, 1, "max"),
    "load1": ("pulsegrid_load", 'period="1m"', False, 1, "max"),
    "load5": ("pulsegrid_load", 'period="5m"', False, 1, "max"),
    "iowait": ("pulsegrid_cpu_mode_percent", 'mode="iowait"', False, 1, "max"),
    "steal": ("pulsegrid_cpu_mode_percent", 'mode="steal"', False, 1, "max"),
    "inodes": ("pulsegrid_disk_inodes_used_percent", "", False, 1, "max"),
    "disk_busy": ("pulsegrid_disk_io_time_seconds_total", "", True, 100, "max"),
    "network_in": ("pulsegrid_network_bytes_total", 'direction="rx"', True, 8 / 1e6, "sum"),
    "network_out": ("pulsegrid_network_bytes_total", 'direction="tx"', True, 8 / 1e6, "sum"),
}


@dataclass
class HostPreview:
    host_id: str
    fires: int = 0
    firing_minutes: int = 0
    peak: float | None = None
    first_fired_at: int | None = None
    last_fired_at: int | None = None


@dataclass
class Preview:
    days: int
    fires: int = 0
    firing_minutes: int = 0
    hosts_affected: int = 0
    hosts: list[HostPreview] = field(default_factory=list)
    verdict: str = "quiet"  # quiet, occasional, noisy
    advice: str | None = None


def build_query(
    kind: str,
    metric: str | None,
    target: str | None,
    labels: dict[str, str],
    aggregation: str,
    window_seconds: int,
    host_id: uuid.UUID | None,
    host_ids: list[str] | None,
) -> str:
    ms: list[str] = []
    if host_id is not None:
        ms.append(f'host_id="{host_id}"')
    elif host_ids is not None:
        ms.append('host_id=~"' + "|".join(host_ids) + '"')
    if kind == "metric":
        name, fixed, rate, scale, fold = METRICS[metric or ""]
        if fixed:
            ms.insert(0, fixed)
    else:  # custom: names and label keys were validated by RuleIn
        name, rate, scale, fold = "pulsegrid_custom_" + (target or ""), False, 1, "max"
        ms += [f'{k}="{v}"' for k, v in sorted(labels.items()) if k != "tenant_id"]
    sel = name + "{" + ",".join(ms) + "}"
    window = f"{max(window_seconds, 60)}s"
    if rate:
        w = window if aggregation in ("avg", "max", "min") else "3m"
        inner = f"rate({sel}[{w}])"
        if aggregation in ("max", "min"):
            inner = f"{aggregation}_over_time(rate({sel}[3m])[{w}:1m])"
    elif aggregation in ("avg", "max", "min"):
        inner = f"{aggregation}_over_time({sel}[{window}])"
    else:
        inner = f"last_over_time({sel}[3m])"
    q = f"{fold} by (host_id) ({inner})"
    return f"({q}) * {scale:g}" if scale != 1 else q


def simulate(
    points: list[list[float]],
    operator: str,
    threshold: float,
    duration_seconds: int,
    recovery: float | None,
) -> HostPreview:
    """Walk one host's minute-by-minute values through breach → firing →
    resolved, the way the alerter does."""
    out = HostPreview(host_id="")

    def breach(v: float) -> bool:
        return v > threshold if operator == ">" else v < threshold

    def recovered(v: float) -> bool:
        if recovery is None:
            return not breach(v)
        return v <= recovery if operator == ">" else v >= recovery

    since: float | None = None
    firing = False
    for ts, v in points:
        if out.peak is None or (v > out.peak if operator == ">" else v < out.peak):
            out.peak = v
        if firing:
            if recovered(v):
                firing, since = False, None
            else:
                out.firing_minutes += 1
            continue
        if breach(v):
            since = ts if since is None else since
            if ts - since >= duration_seconds:
                firing = True
                out.fires += 1
                out.firing_minutes += 1
                out.first_fired_at = out.first_fired_at or int(ts)
                out.last_fired_at = int(ts)
        else:
            since = None
    if out.peak is not None:
        out.peak = round(out.peak, 2)
    return out


async def preview(
    tenant_id: uuid.UUID,
    *,
    kind: str,
    metric: str | None,
    target: str | None,
    labels: dict[str, str],
    operator: str,
    threshold: float,
    duration_seconds: int,
    recovery_threshold: float | None,
    aggregation: str,
    window_seconds: int,
    host_id: uuid.UUID | None,
    host_ids: list[str] | None,
    days: int,
) -> Preview:
    end = int(time.time())
    start = end - days * 86400
    query = build_query(
        kind, metric, target, labels, aggregation, window_seconds, host_id, host_ids
    )
    series = await query_series(tenant_id, query, start, end, STEP, ["host_id"])
    out = Preview(days=days)
    for s in series:
        h = simulate(s["points"], operator, threshold, duration_seconds, recovery_threshold)
        h.host_id = s["labels"].get("host_id", "")
        out.hosts.append(h)
    return _summarise(out, days)


def _summarise(out: Preview, days: int) -> Preview:
    out.hosts.sort(key=lambda h: (-h.fires, -h.firing_minutes))
    out.fires = sum(h.fires for h in out.hosts)
    out.firing_minutes = sum(h.firing_minutes for h in out.hosts)
    out.hosts_affected = sum(1 for h in out.hosts if h.fires)
    per_day = out.fires / max(days, 1)
    if per_day >= 3:
        out.verdict = "noisy"
        out.advice = (
            f"About {per_day:.0f} alerts a day. Raise the threshold, use an average over "
            "a longer window, or lengthen the duration."
        )
    elif out.fires:
        out.verdict = "occasional"
    return out


async def preview_logs(
    account: int,
    f: logstore.LogFilter,
    *,
    threshold: float,
    duration_seconds: int,
    window_seconds: int,
    days: int,
) -> Preview:
    """Log rules: matching lines per window, per host, through the same walk.
    Each point covers a whole window, so firing time counts in windows."""
    end = int(time.time())
    start = end - days * 86400
    series = await logstore.hits_by_host(account, f, start, end, window_seconds)
    out = Preview(days=days)
    for host_id, points in series.items():
        h = simulate(points, ">", threshold, duration_seconds, None)
        h.host_id = host_id
        h.firing_minutes = h.firing_minutes * window_seconds // 60
        out.hosts.append(h)
    out = _summarise(out, days)
    if out.verdict == "noisy":
        out.advice = (
            f"About {out.fires / max(days, 1):.0f} alerts a day. Raise the line count, "
            "narrow the text or levels, or lengthen the duration."
        )
    return out
