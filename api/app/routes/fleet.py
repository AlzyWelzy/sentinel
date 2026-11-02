"""Fleet-wide views and reports: an operations wall, tag groups with their
availability, capacity per group, unusual behaviour in plain words, and
the busy-hours, top and bottom, outage, restart and inventory reports."""

import time
import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Query
from pydantic import BaseModel
from sqlalchemy import select

from app.models import AlertRule, Check, Host, HostInventory, Incident
from app.routes.checks import _out as checks_out
from app.routes.fleetview import servers_overview
from app.services import metrics
from app.services.metrics import COMPARE, MetricsUnavailable
from app.services.reports import PUSH_SECONDS
from app.tenancy import Tenant, TenantContext

router = APIRouter(prefix="/v1", tags=["fleet"])

UNTAGGED = "Untagged"
_SEVERITY = {"critical": 0, "warning": 1, "info": 2}


def _all(query: str) -> str:
    """A COMPARE query for every server in the account (the tenant label is
    added by the metrics store)."""
    return query.replace("{SEL,", "{").replace("{SEL}", "")


async def _by_host(tenant_id: uuid.UUID, query: str) -> dict[str, float]:
    return {
        labels.get("host_id", ""): v for labels, v in await metrics.query_instant(tenant_id, query)
    }


async def _hosts(t: TenantContext) -> list[Host]:
    return list(
        await t.db.scalars(
            select(Host)
            .where(Host.tenant_id == t.tenant_id, Host.revoked_at.is_(None))
            .order_by(Host.hostname)
        )
    )


# ── Operations wall ──────────────────────────────────────────────────────


class Tile(BaseModel):
    kind: Literal["server", "check"]
    id: uuid.UUID
    name: str
    status: str  # down, critical, warning, maintenance, up, paused, pending
    reason: str | None
    tags: list[str]


class Wall(BaseModel):
    counts: dict[str, int]
    tiles: list[Tile]
    generated_at: int


@router.get("/fleet/wall")
async def wall(t: Tenant) -> Wall:
    """Every server and outside uptime check as a tile, worst first, with
    the open incident (or failure) that explains a bad state."""
    overview = await servers_overview(t)
    hosts = {h.id: h for h in await _hosts(t)}
    reasons: dict[uuid.UUID, tuple[int, str]] = {}
    for inc in await t.db.scalars(
        select(Incident).where(
            Incident.tenant_id == t.tenant_id,
            Incident.status == "open",
            Incident.host_id.is_not(None),
            Incident.merged_into.is_(None),
        )
    ):
        rank = _SEVERITY.get(inc.severity, 3)
        if inc.host_id is not None and (
            inc.host_id not in reasons or rank < reasons[inc.host_id][0]
        ):
            reasons[inc.host_id] = (rank, inc.summary)
    tiles = []
    for s in overview.servers:
        reason = reasons.get(s.id, (0, None))[1]
        if s.status == "down":
            reason = "Not reporting" + (f" since {_ago(s.last_seen)}" if s.last_seen else "")
        h = hosts.get(s.id)
        tiles.append(
            Tile(
                kind="server",
                id=s.id,
                name=s.hostname,
                status=s.status,
                reason=reason,
                tags=list(h.tags or []) if h else [],
            )
        )
    probe_checks = list(
        await t.db.scalars(
            select(Check).where(Check.tenant_id == t.tenant_id, Check.on_probes.is_(True))
        )
    )
    for c in await checks_out(t, probe_checks):
        failing = next((r for r in c.results if not r.ok), None)
        tiles.append(
            Tile(
                kind="check",
                id=c.id,
                name=c.name,
                status=c.status,
                reason=failing.detail if c.status == "down" and failing else None,
                tags=[c.tag] if c.tag else [],
            )
        )
    order = {"down": 0, "critical": 1, "warning": 2, "maintenance": 3, "pending": 4, "paused": 5}
    tiles.sort(key=lambda x: (order.get(x.status, 6), x.name.lower()))
    counts: dict[str, int] = {}
    for x in tiles:
        counts[x.status] = counts.get(x.status, 0) + 1
    return Wall(counts=counts, tiles=tiles, generated_at=int(time.time()))


def _ago(ts: int) -> str:
    s = max(0, int(time.time()) - ts)
    if s < 3600:
        return f"{s // 60} min ago"
    if s < 86400:
        return f"{s // 3600} h ago"
    return f"{s // 86400} d ago"


# ── Groups (tags) ────────────────────────────────────────────────────────


class Group(BaseModel):
    name: str
    servers: int
    counts: dict[str, int]
    availability_percent: float | None


def availability(pushes: float | None, observed_seconds: int) -> float | None:
    """Share of the expected agent reports that arrived."""
    expected = observed_seconds / PUSH_SECONDS
    if expected < 1:
        return None
    return min((pushes or 0) / expected * 100, 100.0)


@router.get("/fleet/groups")
async def groups(
    t: Tenant, range: Annotated[int, Query(ge=3600, le=90 * 86400)] = 86400
) -> list[Group]:
    """Each tag as a group (servers without tags under "Untagged"): its
    servers by status and their average availability over the range."""
    overview = await servers_overview(t)
    status = {s.id: s.status for s in overview.servers}
    hosts = await _hosts(t)
    try:
        pushes = await _by_host(t.tenant_id, f"count_over_time(sentinel_uptime_seconds[{range}s])")
    except MetricsUnavailable:
        pushes = None
    now = time.time()
    by_group: dict[str, list[Host]] = {}
    for h in hosts:
        for tag in h.tags or [UNTAGGED]:
            by_group.setdefault(tag, []).append(h)
    out = []
    for name, members in by_group.items():
        counts = {"paused": 0, "down": 0, "critical": 0, "warning": 0, "maintenance": 0, "up": 0}
        avail = []
        for h in members:
            counts[status.get(h.id, "down")] += 1
            if pushes is not None:
                observed = min(range, max(int(now - h.created_at.timestamp()), 0))
                a = availability(pushes.get(str(h.id)), observed)
                if a is not None:
                    avail.append(a)
        out.append(
            Group(
                name=name,
                servers=len(members),
                counts=counts,
                availability_percent=round(sum(avail) / len(avail), 2) if avail else None,
            )
        )
    out.sort(key=lambda g: (g.name == UNTAGGED, -g.counts["down"] - g.counts["critical"], g.name))
    return out


# ── Capacity ─────────────────────────────────────────────────────────────


class HotServer(BaseModel):
    id: uuid.UUID
    hostname: str
    cpu_peak: float | None
    memory_peak: float | None
    disk: float | None


class CapacityGroup(BaseModel):
    name: str
    servers: int
    cpu_cores: int
    memory_bytes: int
    cpu_avg: float | None
    cpu_peak: float | None
    memory_avg: float | None
    memory_peak: float | None
    disk_fullest: float | None
    # The first disk in the group to fill at its current rate.
    soonest_full_days: float | None
    soonest_full_host: str | None
    hottest: list[HotServer]


def _mean(vals: list[float]) -> float | None:
    return round(sum(vals) / len(vals), 1) if vals else None


@router.get("/fleet/capacity")
async def capacity(t: Tenant, days: Annotated[int, Query(ge=1, le=90)] = 7) -> list[CapacityGroup]:
    """Per tag group (and "All servers"): CPU and memory, average and peak
    over the period, the fullest disk, the first disk to fill, and the
    three servers running hottest."""
    w = f"{days}d"
    hosts = await _hosts(t)
    try:
        cpu_avg = await _by_host(t.tenant_id, f"avg_over_time(({_all(COMPARE['cpu'])})[{w}:5m])")
        cpu_peak = await _by_host(t.tenant_id, f"max_over_time(({_all(COMPARE['cpu'])})[{w}:5m])")
        mem_avg = await _by_host(t.tenant_id, f"avg_over_time(({_all(COMPARE['memory'])})[{w}:5m])")
        mem_peak = await _by_host(
            t.tenant_id, f"max_over_time(({_all(COMPARE['memory'])})[{w}:5m])"
        )
        disk_now = await _by_host(
            t.tenant_id, "max by (host_id) (last_over_time(sentinel_disk_used_percent[10m]))"
        )
        # Days until full per host: the fastest-filling filesystem.
        full = await _by_host(
            t.tenant_id,
            "min by (host_id) ((100 - last_over_time(sentinel_disk_used_percent[10m])) / "
            "(deriv(sentinel_disk_used_percent[24h]) * 86400 > 0))",
        )
    except MetricsUnavailable:
        cpu_avg = cpu_peak = mem_avg = mem_peak = disk_now = full = {}

    def group(name: str, members: list[Host]) -> CapacityGroup:
        keys = [str(h.id) for h in members]

        def vals(d: dict[str, float]) -> list[float]:
            return [d[k] for k in keys if k in d]

        soon = sorted((full[str(h.id)], h.hostname) for h in members if str(h.id) in full)
        hot = sorted(members, key=lambda h: -(cpu_peak.get(str(h.id)) or 0))[:3]
        return CapacityGroup(
            name=name,
            servers=len(members),
            cpu_cores=sum(h.cpu_cores or 0 for h in members),
            memory_bytes=sum(h.memory_bytes or 0 for h in members),
            cpu_avg=_mean(vals(cpu_avg)),
            cpu_peak=round(max(vals(cpu_peak)), 1) if vals(cpu_peak) else None,
            memory_avg=_mean(vals(mem_avg)),
            memory_peak=round(max(vals(mem_peak)), 1) if vals(mem_peak) else None,
            disk_fullest=round(max(vals(disk_now)), 1) if vals(disk_now) else None,
            soonest_full_days=round(soon[0][0], 1) if soon and soon[0][0] < 3650 else None,
            soonest_full_host=soon[0][1] if soon and soon[0][0] < 3650 else None,
            hottest=[
                HotServer(
                    id=h.id,
                    hostname=h.hostname,
                    cpu_peak=_r(cpu_peak.get(str(h.id))),
                    memory_peak=_r(mem_peak.get(str(h.id))),
                    disk=_r(disk_now.get(str(h.id))),
                )
                for h in hot
            ],
        )

    by_group: dict[str, list[Host]] = {}
    for h in hosts:
        for tag in h.tags or [UNTAGGED]:
            by_group.setdefault(tag, []).append(h)
    out = [group("All servers", hosts)] if hosts else []
    out += [
        group(n, m) for n, m in sorted(by_group.items(), key=lambda x: (x[0] == UNTAGGED, x[0]))
    ]
    return out


def _r(v: float | None) -> float | None:
    return None if v is None else round(v, 1)


# ── Anomalies ────────────────────────────────────────────────────────────

# metric key, what to call it, unit for the sentence, the smallest change
# worth mentioning (so a flat-at-zero metric doesn't "triple" to 0.3).
ANOMALY_METRICS = [
    ("cpu", "CPU", "percent", 10.0),
    ("memory", "Memory", "percent", 10.0),
    ("load", "Load", "load", 1.0),
    ("disk_io", "Disk throughput", "bytes_per_second", 1_000_000.0),
    ("network", "Network traffic", "bytes_per_second", 500_000.0),
]


Severity = Literal["confirmed", "likely"]


class Anomaly(BaseModel):
    host_id: uuid.UUID
    hostname: str
    metric: str
    label: str
    unit: str
    current: float
    usual: float
    factor: float
    severity: Severity
    sentence: str


def judge(
    current: float, usual: float, spread: float, floor: float
) -> tuple[Severity, float] | None:
    """Whether the last 15 minutes are unusual against the past week:
    well above the usual level (3 standard deviations, and at least
    `floor` above it), and how many times the usual level it is."""
    rise = current - usual
    if rise < floor or rise < 3 * max(spread, floor / 3):
        return None
    factor = current / usual if usual > 0 else float("inf")
    if factor < 1.5:
        return None
    severity: Severity = (
        "confirmed" if rise >= 5 * max(spread, floor / 3) and factor >= 2 else "likely"
    )
    return severity, factor


def fmt(value: float, unit: str) -> str:
    if unit == "percent":
        return f"{value:.0f}%"
    if unit == "bytes_per_second":
        for size, name in ((1e9, "GB/s"), (1e6, "MB/s"), (1e3, "KB/s")):
            if value >= size:
                return f"{value / size:.1f} {name}"
        return f"{value:.0f} B/s"
    return f"{value:.2f}"


@router.get("/fleet/anomalies")
async def anomalies(t: Tenant) -> list[Anomaly]:
    """Servers behaving unlike their own past week right now: the last 15
    minutes against the week's level and spread, for CPU, memory, load,
    disk and network. Servers with less than a day of history are skipped."""
    names = {str(h.id): (h.id, h.hostname) for h in await _hosts(t)}
    out: list[Anomaly] = []
    try:
        for key, label, unit, floor in ANOMALY_METRICS:
            expr = _all(COMPARE[key])
            now = await _by_host(t.tenant_id, f"avg_over_time(({expr})[15m:1m])")
            if not now:
                continue
            usual = await _by_host(t.tenant_id, f"avg_over_time(({expr})[7d:10m] offset 15m)")
            spread = await _by_host(t.tenant_id, f"stddev_over_time(({expr})[7d:10m] offset 15m)")
            history = await _by_host(t.tenant_id, f"count_over_time(({expr})[7d:1h] offset 15m)")
            for hid, cur in now.items():
                if hid not in names or hid not in usual or history.get(hid, 0) < 24:
                    continue
                verdict = judge(cur, usual[hid], spread.get(hid, 0.0), floor)
                if verdict is None:
                    continue
                severity, factor = verdict
                times = "far above" if factor == float("inf") else f"{factor:.1f}× "
                out.append(
                    Anomaly(
                        host_id=names[hid][0],
                        hostname=names[hid][1],
                        metric=key,
                        label=label,
                        unit=unit,
                        current=round(cur, 2),
                        usual=round(usual[hid], 2),
                        factor=round(min(factor, 999), 1),
                        severity=severity,
                        sentence=(
                            f"{label} on {names[hid][1]} is {fmt(cur, unit)}, {times}"
                            f"{'' if factor == float('inf') else 'its usual '}"
                            f"{fmt(usual[hid], unit)} over the past week."
                        ).replace("far above", "far above its usual"),
                    )
                )
    except MetricsUnavailable:
        return []
    out.sort(key=lambda a: (a.severity != "confirmed", -a.factor))
    return out


# ── Reports ──────────────────────────────────────────────────────────────

ReportMetric = Literal["cpu", "memory", "disk", "load", "network", "disk_io"]


class BusyHours(BaseModel):
    metric: str
    days: int
    timezone: str
    # matrix[weekday][hour], Monday first; None where there was no data.
    matrix: list[list[float | None]]
    busiest: str | None


def busy_matrix(points: list[list[float]], offset_seconds: int) -> list[list[float | None]]:
    """Average each (weekday, hour) slot of hourly points, in local time."""
    sums = [[0.0] * 24 for _ in range(7)]
    counts = [[0] * 24 for _ in range(7)]
    for ts, v in points:
        local = datetime.fromtimestamp(ts + offset_seconds, UTC)
        sums[local.weekday()][local.hour] += v
        counts[local.weekday()][local.hour] += 1
    return [
        [round(sums[d][h] / counts[d][h], 2) if counts[d][h] else None for h in range(24)]
        for d in range(7)
    ]


@router.get("/reports/busy-hours")
async def busy_hours(
    t: Tenant,
    metric: ReportMetric = "cpu",
    days: Annotated[int, Query(ge=7, le=90)] = 28,
    host_id: uuid.UUID | None = None,
    tz_offset_minutes: Annotated[int, Query(ge=-720, le=840)] = 330,
) -> BusyHours:
    """When the servers (or one server) are busiest: the average of each
    weekday and hour over the period, in the viewer's time zone."""
    sel = f'host_id="{host_id}"' if host_id else ""
    q = (
        COMPARE[metric]
        .replace("{SEL,", "{" + sel + ("," if sel else ""))
        .replace("{SEL}", "{" + sel + "}" if sel else "")
    )
    end = int(time.time()) // 3600 * 3600
    start = end - days * 86400
    try:
        series = await metrics.query_series(
            t.tenant_id, f"avg(avg_over_time(({q})[1h:5m]))", start, end, 3600, []
        )
    except MetricsUnavailable:
        series = []
    points = series[0]["points"] if series else []
    matrix = busy_matrix(points, tz_offset_minutes * 60)
    best = max(
        ((v, d, h) for d, row in enumerate(matrix) for h, v in enumerate(row) if v is not None),
        default=None,
    )
    day_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    return BusyHours(
        metric=metric,
        days=days,
        timezone=f"UTC{'+' if tz_offset_minutes >= 0 else '-'}{abs(tz_offset_minutes) // 60:02d}:"
        f"{abs(tz_offset_minutes) % 60:02d}",
        matrix=matrix,
        busiest=f"{day_names[best[1]]} {best[2]:02d}:00–{(best[2] + 1) % 24:02d}:00"
        if best
        else None,
    )


class Ranked(BaseModel):
    host_id: uuid.UUID
    hostname: str
    average: float
    peak: float


class TopBottom(BaseModel):
    metric: str
    days: int
    top: list[Ranked]
    bottom: list[Ranked]


@router.get("/reports/top")
async def top_bottom(
    t: Tenant,
    metric: ReportMetric = "cpu",
    days: Annotated[int, Query(ge=1, le=90)] = 7,
    n: Annotated[int, Query(ge=1, le=50)] = 10,
) -> TopBottom:
    """The busiest and quietest servers for a metric over the period, by
    average (the quietest are the candidates for a smaller plan)."""
    names = {str(h.id): h for h in await _hosts(t)}
    q = _all(COMPARE[metric])
    try:
        avg = await _by_host(t.tenant_id, f"avg_over_time(({q})[{days}d:5m])")
        peak = await _by_host(t.tenant_id, f"max_over_time(({q})[{days}d:5m])")
    except MetricsUnavailable:
        avg, peak = {}, {}
    rows = sorted(
        (
            Ranked(
                host_id=names[k].id,
                hostname=names[k].hostname,
                average=round(v, 2),
                peak=round(peak.get(k, v), 2),
            )
            for k, v in avg.items()
            if k in names
        ),
        key=lambda r: -r.average,
    )
    return TopBottom(metric=metric, days=days, top=rows[:n], bottom=list(reversed(rows[-n:])))


class Outage(BaseModel):
    host_id: uuid.UUID | None
    hostname: str
    summary: str
    started_at: datetime
    ended_at: datetime | None
    duration_seconds: int
    acknowledged_by: str | None


@router.get("/reports/outages")
async def outages(
    t: Tenant,
    days: Annotated[int, Query(ge=1, le=90)] = 30,
    host_id: uuid.UUID | None = None,
) -> list[Outage]:
    """Every time a server stopped reporting in the period, longest first."""
    since = datetime.fromtimestamp(time.time() - days * 86400, UTC)
    q = (
        select(Incident)
        .join(AlertRule, AlertRule.id == Incident.rule_id)
        .where(
            Incident.tenant_id == t.tenant_id,
            AlertRule.kind == "host_down",
            Incident.merged_into.is_(None),
            (Incident.resolved_at.is_(None)) | (Incident.resolved_at > since),
        )
    )
    if host_id:
        q = q.where(Incident.host_id == host_id)
    now = datetime.now(UTC)
    out = [
        Outage(
            host_id=i.host_id,
            hostname=i.hostname,
            summary=i.summary,
            started_at=i.opened_at,
            ended_at=i.resolved_at,
            duration_seconds=int(((i.resolved_at or now) - i.opened_at).total_seconds()),
            acknowledged_by=i.acknowledged_by,
        )
        for i in await t.db.scalars(q)
    ]
    out.sort(key=lambda o: -o.duration_seconds)
    return out[:500]


class Restart(BaseModel):
    host_id: uuid.UUID
    hostname: str
    restarts: int
    uptime_seconds: float | None


@router.get("/reports/restarts")
async def restarts(t: Tenant, days: Annotated[int, Query(ge=1, le=90)] = 30) -> list[Restart]:
    """How many times each server rebooted in the period (its uptime went
    back to zero), and its uptime now."""
    names = {str(h.id): h for h in await _hosts(t)}
    try:
        resets = await _by_host(
            t.tenant_id, f"max by (host_id) (resets(sentinel_uptime_seconds[{days}d]))"
        )
        up = await _by_host(
            t.tenant_id, "max by (host_id) (last_over_time(sentinel_uptime_seconds[10m]))"
        )
    except MetricsUnavailable:
        resets, up = {}, {}
    out = [
        Restart(
            host_id=h.id,
            hostname=h.hostname,
            restarts=int(resets.get(k, 0)),
            uptime_seconds=up.get(k),
        )
        for k, h in names.items()
    ]
    out.sort(key=lambda r: (-r.restarts, r.hostname))
    return out


class InventoryRow(BaseModel):
    host_id: uuid.UUID
    hostname: str
    platform: str | None
    platform_version: str | None
    kernel: str | None
    arch: str | None
    cpu_model: str | None
    cpu_cores: int | None
    memory_bytes: int | None
    virtualization: str | None
    agent_version: str | None
    ip_addresses: list[str]
    public_ip: str | None
    tags: list[str]
    packages: int | None
    listening_ports: int | None
    first_seen: datetime


@router.get("/reports/inventory")
async def inventory(t: Tenant) -> list[InventoryRow]:
    """Every server's system details in one table (for a CSV or an audit)."""
    hosts = await _hosts(t)
    inv = {
        i.host_id: i.data or {}
        for i in await t.db.scalars(
            select(HostInventory).where(HostInventory.tenant_id == t.tenant_id)
        )
    }
    out = []
    for h in hosts:
        d = inv.get(h.id, {})
        ports = d.get("listening_ports")
        out.append(
            InventoryRow(
                host_id=h.id,
                hostname=h.hostname,
                platform=h.platform,
                platform_version=h.platform_version,
                kernel=d.get("kernel_version"),
                arch=h.arch,
                cpu_model=d.get("cpu_model"),
                cpu_cores=h.cpu_cores,
                memory_bytes=h.memory_bytes,
                virtualization=d.get("virtualization"),
                agent_version=h.agent_version,
                ip_addresses=list(h.ip_addresses or []),
                public_ip=h.public_ip,
                tags=list(h.tags or []),
                packages=len(d["packages"]) if isinstance(d.get("packages"), list) else None,
                listening_ports=len({(p.get("port"), p.get("protocol")) for p in ports})
                if isinstance(ports, list)
                else None,
                first_seen=h.created_at,
            )
        )
    return out
