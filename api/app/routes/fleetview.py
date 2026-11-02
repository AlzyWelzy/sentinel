"""At-a-glance views: every server's health on one screen (status counts,
CPU, memory, fullest disk, load), and a server's disks with a forecast."""

import time
import uuid
from typing import Annotated, Literal, cast

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select

from app.models import Host, Incident
from app.routes.v1 import _hosts_out
from app.services import metrics
from app.services.metrics import MetricsUnavailable
from app.tenancy import Tenant

router = APIRouter(prefix="/v1", tags=["servers"])

Status = Literal["paused", "down", "critical", "warning", "maintenance", "up"]


class ServerHealth(BaseModel):
    id: uuid.UUID
    hostname: str
    status: Status
    online: bool
    in_maintenance: bool
    paused: bool = False
    cpu: float | None
    memory: float | None
    disk: float | None
    load1: float | None
    cpu_cores: int | None
    uptime_seconds: float | None
    open_incidents: int
    critical_incidents: int
    last_seen: int | None


class FleetOverview(BaseModel):
    counts: dict[str, int]
    servers: list[ServerHealth]
    metrics_available: bool


async def _latest(tenant_id: uuid.UUID, query: str) -> dict[str, float]:
    return {
        labels.get("host_id", ""): v for labels, v in await metrics.query_instant(tenant_id, query)
    }


@router.get("/servers/overview")
async def servers_overview(t: Tenant) -> FleetOverview:
    """Every server with its status (down: not reporting; critical / warning:
    the worst open incident; maintenance; up; paused first) and latest CPU, memory, fullest
    disk and 1-minute load."""
    hosts = list(
        await t.db.scalars(
            select(Host)
            .where(Host.tenant_id == t.tenant_id, Host.revoked_at.is_(None))
            .order_by(Host.hostname)
        )
    )
    outs = {h.id: h for h in await _hosts_out(t, hosts)}
    open_by_host: dict[uuid.UUID, dict[str, int]] = {}
    rows = await t.db.execute(
        select(Incident.host_id, Incident.severity, func.count())
        .where(
            Incident.tenant_id == t.tenant_id,
            Incident.status == "open",
            Incident.host_id.is_not(None),
        )
        .group_by(Incident.host_id, Incident.severity)
    )
    for row in rows:
        if row[0] is not None:
            open_by_host.setdefault(row[0], {})[str(row[1])] = int(row[2])
    available = True
    try:
        cpu = await _latest(
            t.tenant_id, "max by (host_id) (last_over_time(sentinel_cpu_usage_percent[3m]))"
        )
        mem = await _latest(
            t.tenant_id, "max by (host_id) (last_over_time(sentinel_memory_used_percent[3m]))"
        )
        disk = await _latest(
            t.tenant_id, "max by (host_id) (last_over_time(sentinel_disk_used_percent[5m]))"
        )
        load = await _latest(
            t.tenant_id, 'max by (host_id) (last_over_time(sentinel_load{period="1m"}[3m]))'
        )
        uptime = await _latest(
            t.tenant_id, "max by (host_id) (last_over_time(sentinel_uptime_seconds[3m]))"
        )
    except MetricsUnavailable:
        cpu = mem = disk = load = uptime = {}
        available = False
    counts = {"paused": 0, "down": 0, "critical": 0, "warning": 0, "maintenance": 0, "up": 0}
    servers = []
    for h in hosts:
        o = outs[h.id]
        sev = open_by_host.get(h.id, {})
        status: Status
        if o.paused:
            status = "paused"
        elif not o.online:
            status = "down"
        elif sev.get("critical"):
            status = "critical"
        elif sev.get("warning"):
            status = "warning"
        elif o.in_maintenance:
            status = "maintenance"
        else:
            status = "up"
        counts[status] += 1
        key = str(h.id)

        def r(v: float | None) -> float | None:
            return None if v is None else round(v, 1)

        servers.append(
            ServerHealth(
                id=h.id,
                hostname=h.hostname,
                status=status,
                online=o.online,
                in_maintenance=o.in_maintenance,
                paused=o.paused,
                cpu=r(cpu.get(key)) if o.online else None,
                memory=r(mem.get(key)) if o.online else None,
                disk=r(disk.get(key)),
                load1=r(load.get(key)) if o.online else None,
                cpu_cores=h.cpu_cores,
                uptime_seconds=uptime.get(key) if o.online else None,
                open_incidents=sum(sev.values()),
                critical_incidents=sev.get("critical", 0),
                last_seen=o.last_seen,
            )
        )
    return FleetOverview(counts=counts, servers=servers, metrics_available=available)


class DiskOut(BaseModel):
    mountpoint: str
    device: str | None
    fstype: str | None
    total_bytes: float | None
    used_bytes: float | None
    free_bytes: float | None
    used_percent: float | None
    inodes_used_percent: float | None
    # From the last day's trend: used % in 7 days, and days until full.
    predicted_7d_percent: float | None
    days_until_full: float | None


@router.get("/hosts/{host_id}/disks")
async def host_disks(host_id: uuid.UUID, t: Tenant) -> list[DiskOut]:
    host = await t.db.scalar(select(Host).where(Host.id == host_id, Host.tenant_id == t.tenant_id))
    if host is None:
        raise HTTPException(status_code=404, detail="Host not found")
    return await disks_for(t.tenant_id, host.id)


async def disks_for(tenant_id: uuid.UUID, host_id: uuid.UUID) -> list[DiskOut]:
    """A server's filesystems now, with a forecast (also the staff view's)."""
    sel = f'host_id="{host_id}"'

    async def by_mount(query: str) -> dict[str, tuple[dict, float]]:
        return {
            labels.get("mountpoint", ""): (labels, v)
            for labels, v in await metrics.query_instant(tenant_id, query)
        }

    try:
        used_pct = await by_mount(f"last_over_time(sentinel_disk_used_percent{{{sel}}}[10m])")
        free = await by_mount(f"last_over_time(sentinel_disk_free_bytes{{{sel}}}[10m])")
        total = await by_mount(f"last_over_time(sentinel_disk_total_bytes{{{sel}}}[10m])")
        used = await by_mount(f"last_over_time(sentinel_disk_used_bytes{{{sel}}}[10m])")
        inodes = await by_mount(f"last_over_time(sentinel_disk_inodes_used_percent{{{sel}}}[10m])")
        predicted = await by_mount(
            f"predict_linear(sentinel_disk_used_percent{{{sel}}}[24h], 7 * 86400)"
        )
        slope = await by_mount(f"deriv(sentinel_disk_used_percent{{{sel}}}[24h])")
    except MetricsUnavailable:
        raise HTTPException(status_code=503, detail="Metrics are unavailable right now") from None
    out = []
    for mount, (labels, pct) in sorted(used_pct.items()):
        free_b = free.get(mount, ({}, None))[1]
        total_b = total.get(mount, ({}, None))[1]
        if total_b is None and free_b is not None and pct < 100:
            total_b = round(free_b / (1 - pct / 100))  # agents before 0.7 sent no total
        used_b = used.get(mount, ({}, None))[1]
        if used_b is None and total_b is not None and free_b is not None:
            used_b = total_b - free_b
        growth = slope.get(mount, ({}, None))[1]
        days = round((100 - pct) / (growth * 86400), 1) if growth and growth > 0 else None
        p7 = predicted.get(mount, ({}, None))[1]
        out.append(
            DiskOut(
                mountpoint=mount,
                device=labels.get("device"),
                fstype=total.get(mount, ({}, None))[0].get("fstype"),
                total_bytes=total_b,
                used_bytes=used_b,
                free_bytes=free_b,
                used_percent=round(pct, 1),
                inodes_used_percent=round(inodes[mount][1], 1) if mount in inodes else None,
                predicted_7d_percent=None if p7 is None else round(max(0.0, min(100.0, p7)), 1),
                days_until_full=days if days is not None and days < 3650 else None,
            )
        )
    return out


# ── One server's summary ─────────────────────────────────────────────────

TimelineState = Literal["down", "critical", "warning"]
# Worse states win where incidents overlap.
_RANK = {"down": 3, "critical": 2, "warning": 1}


class Segment(BaseModel):
    start: int
    end: int
    state: TimelineState


class HistoryItem(BaseModel):
    id: uuid.UUID
    state: TimelineState
    summary: str
    opened_at: int
    resolved_at: int | None
    duration_seconds: int


class ServerSummary(BaseModel):
    range_seconds: int
    # Share of the range the agent reported (pushes received / expected).
    availability_percent: float | None
    downtimes: int
    downtime_seconds: int
    timeline: list[Segment]
    history: list[HistoryItem]
    # The open incidents, worst first: what is wrong right now.
    root_causes: list[str]
    uptime_seconds: float | None
    processes: float | None
    sessions: float | None
    open_files: float | None
    listening_ports: int | None


def timeline(spans: list[tuple[int, int, str]], start: int, end: int) -> list[Segment]:
    """Merge incident spans (start, end, state) into non-overlapping segments
    within [start, end], the worst state winning where they overlap."""
    edges = sorted({start, end, *(t for s, e, _ in spans for t in (s, e) if start < t < end)})
    out: list[Segment] = []
    for a, b in zip(edges, edges[1:], strict=False):
        live = [st for s, e, st in spans if s < b and e > a]
        if not live:
            continue
        state = max(live, key=lambda st: _RANK[st])
        if out and out[-1].state == state and out[-1].end == a:
            out[-1].end = b
        else:
            out.append(Segment(start=a, end=b, state=cast(TimelineState, state)))
    return out


async def summary_for(db, tenant_id: uuid.UUID, host: Host, range_seconds: int) -> ServerSummary:
    """Availability, incident timeline and history, and a few system facts
    for one server over the last range_seconds (also the staff view's)."""
    from datetime import UTC, datetime

    from app.models import AlertRule, HostInventory
    from app.services.reports import PUSH_SECONDS

    now = int(time.time())
    start = now - range_seconds
    since = datetime.fromtimestamp(start, UTC)
    rows = await db.execute(
        select(Incident, AlertRule.kind)
        .outerjoin(AlertRule, AlertRule.id == Incident.rule_id)
        .where(
            Incident.tenant_id == tenant_id,
            Incident.host_id == host.id,
            Incident.merged_into.is_(None),
            (Incident.resolved_at.is_(None)) | (Incident.resolved_at > since),
        )
        .order_by(Incident.opened_at.desc())
    )
    spans: list[tuple[int, int, str]] = []
    history: list[HistoryItem] = []
    open_now: list[tuple[int, str]] = []
    downtimes = 0
    for inc, kind in rows:
        state = "down" if kind == "host_down" else inc.severity
        if state not in _RANK:
            continue  # info
        opened = int(inc.opened_at.timestamp())
        closed = int(inc.resolved_at.timestamp()) if inc.resolved_at else None
        spans.append((max(opened, start), closed or now, state))
        downtimes += state == "down"
        history.append(
            HistoryItem(
                id=inc.id,
                state=cast(TimelineState, state),
                summary=inc.summary,
                opened_at=opened,
                resolved_at=closed,
                duration_seconds=(closed or now) - opened,
            )
        )
        if closed is None:
            open_now.append((_RANK[state], inc.summary))
    segs = timeline(spans, start, now)

    sel = f'host_id="{host.id}"'

    async def one(query: str) -> float | None:
        res = await metrics.query_instant(tenant_id, query)
        return res[0][1] if res else None

    availability = uptime = processes = sessions = open_files = None
    try:
        observed = min(range_seconds, max(now - int(host.created_at.timestamp()), 0))
        if observed >= PUSH_SECONDS:
            pushes = await one(
                f"count_over_time(sentinel_uptime_seconds{{{sel}}}[{range_seconds}s])"
            )
            availability = round(min((pushes or 0) / (observed / PUSH_SECONDS) * 100, 100.0), 2)
        uptime = await one(f"last_over_time(sentinel_uptime_seconds{{{sel}}}[10m])")
        processes = await one(f"last_over_time(sentinel_processes_total{{{sel}}}[10m])")
        sessions = await one(f"last_over_time(sentinel_users_logged_in{{{sel}}}[10m])")
        open_files = await one(f"last_over_time(sentinel_open_files{{{sel}}}[10m])")
    except MetricsUnavailable:
        pass
    inv = await db.scalar(select(HostInventory).where(HostInventory.host_id == host.id))
    ports = None
    if inv is not None:
        ports = len(
            {
                (p.get("port"), p.get("protocol"))
                for p in (inv.data or {}).get("listening_ports") or []
            }
        )
    return ServerSummary(
        range_seconds=range_seconds,
        availability_percent=availability,
        downtimes=downtimes,
        downtime_seconds=sum(s.end - s.start for s in segs if s.state == "down"),
        timeline=segs,
        history=history[:50],
        root_causes=[s for _, s in sorted(open_now, key=lambda x: -x[0])][:3],
        uptime_seconds=uptime,
        processes=processes,
        sessions=sessions,
        open_files=open_files,
        listening_ports=ports,
    )


@router.get("/hosts/{host_id}/summary")
async def host_summary(
    host_id: uuid.UUID, t: Tenant, range: Annotated[int, Query(ge=3600, le=90 * 86400)] = 86400
) -> ServerSummary:
    host = await t.db.scalar(select(Host).where(Host.id == host_id, Host.tenant_id == t.tenant_id))
    if host is None:
        raise HTTPException(status_code=404, detail="Host not found")
    return await summary_for(t.db, t.tenant_id, host, range)


# ── Forecast ─────────────────────────────────────────────────────────────


class ForecastSeries(BaseModel):
    key: str  # cpu, memory, disk:<mountpoint>
    label: str
    history: list[list[float]]  # hourly averages [ts, percent]
    trend: list[list[float]]
    upper: list[list[float]]
    slope_per_day: float
    reaches_at: int | None


class ForecastOut(BaseModel):
    limit: float
    horizon_days: int
    # Resources without a day of history are listed here, not projected.
    waiting: list[str]
    series: list[ForecastSeries]


async def forecast_for(tenant_id: uuid.UUID, host_id: uuid.UUID, days: int) -> ForecastOut:
    """CPU, memory and each disk's last 14 days (hourly averages) and where
    their trend puts them over the next `days` (also the staff view's)."""
    from app.services.forecast import project

    limit = 90.0
    now = int(time.time())
    start = now - 14 * 86400
    sel = f'host_id="{host_id}"'
    wanted = [
        ("cpu", "CPU", f"avg_over_time(sentinel_cpu_usage_percent{{{sel}}}[1h])", []),
        ("memory", "Memory", f"avg_over_time(sentinel_memory_used_percent{{{sel}}}[1h])", []),
        (
            "disk",
            "Disk",
            f"avg_over_time(sentinel_disk_used_percent{{{sel}}}[1h])",
            ["mountpoint"],
        ),
    ]
    out: list[ForecastSeries] = []
    waiting: list[str] = []
    try:
        for key, label, query, legend in wanted:
            for s in await metrics.query_series(tenant_id, query, start, now, 3600, legend):
                mount = s["labels"].get("mountpoint")
                name = f"{label} {mount}" if mount else label
                p = project(s["points"], horizon=days * 86400, step=3600, limit=limit)
                if p is None:
                    waiting.append(name)
                    continue
                out.append(
                    ForecastSeries(
                        key=f"{key}:{mount}" if mount else key,
                        label=name,
                        history=s["points"],
                        trend=p.points,
                        upper=p.upper,
                        slope_per_day=p.slope_per_day,
                        reaches_at=p.reaches_at,
                    )
                )
    except MetricsUnavailable:
        raise HTTPException(status_code=503, detail="Metrics are unavailable right now") from None
    out.sort(key=lambda s: (s.reaches_at is None, s.reaches_at or 0, s.key))
    return ForecastOut(limit=limit, horizon_days=days, waiting=waiting, series=out)


@router.get("/hosts/{host_id}/forecast")
async def host_forecast(
    host_id: uuid.UUID, t: Tenant, days: Annotated[int, Query(ge=1, le=30)] = 7
) -> ForecastOut:
    host = await t.db.scalar(select(Host).where(Host.id == host_id, Host.tenant_id == t.tenant_id))
    if host is None:
        raise HTTPException(status_code=404, detail="Host not found")
    return await forecast_for(t.tenant_id, host.id, days)
