"""At-a-glance views: every server's health on one screen (status counts,
CPU, memory, fullest disk, load), and a server's disks with a forecast."""

import uuid
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select

from app.models import Host, Incident
from app.routes.v1 import _hosts_out
from app.services import metrics
from app.services.metrics import MetricsUnavailable
from app.tenancy import Tenant

router = APIRouter(prefix="/v1", tags=["servers"])

Status = Literal["down", "critical", "warning", "maintenance", "up"]


class ServerHealth(BaseModel):
    id: uuid.UUID
    hostname: str
    status: Status
    online: bool
    in_maintenance: bool
    cpu: float | None
    memory: float | None
    disk: float | None
    load1: float | None
    cpu_cores: int | None
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
    the worst open incident; maintenance; up) and latest CPU, memory, fullest
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
            t.tenant_id, "max by (host_id) (last_over_time(pulsegrid_cpu_usage_percent[3m]))"
        )
        mem = await _latest(
            t.tenant_id, "max by (host_id) (last_over_time(pulsegrid_memory_used_percent[3m]))"
        )
        disk = await _latest(
            t.tenant_id, "max by (host_id) (last_over_time(pulsegrid_disk_used_percent[5m]))"
        )
        load = await _latest(
            t.tenant_id, 'max by (host_id) (last_over_time(pulsegrid_load{period="1m"}[3m]))'
        )
    except MetricsUnavailable:
        cpu = mem = disk = load = {}
        available = False
    counts = {"down": 0, "critical": 0, "warning": 0, "maintenance": 0, "up": 0}
    servers = []
    for h in hosts:
        o = outs[h.id]
        sev = open_by_host.get(h.id, {})
        status: Status
        if not o.online:
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
                cpu=r(cpu.get(key)) if o.online else None,
                memory=r(mem.get(key)) if o.online else None,
                disk=r(disk.get(key)),
                load1=r(load.get(key)) if o.online else None,
                cpu_cores=h.cpu_cores,
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
    sel = f'host_id="{host.id}"'

    async def by_mount(query: str) -> dict[str, tuple[dict, float]]:
        return {
            labels.get("mountpoint", ""): (labels, v)
            for labels, v in await metrics.query_instant(t.tenant_id, query)
        }

    try:
        used_pct = await by_mount(f"last_over_time(pulsegrid_disk_used_percent{{{sel}}}[10m])")
        free = await by_mount(f"last_over_time(pulsegrid_disk_free_bytes{{{sel}}}[10m])")
        total = await by_mount(f"last_over_time(pulsegrid_disk_total_bytes{{{sel}}}[10m])")
        used = await by_mount(f"last_over_time(pulsegrid_disk_used_bytes{{{sel}}}[10m])")
        inodes = await by_mount(f"last_over_time(pulsegrid_disk_inodes_used_percent{{{sel}}}[10m])")
        predicted = await by_mount(
            f"predict_linear(pulsegrid_disk_used_percent{{{sel}}}[24h], 7 * 86400)"
        )
        slope = await by_mount(f"deriv(pulsegrid_disk_used_percent{{{sel}}}[24h])")
    except MetricsUnavailable:
        raise HTTPException(status_code=503, detail="Metrics are unavailable right now") from None
    out = []
    for mount, (labels, pct) in sorted(used_pct.items()):
        free_b = free.get(mount, ({}, None))[1]
        total_b = total.get(mount, ({}, None))[1]
        if total_b is None and free_b is not None and pct < 100:
            total_b = free_b / (1 - pct / 100)  # agents before 0.7 sent no total
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
