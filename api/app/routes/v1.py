"""Customer-facing API, called by the console dashboard with the user's console JWT.

Every handler takes `t: Tenant`, which carries a session already scoped to the
caller's tenant by RLS. Queries also filter on tenant_id explicitly: RLS is the
safety net, not an excuse to leave the filter out.
"""

import time
import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import AgentKey, AlertRule, AlertState, Host, Incident, MaintenanceWindow
from app.models import Tenant as TenantRow
from app.services import heartbeats, metrics
from app.services.maintenance import in_maintenance
from app.services.secrets import new_agent_key
from app.tenancy import Tenant, TenantContext, actor_of
from app.validation import Trimmed, normalize_tags

router = APIRouter(prefix="/v1")


def install_command(key: str, tags: list[str] | None = None) -> str:
    """Linux and BSD (FreeBSD/OpenBSD/NetBSD)."""
    extra = f" --tags {','.join(tags)}" if tags else ""
    return f"curl -fsSL {settings.PUBLIC_DOWNLOAD_URL}/install.sh | sh -s -- --key {key}{extra}"


def install_command_windows(key: str, tags: list[str] | None = None) -> str:
    """Elevated PowerShell."""
    url = f"{settings.PUBLIC_DOWNLOAD_URL}/install.ps1"
    extra = f" -Tags {','.join(tags)}" if tags else ""
    return f"& ([scriptblock]::Create((irm {url}))) -Key {key}{extra}"


def docker_command(key: str, tags: list[str] | None = None) -> str:
    """The agent as a container watching its host (host /proc, /sys, /etc and
    the logind sessions read-only). The image updates itself; the volume keeps its identity."""
    extra = f" -e SENTINEL_TAGS={','.join(tags)}" if tags else ""
    return (
        "docker run -d --name sentinel-agent --restart unless-stopped --pid host --network host"
        " -v /proc:/host/proc:ro -v /sys:/host/sys:ro -v /etc:/host/etc:ro"
        " -v /run/systemd:/host/run/systemd:ro"
        " -e HOST_PROC=/host/proc -e HOST_SYS=/host/sys -e HOST_ETC=/host/etc -e HOST_RUN=/host/run"
        f" -e SENTINEL_URL={settings.PUBLIC_INGEST_URL} -e SENTINEL_KEY={key}{extra}"
        f" -v sentinel-agent:/var/lib/sentinel {settings.AGENT_IMAGE}"
    )


def cloud_init(key: str, tags: list[str] | None = None) -> str:
    """User data for a new Linux VM (cloud-init runs it once, as root, at
    first boot). It waits for the network, then installs the agent."""
    extra = f" --tags {','.join(tags)}" if tags else ""
    return (
        "#!/bin/sh\n"
        "# Installs the Sentinel monitoring agent at first boot.\n"
        f"url={settings.PUBLIC_DOWNLOAD_URL}/install.sh\n"
        "# Minimal images may have only one of curl and wget.\n"
        "for i in $(seq 1 30); do\n"
        "  if command -v curl >/dev/null; then\n"
        '    curl -fsSL "$url" -o /tmp/sentinel-install.sh && break\n'
        '  else wget -qO /tmp/sentinel-install.sh "$url" && break; fi\n'
        "  sleep 10\n"
        "done\n"
        f"sh /tmp/sentinel-install.sh --key {key}{extra}\n"
        "rm -f /tmp/sentinel-install.sh\n"
    )


# ── Account ──────────────────────────────────────────────────────────────────


class MeOut(BaseModel):
    tenant_id: uuid.UUID
    email: str | None
    display_name: str | None
    status: str
    created_at: datetime
    role: str = Field(default="owner", description="owner, admin, operator, viewer or staff")
    impersonating: bool = Field(default=False, description="a superadmin working here")
    impersonation_writes: bool = False


@router.get("/me")
async def me(t: Tenant, tasks: BackgroundTasks) -> MeOut:
    from app.routes.alerts import ensure_recommended

    # The dashboard opens with this: a new account gets the recommended
    # rules (after the response, once the account is committed).
    tasks.add_task(ensure_recommended, t.tenant_id)
    row = await t.db.get_one(TenantRow, t.tenant_id)
    return MeOut(
        tenant_id=row.id,
        email=row.email,
        display_name=row.display_name,
        status=row.status,
        created_at=row.created_at,
        role=t.role,
        impersonating=t.principal.impersonated,
        impersonation_writes=t.principal.impersonation_writes,
    )


# ── Agent install keys ───────────────────────────────────────────────────────


class AgentKeyIn(BaseModel):
    name: Annotated[str, Trimmed, Field(min_length=1, max_length=100)]
    tags: list[str] = Field(default_factory=list, description="added to servers installed with it")

    @field_validator("tags")
    @classmethod
    def _tags(cls, v: list[str]) -> list[str]:
        return normalize_tags(v)


class AgentKeyOut(BaseModel):
    id: uuid.UUID
    name: str
    key_prefix: str
    created_at: datetime
    revoked_at: datetime | None


class AgentKeyCreated(AgentKeyOut):
    key: str  # shown once; only the hash is stored
    install_command: str
    install_command_windows: str
    cloud_init: str  # user data that installs the agent on a new Linux VM
    docker_command: str = ""  # the self-updating agent container


def _agent_key_out(k: AgentKey) -> AgentKeyOut:
    return AgentKeyOut(
        id=k.id,
        name=k.name,
        key_prefix=k.key_prefix,
        created_at=k.created_at,
        revoked_at=k.revoked_at,
    )


@router.get("/agent-keys")
async def list_agent_keys(t: Tenant) -> list[AgentKeyOut]:
    rows = await t.db.scalars(
        select(AgentKey).where(AgentKey.tenant_id == t.tenant_id).order_by(AgentKey.created_at)
    )
    return [_agent_key_out(k) for k in rows]


@router.post("/agent-keys", status_code=status.HTTP_201_CREATED)
async def create_agent_key(body: AgentKeyIn, t: Tenant) -> AgentKeyCreated:
    plaintext, prefix, key_hash = new_agent_key()
    key = AgentKey(tenant_id=t.tenant_id, name=body.name, key_prefix=prefix, key_hash=key_hash)
    t.db.add(key)
    await t.db.flush()
    await t.db.refresh(key)
    return AgentKeyCreated(
        **_agent_key_out(key).model_dump(),
        key=plaintext,
        install_command=install_command(plaintext, body.tags),
        install_command_windows=install_command_windows(plaintext, body.tags),
        cloud_init=cloud_init(plaintext, body.tags),
        docker_command=docker_command(plaintext, body.tags),
    )


@router.delete("/agent-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_agent_key(key_id: uuid.UUID, t: Tenant) -> None:
    """Stops new installs with this key. Hosts already registered keep working."""
    key = await t.db.scalar(
        select(AgentKey).where(AgentKey.id == key_id, AgentKey.tenant_id == t.tenant_id)
    )
    if key is None:
        raise HTTPException(status_code=404, detail="Agent key not found")
    if key.revoked_at is None:
        key.revoked_at = datetime.now(UTC)


# ── Hosts ────────────────────────────────────────────────────────────────────


class HostOut(BaseModel):
    id: uuid.UUID
    hostname: str
    os: str | None
    platform: str | None
    platform_version: str | None
    arch: str | None
    agent_version: str | None
    online: bool
    last_seen: int | None  # unix seconds
    created_at: datetime
    tags: list[str]
    depends_on_host_id: uuid.UUID | None
    ip_addresses: list[str]
    public_ip: str | None = None
    cpu_cores: int | None
    memory_bytes: int | None
    in_maintenance: bool
    notes: str | None = None
    notes_updated_at: datetime | None = None
    notes_updated_by: str | None = None
    paused: bool = False
    paused_at: datetime | None = None
    paused_by: str | None = None
    kind: Literal["server", "network"] = "server"
    address: str | None = Field(default=None, description="network devices: what's polled")
    poller_host_id: uuid.UUID | None = Field(
        default=None, description="network devices: the server that polls it"
    )
    network_role: str | None = None
    vendor: str | None = None
    device_error: str | None = Field(
        default=None, description="network devices: why the last poll failed"
    )
    depends_on_auto: bool = Field(default=False, description="set from LLDP topology")


def _host_out(h: Host, last_seen: int | None, maintenance: bool = False) -> HostOut:
    return HostOut(
        id=h.id,
        hostname=h.hostname,
        os=h.os,
        platform=h.platform,
        platform_version=h.platform_version,
        arch=h.arch,
        agent_version=h.agent_version,
        online=heartbeats.is_online(last_seen),
        last_seen=last_seen,
        created_at=h.created_at,
        tags=list(h.tags or []),
        depends_on_host_id=h.depends_on_host_id,
        ip_addresses=list(h.ip_addresses or []),
        public_ip=h.public_ip,
        cpu_cores=h.cpu_cores,
        memory_bytes=h.memory_bytes,
        in_maintenance=maintenance,
        notes=h.notes,
        notes_updated_at=h.notes_updated_at,
        notes_updated_by=h.notes_updated_by,
        paused=h.paused_at is not None,
        paused_at=h.paused_at,
        paused_by=h.paused_by,
        kind="network" if h.kind == "network" else "server",
        address=h.address,
        poller_host_id=h.poller_host_id,
        network_role=h.network_role,
        vendor=((h.device or {}).get("system") or {}).get("vendor")
        if h.kind == "network"
        else None,
        device_error=h.device_error,
        depends_on_auto=h.depends_on_auto,
    )


async def _windows(t: TenantContext) -> list[MaintenanceWindow]:
    return list(
        await t.db.scalars(
            select(MaintenanceWindow).where(
                MaintenanceWindow.tenant_id == t.tenant_id, MaintenanceWindow.enabled
            )
        )
    )


async def _hosts_out(t: TenantContext, hosts: list[Host]) -> list[HostOut]:
    seen = await heartbeats.last_seen([h.id for h in hosts])
    windows = await _windows(t)
    now = datetime.now(UTC)
    return [_host_out(h, seen[h.id], in_maintenance(windows, h, now)) for h in hosts]


async def _get_host(t: TenantContext, host_id: uuid.UUID) -> Host:
    host = await t.db.scalar(select(Host).where(Host.id == host_id, Host.tenant_id == t.tenant_id))
    if host is None:
        raise HTTPException(status_code=404, detail="Host not found")
    return host


@router.get("/hosts")
async def list_hosts(
    t: Tenant,
    tag: Annotated[str | None, Query(description="only hosts with this tag")] = None,
    ip: Annotated[str | None, Query(description="only hosts with this IP address")] = None,
) -> list[HostOut]:
    q = select(Host).where(Host.tenant_id == t.tenant_id)
    if tag:
        q = q.where(Host.tags.contains([tag.strip().lower()]))
    if ip:
        q = q.where(Host.ip_addresses.contains([ip.strip()]))
    hosts = list(await t.db.scalars(q.order_by(Host.hostname)))
    return await _hosts_out(t, hosts)


@router.get("/hosts/{host_id}")
async def get_host(host_id: uuid.UUID, t: Tenant) -> HostOut:
    host = await _get_host(t, host_id)
    return (await _hosts_out(t, [host]))[0]


class HostPatch(BaseModel):
    tags: list[str] | None = None
    depends_on_host_id: uuid.UUID | None = Field(
        default=None, description="alerts are held back while this host is silent"
    )
    clear_depends_on: bool = False
    notes: str | None = Field(
        default=None, max_length=4000, description="free text; an empty string clears it"
    )

    @field_validator("tags")
    @classmethod
    def _tags(cls, v: list[str] | None) -> list[str] | None:
        return None if v is None else normalize_tags(v)


@router.patch("/hosts/{host_id}")
async def update_host(host_id: uuid.UUID, body: HostPatch, t: Tenant) -> HostOut:
    host = await _get_host(t, host_id)
    if body.tags is not None:
        host.tags = body.tags
    # Set by hand: topology leaves it alone from now on.
    if body.clear_depends_on:
        host.depends_on_host_id, host.depends_on_auto = None, False
    elif body.depends_on_host_id is not None:
        await _check_dependency(t, host, body.depends_on_host_id)
        host.depends_on_host_id, host.depends_on_auto = body.depends_on_host_id, False
    if body.notes is not None:
        host.notes = body.notes.strip() or None
        host.notes_updated_at = datetime.now(UTC)
        host.notes_updated_by = actor_of(t.principal)
    await t.db.flush()
    return (await _hosts_out(t, [host]))[0]


async def pause_hosts(t: TenantContext, hosts: list[Host]) -> None:
    """Stop monitoring these servers until resumed: their open incidents
    close (quietly, with a note) and any half-fired alert state is dropped,
    so resuming starts clean."""
    from app.models import AlertState, Incident, IncidentEvent

    now = datetime.now(UTC)
    actor = actor_of(t.principal)
    ids = [h.id for h in hosts if h.paused_at is None]
    for h in hosts:
        if h.paused_at is None:
            h.paused_at, h.paused_by = now, actor
    if not ids:
        return
    open_incidents = list(
        await t.db.scalars(
            select(Incident).where(
                Incident.tenant_id == t.tenant_id,
                Incident.host_id.in_(ids),
                Incident.status == "open",
            )
        )
    )
    for incident in open_incidents:
        incident.status = "resolved"
        incident.resolved_at = now
        incident.resolved_by = actor
        t.db.add(
            IncidentEvent(
                tenant_id=t.tenant_id,
                incident_id=incident.id,
                kind="resolved",
                message="Closed: monitoring was paused for this server",
                actor=actor,
            )
        )
    await t.db.execute(
        delete(AlertState).where(AlertState.tenant_id == t.tenant_id, AlertState.host_id.in_(ids))
    )


def resume_hosts(hosts: list[Host]) -> None:
    for h in hosts:
        h.paused_at = h.paused_by = None


@router.post("/hosts/{host_id}/pause")
async def pause_host(host_id: uuid.UUID, t: Tenant) -> HostOut:
    """Pause monitoring: no alerts or incidents for this server until it's
    resumed. Its metrics are still collected."""
    host = await _get_host(t, host_id)
    await pause_hosts(t, [host])
    await t.db.flush()
    return (await _hosts_out(t, [host]))[0]


@router.post("/hosts/{host_id}/resume")
async def resume_host(host_id: uuid.UUID, t: Tenant) -> HostOut:
    host = await _get_host(t, host_id)
    resume_hosts([host])
    await t.db.flush()
    return (await _hosts_out(t, [host]))[0]


async def _check_dependency(t: TenantContext, host: Host, parent_id: uuid.UUID) -> None:
    """The parent must be the tenant's own, and following parents from it
    must never come back to this host (a loop would hide both hosts' alerts
    whenever either went quiet)."""
    if parent_id == host.id:
        raise HTTPException(status_code=422, detail="A server can't depend on itself")
    current: uuid.UUID | None = parent_id
    for _ in range(50):
        if current is None:
            return
        row = await t.db.scalar(
            select(Host).where(Host.id == current, Host.tenant_id == t.tenant_id)
        )
        if row is None:
            raise HTTPException(status_code=422, detail="depends_on_host_id not found")
        if row.depends_on_host_id == host.id:
            raise HTTPException(
                status_code=422, detail="That would make the servers depend on each other"
            )
        current = row.depends_on_host_id
    raise HTTPException(status_code=422, detail="Dependency chain is too long")


@router.delete("/hosts/{host_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_host(host_id: uuid.UUID, t: Tenant) -> None:
    """Removes the host; its agent's token stops working immediately. Its
    open incidents resolve (nothing else ever would) and its alert state goes."""
    host = await _get_host(t, host_id)
    polled = await t.db.scalar(
        select(func.count())
        .select_from(Host)
        .where(Host.tenant_id == t.tenant_id, Host.poller_host_id == host.id)
    )
    if polled:
        raise HTTPException(
            status_code=409,
            detail=f"This server polls {polled} network device{'s' if polled != 1 else ''}: "
            "move them to another server or remove them first",
        )
    await t.db.execute(
        update(Incident)
        .where(
            Incident.tenant_id == t.tenant_id,
            Incident.host_id == host.id,
            Incident.status == "open",
        )
        .values(status="resolved", resolved_at=datetime.now(UTC), resolved_by="server removed")
    )
    await t.db.execute(
        delete(AlertState).where(AlertState.tenant_id == t.tenant_id, AlertState.host_id == host.id)
    )
    await t.db.delete(host)
    if host.token_hash:
        await heartbeats.forget_host_tokens([host.token_hash])
    try:
        await metrics.delete_host_series(t.tenant_id, host.id)
    except metrics.MetricsUnavailable:
        # The host is gone either way; its series age out with retention.
        pass


class TagOut(BaseModel):
    tag: str
    hosts: int


@router.get("/tags")
async def list_tags(t: Tenant) -> list[TagOut]:
    tag = func.unnest(Host.tags).label("tag")
    sub = select(tag).where(Host.tenant_id == t.tenant_id).subquery()
    rows = await t.db.execute(
        select(sub.c.tag, func.count()).group_by(sub.c.tag).order_by(sub.c.tag)
    )
    return [TagOut(tag=r[0], hosts=r[1]) for r in rows]


class ProcessOut(BaseModel):
    name: str
    cpu_percent: float | None  # share of the whole machine
    memory_bytes: float | None
    count: int | None


class ProcessesOut(BaseModel):
    total: int | None  # every process on the host
    processes: list[ProcessOut]  # the busiest by CPU and by memory


@router.get("/hosts/{host_id}/processes")
async def host_processes(host_id: uuid.UUID, t: Tenant) -> ProcessesOut:
    host = await _get_host(t, host_id)
    return await processes_of(t.tenant_id, host.id)


async def processes_of(tenant_id: uuid.UUID, host_id: uuid.UUID) -> ProcessesOut:
    """Latest top processes from the agent. Names that dropped out of the
    agent's top list in the last minute still show, with their last values."""
    try:
        cpu = await metrics.query_latest(tenant_id, host_id, "sentinel_process_cpu_percent", "90s")
        mem = await metrics.query_latest(tenant_id, host_id, "sentinel_process_memory_bytes", "90s")
        cnt = await metrics.query_latest(tenant_id, host_id, "sentinel_process_count", "90s")
        total = await metrics.query_latest(tenant_id, host_id, "sentinel_processes_total", "3m")
    except metrics.MetricsUnavailable:
        raise HTTPException(status_code=503, detail="Metrics store unavailable") from None
    rows: dict[str, ProcessOut] = {}

    def row(labels: dict[str, str]) -> ProcessOut:
        name = labels.get("process", "")
        return rows.setdefault(
            name, ProcessOut(name=name, cpu_percent=None, memory_bytes=None, count=None)
        )

    for labels, v in cpu:
        row(labels).cpu_percent = v
    for labels, v in mem:
        row(labels).memory_bytes = v
    for labels, v in cnt:
        row(labels).count = int(v)
    ordered = sorted(
        rows.values(), key=lambda p: (-(p.cpu_percent or 0), -(p.memory_bytes or 0), p.name)
    )
    return ProcessesOut(total=int(total[0][1]) if total else None, processes=ordered)


class CheckOut(BaseModel):
    kind: Literal["process", "service"]
    name: str
    # running / stopped as last reported; "waiting" until the agent first
    # reports it (it picks up new watches within a couple of minutes).
    state: Literal["running", "stopped", "waiting"]
    processes: int | None  # for processes: how many are running
    rule_ids: list[uuid.UUID]


class ChecksOut(BaseModel):
    checks: list[CheckOut]
    failed_units: int | None  # systemd units in the failed state (Linux)


@router.get("/hosts/{host_id}/checks")
async def host_checks(host_id: uuid.UUID, t: Tenant) -> ChecksOut:
    """The processes and services this host's alert rules watch, and their
    state as last reported by the agent."""
    return await checks_of(t.db, await _get_host(t, host_id))


async def checks_of(db: AsyncSession, host: Host) -> ChecksOut:
    rules = await db.scalars(
        select(AlertRule).where(
            AlertRule.tenant_id == host.tenant_id,
            AlertRule.kind.in_(["process_down", "service_down"]),
            AlertRule.enabled,
            or_(AlertRule.host_id.is_(None), AlertRule.host_id == host.id),
        )
    )
    wanted: dict[tuple[Literal["process", "service"], str], list[uuid.UUID]] = {}
    for r in rules:
        if r.tag is not None and r.tag not in (host.tags or []):
            continue
        kind: Literal["process", "service"] = "process" if r.kind == "process_down" else "service"
        wanted.setdefault((kind, r.target or ""), []).append(r.id)
    try:
        procs = await metrics.query_latest(
            host.tenant_id, host.id, "sentinel_watched_process_count"
        )
        svcs = await metrics.query_latest(host.tenant_id, host.id, "sentinel_service_up")
        failed = await metrics.query_latest(
            host.tenant_id, host.id, "sentinel_systemd_failed_units"
        )
    except metrics.MetricsUnavailable:
        raise HTTPException(status_code=503, detail="Metrics store unavailable") from None
    seen_procs = {labels.get("process"): v for labels, v in procs}
    seen_svcs = {labels.get("service"): v for labels, v in svcs}
    checks = []
    for (kind, name), rule_ids in sorted(wanted.items()):
        value = (seen_procs if kind == "process" else seen_svcs).get(name)
        state = "waiting" if value is None else ("running" if value >= 1 else "stopped")
        checks.append(
            CheckOut(
                kind=kind,
                name=name,
                state=state,
                processes=int(value) if kind == "process" and value is not None else None,
                rule_ids=rule_ids,
            )
        )
    return ChecksOut(checks=checks, failed_units=int(failed[0][1]) if failed else None)


class Series(BaseModel):
    labels: dict[str, str]
    points: list[list[float]]  # [unix seconds, value]


class MetricsOut(BaseModel):
    metric: str
    unit: str
    series: list[Series]


MetricName = Literal[
    "cpu",
    "cpu_modes",
    "cpu_cores",
    "memory",
    "swap",
    "disk",
    "inodes",
    "disk_io",
    "disk_iops",
    "disk_busy",
    "load",
    "network",
    "processes",
    "memory_breakdown",
    "swap_io",
    "page_faults",
    "disk_latency",
    "disk_queue",
    "network_interfaces",
    "network_packets",
    "network_errors",
    "tcp_connections",
    "context_switches",
    "proc_states",
    "threads",
    "pressure",
    "users_logged_in",
    "open_files",
    "user_cpu",
    "user_memory",
    "process_cpu",
    "process_memory",
]


@router.get("/hosts/{host_id}/metrics")
async def host_metrics(
    host_id: uuid.UUID,
    t: Tenant,
    metric: MetricName,
    start: Annotated[int | None, Query(description="unix seconds; default 1h ago")] = None,
    end: Annotated[int | None, Query(description="unix seconds; default now")] = None,
    step: Annotated[int, Query(ge=15, le=86400)] = 60,
) -> MetricsOut:
    host = await _get_host(t, host_id)
    end = end or int(time.time())
    start = start or end - 3600
    if start >= end:
        raise HTTPException(status_code=422, detail="start must be before end")
    if (end - start) / step > 11000:
        raise HTTPException(status_code=422, detail="Too many points; increase step")
    try:
        series = await metrics.query_range(t.tenant_id, host.id, metric, start, end, step)
    except metrics.MetricsUnavailable:
        raise HTTPException(status_code=503, detail="Metrics store unavailable") from None
    return MetricsOut(
        metric=metric,
        unit=metrics.CATALOG[metric].unit,
        series=[Series(**s) for s in series],
    )
