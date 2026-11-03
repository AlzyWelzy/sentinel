"""The superadmin panel: every organisation, the fleet, agent rollouts.

Superadmins are Sentinel users with is_superadmin (from SUPERADMIN_EMAILS).
They see every organisation's servers, charts and incidents here, manage
organisations (suspend, resume, delete), the agent rollout and probes. To
work inside an organisation they start an impersonation: audited, with a
reason, time-limited and read-only unless they ask for writes.

These routes use the cross-tenant service role, so the superadmin check
below is the only gate. Keep every handler behind `staff`.
"""

import time
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import Text, cast, func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.native import issue_access_token
from app.auth.principal import Principal
from app.config import settings
from app.db import AppSession, service_session
from app.models import AgentKey, Check, Host, Incident, IncidentEvent, Tenant
from app.routes import audit as audit_routes
from app.routes import reports as report_routes
from app.routes import v1
from app.routes.alerts import (
    IncidentDetail,
    IncidentEventOut,
    IncidentOut,
    _incident_out,
    add_recommended_to,
    ensure_recommended,
)
from app.routes.checks import CheckStatus, _status
from app.routes.fleetview import (
    DiskOut,
    ForecastOut,
    ServerSummary,
    disks_for,
    forecast_for,
    summary_for,
)
from app.routes.v1 import (
    AgentKeyCreated,
    AgentKeyIn,
    ChecksOut,
    HostOut,
    MetricName,
    MetricsOut,
    ProcessesOut,
    Series,
    _agent_key_out,
    _host_out,
    checks_of,
    cloud_init,
    docker_command,
    install_command,
    install_command_windows,
    processes_of,
)
from app.services import audit, checkresults, heartbeats, hostpdf, metrics, oncall, rollout, tenants
from app.services.secrets import new_agent_key
from app.tenancy import TenantContext, current_principal


async def staff(principal: Annotated[Principal, Depends(current_principal)]) -> Principal:
    if not principal.superadmin or principal.impersonated or principal.api_token_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Superadmins only")
    return principal


ServiceDB = Annotated[AsyncSession, Depends(service_session, scope="function")]


async def staff_audit(
    request: Request,
    db: ServiceDB,
    principal: Annotated[Principal, Depends(staff)],
) -> AsyncIterator[None]:
    """Staff changes go into the audit log (the account's, when it's about one)."""
    yield
    if request.method.upper() not in ("GET", "HEAD", "OPTIONS"):
        tenant = request.path_params.get("tenant_id")
        await audit.record_safely(
            db,
            request,
            tenant_id=uuid.UUID(str(tenant)) if tenant else None,
            actor=f"{principal.email} (superadmin)",
            actor_kind="staff",
        )


router = APIRouter(
    prefix="/admin/v1", dependencies=[Depends(staff), Depends(staff_audit, scope="function")]
)


class Overview(BaseModel):
    tenants: int
    hosts: int
    hosts_online: int
    open_incidents: int


class TenantSummary(BaseModel):
    id: uuid.UUID
    email: str | None
    display_name: str | None
    status: str
    hosts: int
    hosts_online: int
    open_incidents: int
    created_at: datetime


async def _online_counts(db: AsyncSession, tenant_ids: list[uuid.UUID] | None = None) -> dict:
    """Online hosts per tenant, from the live heartbeats in Redis."""
    q = select(Host.id, Host.tenant_id).where(Host.revoked_at.is_(None))
    if tenant_ids is not None:
        q = q.where(Host.tenant_id.in_(tenant_ids))
    rows = (await db.execute(q)).all()
    seen = await heartbeats.last_seen([r.id for r in rows])
    counts: dict[uuid.UUID, int] = {}
    for r in rows:
        if heartbeats.is_online(seen[r.id]):
            counts[r.tenant_id] = counts.get(r.tenant_id, 0) + 1
    return counts


@router.get("/overview")
async def overview(db: ServiceDB) -> Overview:
    tenants = await db.scalar(select(func.count()).select_from(Tenant)) or 0
    hosts = (
        await db.scalar(select(func.count()).select_from(Host).where(Host.revoked_at.is_(None)))
        or 0
    )
    open_incidents = (
        await db.scalar(select(func.count()).select_from(Incident).where(Incident.status == "open"))
        or 0
    )
    online = sum((await _online_counts(db)).values())
    return Overview(
        tenants=tenants, hosts=hosts, hosts_online=online, open_incidents=open_incidents
    )


@router.get("/tenants")
async def list_tenants(
    db: ServiceDB,
    q: Annotated[
        str | None, Query(max_length=200, description="email, name or organisation id")
    ] = None,
    with_hosts: bool = Query(default=True, description="only accounts that have servers"),
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[TenantSummary]:
    host_count = (
        select(func.count()).where(Host.tenant_id == Tenant.id, Host.revoked_at.is_(None))
    ).scalar_subquery()
    open_count = (
        select(func.count()).where(Incident.tenant_id == Tenant.id, Incident.status == "open")
    ).scalar_subquery()
    query = select(Tenant, host_count.label("hosts"), open_count.label("open_incidents"))
    if q:
        like = f"%{q.strip()}%"
        query = query.where(
            or_(
                Tenant.email.ilike(like),
                Tenant.display_name.ilike(like),
                cast(Tenant.id, Text).ilike(like),
            )
        )
    if with_hosts:
        query = query.where(host_count > 0)
    rows = (
        await db.execute(
            query.order_by(open_count.desc(), host_count.desc(), Tenant.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
    ).all()
    online = await _online_counts(db, [r.Tenant.id for r in rows])
    return [
        TenantSummary(
            id=r.Tenant.id,
            email=r.Tenant.email,
            display_name=r.Tenant.display_name,
            status=r.Tenant.status,
            hosts=r.hosts,
            hosts_online=online.get(r.Tenant.id, 0),
            open_incidents=r.open_incidents,
            created_at=r.Tenant.created_at,
        )
        for r in rows
    ]


@router.post("/tenants/{tenant_id}/agent-keys", status_code=status.HTTP_201_CREATED)
async def create_tenant_agent_key(
    tenant_id: uuid.UUID,
    body: AgentKeyIn,
    db: ServiceDB,
    principal: Annotated[Principal, Depends(staff)],
) -> AgentKeyCreated:
    """An install key in a customer's account, so staff can install the agent
    on the customer's server for them. The key shows in the account's own
    install keys, named after who made it, and can be revoked there."""
    if await db.get(Tenant, tenant_id) is None:
        raise HTTPException(status_code=404, detail="Account not found")
    plaintext, prefix, key_hash = new_agent_key()
    key = AgentKey(
        tenant_id=tenant_id,
        name=f"{body.name} (by {_actor(principal)})"[:100],
        key_prefix=prefix,
        key_hash=key_hash,
    )
    db.add(key)
    await db.flush()
    await db.refresh(key)
    # Customers may not manage rules themselves, so their first server
    # comes with the recommended ones.
    await ensure_recommended(tenant_id)
    return AgentKeyCreated(
        **_agent_key_out(key).model_dump(),
        key=plaintext,
        install_command=install_command(plaintext, body.tags),
        install_command_windows=install_command_windows(plaintext, body.tags),
        cloud_init=cloud_init(plaintext, body.tags),
        docker_command=docker_command(plaintext, body.tags),
    )


class RecommendedResult(BaseModel):
    accounts: int
    accounts_changed: int
    rules_added: int


@router.post("/alert-rules/recommended")
async def add_recommended_everywhere(db: ServiceDB) -> RecommendedResult:
    """Adds the recommended alert rules to every active account, skipping
    rules an account already has by name. Safe to run again."""
    tenant_ids = list(await db.scalars(select(Tenant.id).where(Tenant.status == "active")))
    added = [await add_recommended_to(tid) for tid in tenant_ids]
    await db.execute(
        text(
            "UPDATE tenants SET recommended_rules_at = coalesce(recommended_rules_at, now()) "
            "WHERE id = ANY(:ids)"
        ),
        {"ids": tenant_ids},
    )
    return RecommendedResult(
        accounts=len(tenant_ids),
        accounts_changed=sum(1 for n in added if n),
        rules_added=sum(added),
    )


@router.get("/tenants/{tenant_id}/hosts")
async def tenant_hosts(tenant_id: uuid.UUID, db: ServiceDB) -> list[HostOut]:
    if await db.get(Tenant, tenant_id) is None:
        raise HTTPException(status_code=404, detail="Account not found")
    hosts = list(
        await db.scalars(select(Host).where(Host.tenant_id == tenant_id).order_by(Host.hostname))
    )
    seen = await heartbeats.last_seen([h.id for h in hosts])
    return [_host_out(h, seen[h.id]) for h in hosts]


class StaffHost(HostOut):
    tenant_id: uuid.UUID
    account_email: str | None
    cpu: float | None = None
    memory: float | None = None
    disk: float | None = None
    load1: float | None = None
    uptime_seconds: float | None = None
    open_incidents: int = 0
    critical_incidents: int = 0


# Latest value per server across every account, for the staff list.
_LATEST = {
    "cpu": "max by (host_id) (last_over_time(sentinel_cpu_usage_percent[3m]))",
    "memory": "max by (host_id) (last_over_time(sentinel_memory_used_percent[3m]))",
    "disk": "max by (host_id) (last_over_time(sentinel_disk_used_percent[5m]))",
    "load1": 'max by (host_id) (last_over_time(sentinel_load{period="1m"}[3m]))',
    "uptime_seconds": "max by (host_id) (last_over_time(sentinel_uptime_seconds[3m]))",
}


async def _latest_all() -> dict[str, dict[str, float]]:
    out: dict[str, dict[str, float]] = {}
    try:
        for name, query in _LATEST.items():
            for labels, v in await metrics.query_instant_all(query):
                out.setdefault(labels.get("host_id", ""), {})[name] = v
    except metrics.MetricsUnavailable:
        return {}
    return out


@router.get("/hosts")
async def all_hosts(
    db: ServiceDB,
    q: Annotated[str | None, Query(max_length=200, description="hostname, tag or account")] = None,
    limit: Annotated[int, Query(ge=1, le=2000)] = 1000,
) -> list[StaffHost]:
    """Every server in every account, for staff who look after all of them."""
    query = (
        select(Host, Tenant.email)
        .join(Tenant, Tenant.id == Host.tenant_id)
        .where(Host.revoked_at.is_(None))
    )
    if q:
        like = f"%{q.strip()}%"
        query = query.where(
            or_(Host.hostname.ilike(like), Tenant.email.ilike(like), Host.public_ip == q.strip())
        )
    rows = (await db.execute(query.order_by(Tenant.email, Host.hostname).limit(limit))).all()
    seen = await heartbeats.last_seen([h.id for h, _ in rows])
    latest = await _latest_all()
    incidents: dict[uuid.UUID, dict[str, int]] = {}
    for row in await db.execute(
        select(Incident.host_id, Incident.severity, func.count())
        .where(Incident.status == "open", Incident.host_id.is_not(None))
        .group_by(Incident.host_id, Incident.severity)
    ):
        if row[0] is not None:
            incidents.setdefault(row[0], {})[str(row[1])] = int(row[2])
    out = []
    for h, e in rows:
        base = _host_out(h, seen[h.id])
        m = latest.get(str(h.id), {})
        live = {k: round(v, 1) for k, v in m.items() if base.online or k == "disk"}
        sev = incidents.get(h.id, {})
        out.append(
            StaffHost(
                **base.model_dump(),
                **live,
                tenant_id=h.tenant_id,
                account_email=e,
                open_incidents=sum(sev.values()),
                critical_incidents=sev.get("critical", 0),
            )
        )
    return out


class StaffCheck(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    account_email: str | None
    name: str
    type: str
    target: str
    on_probes: bool
    interval_seconds: int
    host_id: uuid.UUID | None
    tag: str | None
    status: CheckStatus
    latency_ms: float | None
    last_failure: str | None
    slo_target: float


@router.get("/checks")
async def all_checks(
    db: ServiceDB, limit: Annotated[int, Query(ge=1, le=2000)] = 1000
) -> list[StaffCheck]:
    """Every check in every account with its current status, failing first."""
    rows = (
        await db.execute(
            select(Check, Tenant.email)
            .join(Tenant, Tenant.id == Check.tenant_id)
            .order_by(Tenant.email, Check.name)
            .limit(limit)
        )
    ).all()
    ids = [c.id for c, _ in rows]
    latest = await checkresults.latest(ids)
    failures = await checkresults.last_failures(ids)
    out = []
    for c, email in rows:
        results = latest.get(c.id, [])
        lat = [r["latency_ms"] for r in results if r.get("latency_ms")]
        out.append(
            StaffCheck(
                id=c.id,
                tenant_id=c.tenant_id,
                account_email=email,
                name=c.name,
                type=c.type,
                target=c.target,
                on_probes=c.on_probes,
                interval_seconds=c.interval_seconds,
                host_id=c.host_id,
                tag=c.tag,
                status=_status(c, results),
                latency_ms=round(sum(lat) / len(lat), 1) if lat else None,
                last_failure=(failures.get(c.id) or {}).get("detail"),
                slo_target=float(c.slo_target),
            )
        )
    order = {"down": 0, "pending": 1, "up": 2, "paused": 3}
    out.sort(key=lambda x: order[x.status])
    return out


async def _host(db: AsyncSession, host_id: uuid.UUID) -> Host:
    host = await db.get(Host, host_id)
    if host is None:
        raise HTTPException(status_code=404, detail="Host not found")
    return host


@router.get("/hosts/{host_id}")
async def get_host(host_id: uuid.UUID, db: ServiceDB) -> HostOut:
    host = await _host(db, host_id)
    seen = await heartbeats.last_seen([host.id])
    return _host_out(host, seen[host.id])


@router.get("/hosts/{host_id}/metrics")
async def host_metrics(
    host_id: uuid.UUID,
    db: ServiceDB,
    metric: MetricName,
    start: int | None = None,
    end: int | None = None,
    step: Annotated[int, Query(ge=15, le=86400)] = 60,
) -> MetricsOut:
    host = await _host(db, host_id)
    end = end or int(time.time())
    start = start or end - 3600
    if start >= end or (end - start) / step > 11000:
        raise HTTPException(status_code=422, detail="Invalid range")
    try:
        # Scoped to the host's own tenant, exactly as for the customer.
        series = await metrics.query_range(host.tenant_id, host.id, metric, start, end, step)
    except metrics.MetricsUnavailable:
        raise HTTPException(status_code=503, detail="Metrics store unavailable") from None
    return MetricsOut(
        metric=metric, unit=metrics.CATALOG[metric].unit, series=[Series(**s) for s in series]
    )


@router.get("/hosts/{host_id}/disks")
async def host_disks(host_id: uuid.UUID, db: ServiceDB) -> list[DiskOut]:
    host = await _host(db, host_id)
    return await disks_for(host.tenant_id, host.id)


@router.get("/hosts/{host_id}/summary")
async def host_summary(
    host_id: uuid.UUID, db: ServiceDB, range: Annotated[int, Query(ge=3600, le=90 * 86400)] = 86400
) -> ServerSummary:
    host = await _host(db, host_id)
    return await summary_for(db, host.tenant_id, host, range)


@router.get("/hosts/{host_id}/forecast")
async def host_forecast(
    host_id: uuid.UUID, db: ServiceDB, days: Annotated[int, Query(ge=1, le=30)] = 7
) -> ForecastOut:
    host = await _host(db, host_id)
    return await forecast_for(host.tenant_id, host.id, days)


@router.get("/hosts/{host_id}/processes")
async def host_processes(host_id: uuid.UUID, db: ServiceDB) -> ProcessesOut:
    host = await _host(db, host_id)
    return await processes_of(host.tenant_id, host.id)


@router.get("/hosts/{host_id}/checks")
async def host_checks(host_id: uuid.UUID, db: ServiceDB) -> ChecksOut:
    return await checks_of(db, await _host(db, host_id))


class StaffIncident(IncidentOut):
    tenant_id: uuid.UUID
    account_email: str | None


@router.get("/incidents")
async def incidents(
    db: ServiceDB,
    status_: Annotated[Literal["open", "resolved"] | None, Query(alias="status")] = "open",
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[StaffIncident]:
    q = select(Incident, Tenant.email).join(Tenant, Tenant.id == Incident.tenant_id)
    if status_:
        q = q.where(Incident.status == status_)
    rows = (await db.execute(q.order_by(Incident.opened_at.desc()).limit(limit))).all()
    return [
        StaffIncident(
            **_incident_out(r.Incident).model_dump(),
            tenant_id=r.Incident.tenant_id,
            account_email=r.email,
        )
        for r in rows
    ]


# ── Incidents in detail ──────────────────────────────────────────────────────


@router.get("/incidents/{incident_id}")
async def incident_detail(incident_id: uuid.UUID, db: ServiceDB) -> IncidentDetail:
    incident = await db.scalar(select(Incident).where(Incident.id == incident_id))
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    events = await db.scalars(
        select(IncidentEvent)
        .where(IncidentEvent.incident_id == incident.id)
        .order_by(IncidentEvent.created_at, IncidentEvent.id)
    )
    return IncidentDetail(
        **_incident_out(incident).model_dump(),
        events=[
            IncidentEventOut(
                id=e.id, kind=e.kind, message=e.message, actor=e.actor, created_at=e.created_at
            )
            for e in events
        ],
    )


# ── Agent fleet ──────────────────────────────────────────────────────────────


class FleetVersion(BaseModel):
    version: str
    hosts: int


class FleetHost(BaseModel):
    id: uuid.UUID
    hostname: str
    agent_version: str | None
    os: str | None
    platform: str | None
    online: bool
    tenant_email: str | None
    probe_region: str | None


class Fleet(BaseModel):
    latest_version: str
    versions: list[FleetVersion]
    outdated: list[FleetHost]
    probes: list[FleetHost]
    rollout: "RolloutOut"


@router.get("/fleet")
async def fleet(db: ServiceDB) -> Fleet:
    """Agent versions across every account. Agents update themselves within
    the hour (installer timer) to the version the rollout offers them; one
    stuck on another version usually means its updater can't reach the
    download URL, or it runs in a container without the self-updating image."""
    plan = await rollout.current(db)
    rows = (
        await db.execute(
            select(Host, Tenant.email, Tenant.agent_version_pin)
            .join(Tenant, Tenant.id == Host.tenant_id)
            .where(Host.revoked_at.is_(None))
        )
    ).all()
    seen = await heartbeats.last_seen([h.id for h, _, _ in rows])
    counts: dict[str, int] = {}
    outdated: list[FleetHost] = []
    probes: list[FleetHost] = []
    latest = plan.stable_version
    for h, email, pin in rows:
        counts[h.agent_version or "unknown"] = counts.get(h.agent_version or "unknown", 0) + 1
        fh = FleetHost(
            id=h.id,
            hostname=h.hostname,
            agent_version=h.agent_version,
            os=h.os,
            platform=h.platform,
            online=heartbeats.is_online(seen.get(h.id)),
            tenant_email=email,
            probe_region=h.probe_region,
        )
        if h.probe_region:
            probes.append(fh)
        offered = rollout.version_for(plan, h.id, pin)
        if offered not in ("", "latest", "dev") and h.agent_version != offered:
            outdated.append(fh)
    versions = [FleetVersion(version=v, hosts=n) for v, n in counts.items()]
    versions.sort(key=lambda v: -v.hosts)
    probes.sort(key=lambda h: (h.probe_region or "", h.hostname))
    return Fleet(
        latest_version=latest,
        versions=versions,
        outdated=sorted(outdated, key=lambda h: h.hostname)[:500],
        probes=probes,
        rollout=await _rollout_out(db, plan),
    )


# ── Agent rollout ────────────────────────────────────────────────────────────


class RolloutOut(BaseModel):
    stable_version: str
    candidate_version: str | None
    candidate_percent: int
    candidate_since: datetime | None
    rolled_back_version: str | None
    rollback_reason: str | None
    updated_at: datetime | None
    updated_by: str | None
    available_versions: list[str]
    pins: list[dict]


Fleet.model_rebuild()


class RolloutIn(BaseModel):
    stable_version: str = Field(pattern=rollout.VERSION_RE.pattern)
    candidate_version: str | None = Field(default=None, pattern=rollout.VERSION_RE.pattern)
    candidate_percent: int = Field(default=0, ge=0, le=100)


class PinIn(BaseModel):
    version: str | None = Field(
        default=None, pattern=rollout.VERSION_RE.pattern, description="null to follow the rollout"
    )


async def _rollout_out(db: AsyncSession, plan: rollout.Rollout) -> RolloutOut:
    pins = (
        await db.execute(
            select(Tenant.id, Tenant.email, Tenant.display_name, Tenant.agent_version_pin).where(
                Tenant.agent_version_pin.is_not(None)
            )
        )
    ).all()
    return RolloutOut(
        **plan.__dict__,
        available_versions=rollout.available_versions(),
        pins=[
            {
                "tenant_id": str(p.id),
                "email": p.email,
                "name": p.display_name,
                "version": p.agent_version_pin,
            }
            for p in pins
        ],
    )


def _require_available(*versions: str | None) -> None:
    have = rollout.available_versions()
    if not have:  # dev builds without a dist directory
        return
    missing = [v for v in versions if v and v not in have]
    if missing:
        raise HTTPException(
            status_code=422, detail=f"No agent binaries for {missing[0]} on this server"
        )


def _actor(p: Principal) -> str:
    return p.email or p.name or "staff"


@router.get("/agent-rollout")
async def get_rollout(db: ServiceDB) -> RolloutOut:
    return await _rollout_out(db, await rollout.current(db))


@router.put("/agent-rollout")
async def set_rollout(
    body: RolloutIn, db: ServiceDB, principal: Annotated[Principal, Depends(staff)]
) -> RolloutOut:
    """Set the stable version and an optional candidate for a share of servers."""
    if body.candidate_version is None and body.candidate_percent:
        raise HTTPException(status_code=422, detail="A share needs a candidate version")
    if body.candidate_version == body.stable_version:
        raise HTTPException(status_code=422, detail="The candidate must differ from stable")
    _require_available(body.stable_version, body.candidate_version)
    plan = await rollout.current(db)
    if body.candidate_version != plan.candidate_version:
        plan.candidate_since = datetime.now(UTC) if body.candidate_version else None
    plan.stable_version = body.stable_version
    plan.candidate_version = body.candidate_version
    plan.candidate_percent = body.candidate_percent if body.candidate_version else 0
    await rollout.save(db, plan, _actor(principal))
    return await _rollout_out(db, plan)


@router.post("/agent-rollout/promote")
async def promote_candidate(
    db: ServiceDB, principal: Annotated[Principal, Depends(staff)]
) -> RolloutOut:
    """The candidate becomes stable for every server."""
    plan = await rollout.current(db)
    if not plan.candidate_version:
        raise HTTPException(status_code=409, detail="There is no candidate to promote")
    plan.stable_version = plan.candidate_version
    plan.candidate_version, plan.candidate_percent, plan.candidate_since = None, 0, None
    await rollout.save(db, plan, _actor(principal))
    return await _rollout_out(db, plan)


@router.post("/agent-rollout/rollback")
async def rollback_candidate(
    db: ServiceDB, principal: Annotated[Principal, Depends(staff)]
) -> RolloutOut:
    """Take the candidate back: its servers return to stable within the hour."""
    plan = await rollout.current(db)
    if not plan.candidate_version:
        raise HTTPException(status_code=409, detail="There is no candidate to roll back")
    plan.rolled_back_version = plan.candidate_version
    plan.rollback_reason = f"rolled back by {_actor(principal)}"
    plan.candidate_version, plan.candidate_percent, plan.candidate_since = None, 0, None
    await rollout.save(db, plan, _actor(principal))
    return await _rollout_out(db, plan)


@router.put("/tenants/{tenant_id}/agent-pin")
async def pin_tenant(tenant_id: uuid.UUID, body: PinIn, db: ServiceDB) -> dict:
    """Hold one account's servers at a version (or let them follow the rollout)."""
    tenant = await db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Account not found")
    _require_available(body.version)
    tenant.agent_version_pin = body.version
    return {"tenant_id": str(tenant.id), "version": tenant.agent_version_pin}


# ── Probes (the one thing staff change here) ─────────────────────────────────


async def _as_tenant(db: AsyncSession, principal: Principal, host_id: uuid.UUID) -> TenantContext:
    """Act in the host's own account, as staff, so edits run the same code
    (and checks) as the customer's."""
    host = await _host(db, host_id)
    return TenantContext(tenant_id=host.tenant_id, principal=principal, db=db, role="staff")


@router.get("/hosts/{host_id}/peers")
async def host_peers(host_id: uuid.UUID, db: ServiceDB) -> list[HostOut]:
    """The other servers in this server's account (what it can depend on)."""
    host = await _host(db, host_id)
    return await tenant_hosts(host.tenant_id, db)


@router.delete("/hosts/{host_id}", status_code=204)
async def delete_host(
    host_id: uuid.UUID, db: ServiceDB, principal: Annotated[Principal, Depends(staff)]
) -> None:
    """Remove any account's server. Deleting needs the account's own
    (row-level secured) role; the staff role can't delete hosts."""
    host = await _host(db, host_id)
    async with AppSession() as adb, adb.begin():
        await adb.execute(
            text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(host.tenant_id)}
        )
        t = TenantContext(tenant_id=host.tenant_id, principal=principal, db=adb, role="staff")
        await v1.delete_host(host_id, t)


@router.get("/reports/servers.pdf", response_class=Response)
async def servers_pdf(
    db: ServiceDB,
    host_id: Annotated[list[uuid.UUID], Query(min_length=1, max_length=100)],
    start: datetime | None = None,
    end: datetime | None = None,
    lifetime: bool = False,
    tz: str = "UTC",
) -> Response:
    """The servers PDF for staff; servers may come from several accounts."""
    if oncall.zone(tz).key != tz:
        raise HTTPException(status_code=422, detail="unknown time zone")
    hosts = list(await db.scalars(select(Host).where(Host.id.in_(host_id)).order_by(Host.hostname)))
    if len(hosts) != len(set(host_id)):
        raise HTTPException(status_code=404, detail="Host not found")
    a, b = report_routes.pdf_period(hosts, start, end, lifetime)
    tenants = {h.tenant_id for h in hosts}
    datas = []
    for tenant_id in tenants:
        mine = [h for h in hosts if h.tenant_id == tenant_id]
        datas += await hostpdf.collect(db, tenant_id, mine, a, b, tz)
    datas.sort(key=lambda d: d.host.hostname)
    account = (
        await db.scalar(select(Tenant.email).where(Tenant.id == next(iter(tenants))))
        if len(tenants) == 1
        else f"{len(tenants)} accounts"
    )
    body = hostpdf.render(datas, a, b, account=account or "", tz_name=tz)
    return report_routes.pdf_response(body, hosts, a)


@router.patch("/hosts/{host_id}")
async def update_host(
    host_id: uuid.UUID,
    body: v1.HostPatch,
    db: ServiceDB,
    principal: Annotated[Principal, Depends(staff)],
) -> v1.HostOut:
    return await v1.update_host(host_id, body, await _as_tenant(db, principal, host_id))


@router.post("/hosts/{host_id}/pause")
async def pause_host(
    host_id: uuid.UUID, db: ServiceDB, principal: Annotated[Principal, Depends(staff)]
) -> v1.HostOut:
    return await v1.pause_host(host_id, await _as_tenant(db, principal, host_id))


@router.post("/hosts/{host_id}/resume")
async def resume_host(
    host_id: uuid.UUID, db: ServiceDB, principal: Annotated[Principal, Depends(staff)]
) -> v1.HostOut:
    return await v1.resume_host(host_id, await _as_tenant(db, principal, host_id))


REGION_RE = r"^[a-z0-9][a-z0-9-]{1,39}$"


class ProbeIn(BaseModel):
    region: str | None = Field(default=None, pattern=REGION_RE, description="null to stop probing")


@router.put("/hosts/{host_id}/probe")
async def set_probe(host_id: uuid.UUID, body: ProbeIn, db: ServiceDB) -> FleetHost:
    """Make one of our own agents a public probe for a region (or stop).
    Probes receive every organisation's uptime check targets, so only agents
    in the organisations listed in PROBE_ACCOUNT_IDS qualify."""
    row = (
        await db.execute(
            select(Host, Tenant).join(Tenant, Tenant.id == Host.tenant_id).where(Host.id == host_id)
        )
    ).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Host not found")
    host, tenant = row
    if str(tenant.id) not in settings.PROBE_ACCOUNT_IDS:
        raise HTTPException(
            status_code=403,
            detail="Only agents in the organisations listed in PROBE_ACCOUNT_IDS can be probes",
        )
    host.probe_region = body.region
    seen = await heartbeats.last_seen([host.id])
    return FleetHost(
        id=host.id,
        hostname=host.hostname,
        agent_version=host.agent_version,
        os=host.os,
        platform=host.platform,
        online=heartbeats.is_online(seen.get(host.id)),
        tenant_email=tenant.email,
        probe_region=host.probe_region,
    )


# ── Audit log ────────────────────────────────────────────────────────────────


@router.get("/audit-log")
async def staff_audit_log(
    db: ServiceDB,
    tenant_id: uuid.UUID | None = None,
    staff_only: bool = False,
    q: Annotated[str | None, Query(max_length=100)] = None,
    before: int | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[audit_routes.AuditEventOut]:
    """Every account's changes and staff's own (staff_only: just staff's)."""
    return await audit_routes.query(
        db, tenant_id=tenant_id, staff_only=staff_only, q=q, before=before, limit=limit
    )


# ── Organisations ────────────────────────────────────────────────────────────


@router.post("/tenants/{tenant_id}/suspend", status_code=204)
async def suspend_tenant(tenant_id: uuid.UUID, db: ServiceDB) -> None:
    """Ingest refuses the organisation's agents and its members get 403."""
    await tenants.set_status(db, tenant_id, "suspended")


@router.post("/tenants/{tenant_id}/resume", status_code=204)
async def resume_tenant(tenant_id: uuid.UUID, db: ServiceDB) -> None:
    await tenants.set_status(db, tenant_id, "active")


@router.delete("/tenants/{tenant_id}", status_code=204)
async def delete_tenant(tenant_id: uuid.UUID, db: ServiceDB) -> None:
    await tenants.delete(db, tenant_id)


class UserSummary(BaseModel):
    id: uuid.UUID
    email: str
    name: str | None
    email_verified: bool
    totp_enabled: bool
    superadmin: bool
    disabled: bool
    created_at: datetime
    organisations: int


@router.get("/users")
async def list_users(
    db: ServiceDB,
    q: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[UserSummary]:
    rows = await db.execute(
        text(
            "SELECT u.*, (SELECT count(*) FROM tenant_members m WHERE m.user_id = u.id "
            "AND m.joined_at IS NOT NULL) AS orgs FROM users u "
            "WHERE (CAST(:q AS text) IS NULL OR u.email ILIKE :like OR u.name ILIKE :like) "
            "ORDER BY u.created_at DESC LIMIT :l OFFSET :o"
        ),
        {"q": q, "like": f"%{(q or '').strip()}%", "l": limit, "o": offset},
    )
    return [
        UserSummary(
            id=r.id,
            email=r.email,
            name=r.name,
            email_verified=r.email_verified_at is not None,
            totp_enabled=r.totp_enabled_at is not None,
            superadmin=r.is_superadmin,
            disabled=r.disabled_at is not None,
            created_at=r.created_at,
            organisations=r.orgs,
        )
        for r in rows
    ]


class DisableIn(BaseModel):
    disabled: bool


@router.put("/users/{user_id}/disabled", status_code=204)
async def disable_user(
    user_id: uuid.UUID,
    body: DisableIn,
    db: ServiceDB,
    principal: Annotated[Principal, Depends(staff)],
) -> None:
    """A disabled user can't sign in, and their sessions end now."""
    if str(user_id) == principal.user_id:
        raise HTTPException(status_code=400, detail="You can't disable yourself")
    found = await db.scalar(
        text(
            "UPDATE users SET disabled_at = CASE WHEN :d THEN now() END WHERE id = :u RETURNING id"
        ),
        {"d": body.disabled, "u": user_id},
    )
    if found is None:
        raise HTTPException(status_code=404, detail="User not found")
    if body.disabled:
        await db.execute(
            text(
                "UPDATE user_sessions SET revoked_at = now() "
                "WHERE user_id = :u AND revoked_at IS NULL"
            ),
            {"u": user_id},
        )


# ── Impersonation ────────────────────────────────────────────────────────────

IMPERSONATION_MINUTES = 60


class ImpersonationIn(BaseModel):
    reason: str = Field(min_length=5, max_length=500)
    allow_writes: bool = False


class ImpersonationOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    access_token: str
    allow_writes: bool
    expires_at: datetime


@router.post("/tenants/{tenant_id}/impersonate", status_code=201)
async def impersonate(
    tenant_id: uuid.UUID,
    body: ImpersonationIn,
    request: Request,
    db: ServiceDB,
    principal: Annotated[Principal, Depends(staff)],
) -> ImpersonationOut:
    """A token for working inside one organisation, for an hour. Read-only
    unless allow_writes; every change made with it is audited as the
    superadmin, and starting it is audited too."""
    if await db.get(Tenant, tenant_id) is None:
        raise HTTPException(status_code=404, detail="Organisation not found")
    row = (
        await db.execute(
            text(
                "INSERT INTO impersonations (user_id, tenant_id, reason, allow_writes, expires_at) "
                "VALUES (:u, :t, :r, :w, now() + make_interval(mins => :m)) "
                "RETURNING id, expires_at"
            ),
            {
                "u": principal.user_id,
                "t": tenant_id,
                "r": body.reason,
                "w": body.allow_writes,
                "m": IMPERSONATION_MINUTES,
            },
        )
    ).one()
    token = issue_access_token(
        str(principal.user_id),
        principal.session_id,
        principal.email or "",
        principal.name,
        superadmin=True,
        impersonation=(str(row.id), str(tenant_id), body.allow_writes),
        ttl=IMPERSONATION_MINUTES * 60,
    )
    return ImpersonationOut(
        id=row.id,
        tenant_id=tenant_id,
        access_token=token,
        allow_writes=body.allow_writes,
        expires_at=row.expires_at,
    )


@router.post("/impersonations/{impersonation_id}/end", status_code=204)
async def end_impersonation(
    impersonation_id: uuid.UUID,
    db: ServiceDB,
    principal: Annotated[Principal, Depends(staff)],
) -> None:
    await db.execute(
        text(
            "UPDATE impersonations SET ended_at = now() "
            "WHERE id = :i AND user_id = :u AND ended_at IS NULL"
        ),
        {"i": impersonation_id, "u": principal.user_id},
    )


class ImpersonationRow(BaseModel):
    id: uuid.UUID
    superadmin: str
    tenant_id: uuid.UUID
    organisation: str | None
    reason: str
    allow_writes: bool
    started_at: datetime
    expires_at: datetime
    ended_at: datetime | None


@router.get("/impersonations")
async def list_impersonations(
    db: ServiceDB, limit: Annotated[int, Query(ge=1, le=200)] = 50
) -> list[ImpersonationRow]:
    rows = await db.execute(
        text(
            "SELECT i.*, u.email, t.display_name, t.email AS org_email FROM impersonations i "
            "JOIN users u ON u.id = i.user_id JOIN tenants t ON t.id = i.tenant_id "
            "ORDER BY i.started_at DESC LIMIT :l"
        ),
        {"l": limit},
    )
    return [
        ImpersonationRow(
            id=r.id,
            superadmin=r.email,
            tenant_id=r.tenant_id,
            organisation=r.display_name or r.org_email,
            reason=r.reason,
            allow_writes=r.allow_writes,
            started_at=r.started_at,
            expires_at=r.expires_at,
            ended_at=r.ended_at,
        )
        for r in rows
    ]
