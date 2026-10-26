"""Staff view across every account.

Console staff (a verified token whose `role` is in STAFF_ROLES) can see every
tenant's servers, charts, incidents and the agent fleet to support customers.
The only change staff make here is choosing which of our own agents act as
public probes; anything in a customer's account is done through the
console's view-as-customer, which Pulsegrid treats as read-only.

These routes use the cross-tenant service role, so the staff check below is
the only gate. Keep every handler behind `staff`.
"""

import time
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.console import InvalidToken, Principal, admin_verifier
from app.config import settings
from app.db import service_session
from app.models import Check, Host, Incident, IncidentEvent, Tenant
from app.routes import audit as audit_routes
from app.routes.alerts import IncidentDetail, IncidentEventOut, IncidentOut, _incident_out
from app.routes.checks import CheckStatus, _status
from app.routes.v1 import (
    ChecksOut,
    HostOut,
    MetricName,
    MetricsOut,
    ProcessesOut,
    Series,
    _host_out,
    checks_of,
    processes_of,
)
from app.services import audit, checkresults, heartbeats, metrics, rollout

bearer = HTTPBearer(auto_error=False)


async def staff(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> Principal:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        principal = await admin_verifier.verify(credentials.credentials)
    except InvalidToken:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        ) from None
    if principal.role not in settings.STAFF_ROLES:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Staff access required")
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
            actor=principal.email or principal.name or "staff",
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
    external_account_id: str
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
    q: Annotated[str | None, Query(max_length=200, description="email, name or account id")] = None,
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
                Tenant.external_account_id.ilike(like),
            )
        )
    if with_hosts:
        query = query.where(host_count > 0)
    rows = (
        await db.execute(
            query.order_by(open_count.desc(), host_count.desc(), Tenant.created_at)
            .limit(limit)
            .offset(offset)
        )
    ).all()
    online = await _online_counts(db, [r.Tenant.id for r in rows])
    return [
        TenantSummary(
            id=r.Tenant.id,
            external_account_id=r.Tenant.external_account_id,
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
    return [
        StaffHost(**_host_out(h, seen[h.id]).model_dump(), tenant_id=h.tenant_id, account_email=e)
        for h, e in rows
    ]


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

REGION_RE = r"^[a-z0-9][a-z0-9-]{1,39}$"


class ProbeIn(BaseModel):
    region: str | None = Field(default=None, pattern=REGION_RE, description="null to stop probing")


@router.put("/hosts/{host_id}/probe")
async def set_probe(host_id: uuid.UUID, body: ProbeIn, db: ServiceDB) -> FleetHost:
    """Make one of our own agents a public probe for a region (or stop).
    Probes receive every account's uptime check targets, so only agents in
    the accounts listed in PROBE_ACCOUNT_IDS qualify."""
    row = (
        await db.execute(
            select(Host, Tenant).join(Tenant, Tenant.id == Host.tenant_id).where(Host.id == host_id)
        )
    ).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Host not found")
    host, tenant = row
    if tenant.external_account_id not in settings.PROBE_ACCOUNT_IDS:
        raise HTTPException(
            status_code=403,
            detail="Only agents in the accounts listed in PROBE_ACCOUNT_IDS can be probes",
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
