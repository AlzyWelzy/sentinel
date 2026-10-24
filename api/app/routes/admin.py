"""Staff view across every account: read-only.

Console staff (a verified token whose `role` is in STAFF_ROLES) can see every
tenant's servers, charts and incidents to support customers. Nothing here
changes data; staff who need to act use the console's view-as-customer, which
Pulsegrid already treats as read-only.

These routes use the cross-tenant service role, so the staff check below is
the only gate. Keep every handler behind `staff`.
"""

import time
import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.console import InvalidToken, Principal, admin_verifier
from app.config import settings
from app.db import service_session
from app.models import Host, Incident, Tenant
from app.routes.alerts import IncidentOut, _incident_out
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
from app.services import heartbeats, metrics

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


router = APIRouter(prefix="/admin/v1", dependencies=[Depends(staff)])

ServiceDB = Annotated[AsyncSession, Depends(service_session)]


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
