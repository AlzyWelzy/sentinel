"""Service-to-service routes for the console backend: usage for billing, and
the tenant lifecycle (the console owns users, so it tells Pulsegrid when one
is suspended or deleted).

These run on the BYPASSRLS service role and see every tenant, which is why
they sit behind the internal API key and must never be exposed publicly.
"""

from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import any_, delete, func, literal, select, text, true
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.internal import verify_internal_api_key
from app.config import settings
from app.db import service_session
from app.models import (
    AgentKey,
    ExternalMonitor,
    Host,
    MaintenanceWindow,
    NotificationChannel,
    OutboundMessage,
    Tenant,
)
from app.routes.v1 import cloud_init, install_command, install_command_windows
from app.services import heartbeats
from app.services.maintenance import in_maintenance
from app.services.secrets import new_agent_key
from app.validation import normalize_tags

router = APIRouter(prefix="/internal/v1", dependencies=[Depends(verify_internal_api_key)])

ServiceDB = Annotated[AsyncSession, Depends(service_session, scope="function")]


class TenantUsage(BaseModel):
    external_account_id: str
    active_hosts: int


@router.get("/usage")
async def usage(db: ServiceDB) -> list[TenantUsage]:
    """Hosts that reported in the last 24 hours, per tenant, for per-host billing."""
    since = datetime.now(UTC) - timedelta(days=1)
    rows = await db.execute(
        select(Tenant.external_account_id, func.count(Host.id))
        .join(Host, Host.tenant_id == Tenant.id)
        .where(
            Tenant.source == settings.TENANT_SOURCE,
            Host.revoked_at.is_(None),
            Host.last_seen_at >= since,
        )
        .group_by(Tenant.external_account_id)
    )
    return [TenantUsage(external_account_id=e, active_hosts=n) for e, n in rows]


async def _tenant(db: AsyncSession, external_account_id: str) -> Tenant:
    tenant = await db.scalar(
        select(Tenant).where(
            Tenant.source == settings.TENANT_SOURCE,
            Tenant.external_account_id == external_account_id,
        )
    )
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant


async def _forget_tenant_tokens(db: AsyncSession, tenant: Tenant) -> None:
    hashes = list(await db.scalars(select(Host.token_hash).where(Host.tenant_id == tenant.id)))
    await heartbeats.forget_host_tokens(hashes)


@router.post("/tenants/{external_account_id}/suspend", status_code=status.HTTP_204_NO_CONTENT)
async def suspend(external_account_id: str, db: ServiceDB) -> None:
    """Ingest rejects the tenant's agents and the dashboard returns 403."""
    tenant = await _tenant(db, external_account_id)
    tenant.status = "suspended"
    await _forget_tenant_tokens(db, tenant)


@router.post("/tenants/{external_account_id}/resume", status_code=status.HTTP_204_NO_CONTENT)
async def resume(external_account_id: str, db: ServiceDB) -> None:
    tenant = await _tenant(db, external_account_id)
    tenant.status = "active"
    await _forget_tenant_tokens(db, tenant)


@router.delete("/tenants/{external_account_id}", status_code=status.HTTP_204_NO_CONTENT)
async def purge(external_account_id: str, db: ServiceDB) -> None:
    """Deletes the tenant, its hosts, keys and channels, and all its metric series."""
    tenant = await _tenant(db, external_account_id)
    await _forget_tenant_tokens(db, tenant)
    try:
        async with httpx.AsyncClient(base_url=settings.VICTORIAMETRICS_URL) as client:
            response = await client.post(
                "/api/v1/admin/tsdb/delete_series",
                params={"match[]": f'{{tenant_id="{tenant.id}"}}'},
                timeout=60,
            )
            response.raise_for_status()
    except httpx.HTTPError:
        # Keep the tenant row so the console can retry the whole purge.
        raise HTTPException(status_code=503, detail="Metrics store unavailable") from None
    await db.delete(tenant)


class ProvisionIn(BaseModel):
    email: str | None = None
    name: str | None = None
    key_name: str = Field(min_length=1, max_length=100)
    tags: list[str] = Field(default_factory=list)

    @field_validator("tags")
    @classmethod
    def _tags(cls, v: list[str]) -> list[str]:
        return normalize_tags(v)


class ProvisionOut(BaseModel):
    key: str
    install_command: str
    install_command_windows: str
    cloud_init: str


@router.post("/tenants/{external_account_id}/agent-keys", status_code=status.HTTP_201_CREATED)
async def provision_agent_key(
    external_account_id: str, body: ProvisionIn, db: ServiceDB
) -> ProvisionOut:
    """An install key for a console user, made by the console itself (e.g. to
    install the agent on a VM it launches for them). Creates the tenant, as a
    first visit to the dashboard would, if the user has none yet."""
    row = (
        await db.execute(
            text("SELECT out_tenant_id, out_status FROM pulsegrid_resolve_tenant(:s, :e, :m, :n)"),
            {
                "s": settings.TENANT_SOURCE,
                "e": external_account_id,
                "m": body.email,
                "n": body.name,
            },
        )
    ).one()
    if row.out_status != "active":
        raise HTTPException(status_code=409, detail="Monitoring is suspended for this account")
    plaintext, prefix, key_hash = new_agent_key()
    db.add(
        AgentKey(
            tenant_id=row.out_tenant_id, name=body.key_name, key_prefix=prefix, key_hash=key_hash
        )
    )
    return ProvisionOut(
        key=plaintext,
        install_command=install_command(plaintext, body.tags),
        install_command_windows=install_command_windows(plaintext, body.tags),
        cloud_init=cloud_init(plaintext, body.tags),
    )


SEVERITY_RANK = {"info": 0, "warning": 1, "critical": 2}


class NotifyIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    text: str = Field(default="", max_length=2000)
    severity: Literal["critical", "warning", "info"] = "critical"
    url: str = Field(default="", max_length=500)
    # Same key on "down" and "up": the recovery notification replaces the outage one.
    key: str = Field(default="", max_length=100)
    resolved: bool = False


class NotifyOut(BaseModel):
    queued: int


@router.post("/tenants/{external_account_id}/notify")
async def notify(external_account_id: str, body: NotifyIn, db: ServiceDB) -> NotifyOut:
    """A push notification for something the console watches (an uptime
    monitor going down or up), sent to the user's Pulsegrid push devices so
    they get one stream of alerts. Email stays with the console. A user with
    no tenant or no push devices is not an error: nothing is queued."""
    tenant = await db.scalar(
        select(Tenant).where(
            Tenant.source == settings.TENANT_SOURCE,
            Tenant.external_account_id == external_account_id,
        )
    )
    if tenant is None or tenant.status != "active":
        return NotifyOut(queued=0)
    channels = await db.scalars(
        select(NotificationChannel).where(
            NotificationChannel.tenant_id == tenant.id,
            NotificationChannel.type == "push",
            NotificationChannel.verified_at.is_not(None),
        )
    )
    event = {
        "type": "alert_resolved" if body.resolved else "alert_firing",
        "summary": body.title,
        "condition": body.text,
        "severity": body.severity,
        "url": body.url,
        "incident_id": f"uptime-{body.key}" if body.key else "",
        "source": "uptime",
    }
    queued = 0
    for channel in channels:
        wanted = SEVERITY_RANK.get(channel.min_severity, 0)
        if not body.resolved and SEVERITY_RANK[body.severity] < wanted:
            continue
        db.add(
            OutboundMessage(
                tenant_id=tenant.id,
                channel_id=channel.id,
                kind=event["type"],
                payload={"subject": body.title, "text": body.text, "event": event},
            )
        )
        queued += 1
    return NotifyOut(queued=queued)


class MaintenanceOut(BaseModel):
    in_maintenance: bool
    hosts: list[str]


@router.get("/tenants/{external_account_id}/maintenance")
async def maintenance_for_address(
    external_account_id: str, address: str, db: ServiceDB
) -> MaintenanceOut:
    """Is the user's server at this IP or hostname in a maintenance window
    right now? The console asks before alerting on an uptime check aimed at
    it, so one maintenance window quiets both kinds of alert."""
    address = address.strip().lower()
    tenant = await db.scalar(
        select(Tenant).where(
            Tenant.source == settings.TENANT_SOURCE,
            Tenant.external_account_id == external_account_id,
        )
    )
    if tenant is None or not address:
        return MaintenanceOut(in_maintenance=False, hosts=[])
    hosts = list(
        await db.scalars(
            select(Host).where(
                Host.tenant_id == tenant.id,
                Host.revoked_at.is_(None),
                (func.lower(Host.hostname) == address)
                | (literal(address) == any_(Host.ip_addresses))
                | (Host.public_ip == address),
            )
        )
    )
    if not hosts:
        return MaintenanceOut(in_maintenance=False, hosts=[])
    windows = list(
        await db.scalars(
            select(MaintenanceWindow).where(
                MaintenanceWindow.tenant_id == tenant.id, MaintenanceWindow.enabled
            )
        )
    )
    now = datetime.now(UTC)
    covered = [h.hostname for h in hosts if in_maintenance(windows, h, now)]
    return MaintenanceOut(in_maintenance=bool(covered), hosts=covered)


# ── Uptime monitors kept in step by the console ──────────────────────────────


EXTERNAL_FIELDS = (
    "name",
    "kind",
    "status",
    "uptime_24h",
    "uptime_30d",
    "response_ms",
    "daily",
    "updated_at",
)


class ExternalDay(BaseModel):
    date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    uptime: float | None = Field(default=None, ge=0, le=100)


class ExternalMonitorIn(BaseModel):
    key: str = Field(pattern=r"^[a-z]+:[A-Za-z0-9_-]{1,64}$")
    name: str = Field(min_length=1, max_length=200)
    kind: str | None = Field(default=None, max_length=40)
    status: Literal["up", "down", "pending", "maintenance", "paused", "unknown"]
    uptime_24h: float | None = Field(default=None, ge=0, le=100)
    uptime_30d: float | None = Field(default=None, ge=0, le=100)
    response_ms: float | None = Field(default=None, ge=0)
    daily: list[ExternalDay] = Field(default_factory=list, max_length=90)


class ExternalMonitorsIn(BaseModel):
    source: str = Field(default="kuma", pattern=r"^[a-z]+$")
    monitors: list[ExternalMonitorIn] = Field(default_factory=list, max_length=1000)


@router.put("/tenants/{external_account_id}/external-monitors")
async def put_external_monitors(
    external_account_id: str, body: ExternalMonitorsIn, db: ServiceDB
) -> dict:
    """Replace the account's monitors from one source (keys "<source>:<id>"):
    upsert those sent, drop the ones gone."""
    tenant = await _tenant(db, external_account_id)
    keys = [m.key for m in body.monitors]
    if any(not k.startswith(body.source + ":") for k in keys):
        raise HTTPException(status_code=422, detail="every key starts with the source")
    await db.execute(
        delete(ExternalMonitor).where(
            ExternalMonitor.tenant_id == tenant.id,
            ExternalMonitor.key.like(body.source + ":%"),
            ExternalMonitor.key.not_in(keys) if keys else true(),
        )
    )
    now = datetime.now(UTC)
    for m in body.monitors:
        stmt = pg_insert(ExternalMonitor).values(
            tenant_id=tenant.id,
            key=m.key,
            name=m.name,
            kind=m.kind,
            status=m.status,
            uptime_24h=m.uptime_24h,
            uptime_30d=m.uptime_30d,
            response_ms=m.response_ms,
            daily=[d.model_dump() for d in m.daily],
            updated_at=now,
        )
        await db.execute(
            stmt.on_conflict_do_update(
                index_elements=["tenant_id", "key"],
                set_={c: stmt.excluded[c] for c in EXTERNAL_FIELDS},
            )
        )
    return {"monitors": len(keys)}
