"""Customer-facing API, called by the console dashboard with the user's console JWT.

Every handler takes `t: Tenant`, which carries a session already scoped to the
caller's tenant by RLS. Queries also filter on tenant_id explicitly: RLS is the
safety net, not an excuse to leave the filter out.
"""

import time
import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.config import settings
from app.models import AgentKey, Host
from app.models import Tenant as TenantRow
from app.services import heartbeats, metrics
from app.services.secrets import new_agent_key
from app.tenancy import Tenant

router = APIRouter(prefix="/v1")


def install_command(key: str) -> str:
    """Linux and BSD (FreeBSD/OpenBSD/NetBSD)."""
    return f"curl -fsSL {settings.PUBLIC_DOWNLOAD_URL}/install.sh | sudo sh -s -- --key {key}"


def install_command_windows(key: str) -> str:
    """Elevated PowerShell."""
    url = f"{settings.PUBLIC_DOWNLOAD_URL}/install.ps1"
    return f"& ([scriptblock]::Create((irm {url}))) -Key {key}"


# ── Account ──────────────────────────────────────────────────────────────────


class MeOut(BaseModel):
    tenant_id: uuid.UUID
    email: str | None
    display_name: str | None
    status: str
    created_at: datetime


@router.get("/me")
async def me(t: Tenant) -> MeOut:
    row = await t.db.get_one(TenantRow, t.tenant_id)
    return MeOut(
        tenant_id=row.id,
        email=row.email,
        display_name=row.display_name,
        status=row.status,
        created_at=row.created_at,
    )


# ── Agent install keys ───────────────────────────────────────────────────────


class AgentKeyIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)


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
        install_command=install_command(plaintext),
        install_command_windows=install_command_windows(plaintext),
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


def _host_out(h: Host, last_seen: int | None) -> HostOut:
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
    )


async def _get_host(t: Tenant, host_id: uuid.UUID) -> Host:
    host = await t.db.scalar(select(Host).where(Host.id == host_id, Host.tenant_id == t.tenant_id))
    if host is None:
        raise HTTPException(status_code=404, detail="Host not found")
    return host


@router.get("/hosts")
async def list_hosts(t: Tenant) -> list[HostOut]:
    hosts = list(
        await t.db.scalars(
            select(Host).where(Host.tenant_id == t.tenant_id).order_by(Host.hostname)
        )
    )
    seen = await heartbeats.last_seen([h.id for h in hosts])
    return [_host_out(h, seen[h.id]) for h in hosts]


@router.get("/hosts/{host_id}")
async def get_host(host_id: uuid.UUID, t: Tenant) -> HostOut:
    host = await _get_host(t, host_id)
    seen = await heartbeats.last_seen([host.id])
    return _host_out(host, seen[host.id])


@router.delete("/hosts/{host_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_host(host_id: uuid.UUID, t: Tenant) -> None:
    """Removes the host; its agent's token stops working immediately."""
    host = await _get_host(t, host_id)
    await t.db.delete(host)
    await heartbeats.forget_host_tokens([host.token_hash])
    try:
        await metrics.delete_host_series(t.tenant_id, host.id)
    except metrics.MetricsUnavailable:
        # The host is gone either way; its series age out with retention.
        pass


class Series(BaseModel):
    labels: dict[str, str]
    points: list[list[float]]  # [unix seconds, value]


class MetricsOut(BaseModel):
    metric: str
    unit: str
    series: list[Series]


MetricName = Literal["cpu", "memory", "swap", "disk", "load", "network"]


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
