"""Service-to-service routes for the console backend: usage for billing, and
the tenant lifecycle (the console owns users, so it tells Pulsegrid when one
is suspended or deleted).

These run on the BYPASSRLS service role and see every tenant, which is why
they sit behind the internal API key and must never be exposed publicly.
"""

from datetime import UTC, datetime, timedelta
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.internal import verify_internal_api_key
from app.config import settings
from app.db import service_session
from app.models import AgentKey, Host, Tenant
from app.routes.v1 import cloud_init, install_command, install_command_windows
from app.services import heartbeats
from app.services.secrets import new_agent_key
from app.validation import normalize_tags

router = APIRouter(prefix="/internal/v1", dependencies=[Depends(verify_internal_api_key)])

ServiceDB = Annotated[AsyncSession, Depends(service_session)]


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
