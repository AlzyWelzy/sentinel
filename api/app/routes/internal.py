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
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.internal import verify_internal_api_key
from app.config import settings
from app.db import service_session
from app.models import Host, Tenant
from app.services import heartbeats

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
