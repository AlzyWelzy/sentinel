"""Organisation lifecycle: suspend, resume, delete. Used by superadmins
(routes/admin.py) and by an owner deleting their own organisation."""

import uuid

import httpx
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import Host, Tenant
from app.services import heartbeats


async def _get(db: AsyncSession, tenant_id: uuid.UUID) -> Tenant:
    tenant = await db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Organisation not found")
    return tenant


async def _forget_host_tokens(db: AsyncSession, tenant_id: uuid.UUID) -> None:
    """Ingest caches host tokens with the tenant's status; drop them so a
    status change applies to the next push."""
    hashes = list(await db.scalars(select(Host.token_hash).where(Host.tenant_id == tenant_id)))
    await heartbeats.forget_host_tokens(hashes)


async def set_status(db: AsyncSession, tenant_id: uuid.UUID, status: str) -> None:
    """Suspended: ingest refuses the organisation's agents and the API answers 403."""
    tenant = await _get(db, tenant_id)
    tenant.status = status
    await _forget_host_tokens(db, tenant_id)


async def delete(db: AsyncSession, tenant_id: uuid.UUID) -> None:
    """Deletes the organisation with everything in it (cascades) and its
    metric series. If the metrics store can't be reached nothing is deleted,
    so the call can simply be retried."""
    await _get(db, tenant_id)
    await _forget_host_tokens(db, tenant_id)
    try:
        async with httpx.AsyncClient(base_url=settings.VICTORIAMETRICS_URL) as client:
            response = await client.post(
                "/api/v1/admin/tsdb/delete_series",
                params={"match[]": f'{{tenant_id="{tenant_id}"}}'},
                timeout=60,
            )
            response.raise_for_status()
    except httpx.HTTPError:
        raise HTTPException(
            status_code=503, detail="Metrics store unavailable, try again"
        ) from None
    # IPDR evidence goes too (the organisation's own records end with it).
    from app.services import clickhouse, ipdr

    try:
        for tbl in ipdr.SEALED_TABLES:
            await clickhouse.command(
                f"DELETE FROM {tbl} WHERE tenant_id = {{t:UUID}}",  # noqa: S608 (constant)
                {"t": tenant_id},
            )
    except (clickhouse.EvidenceUnavailable, httpx.HTTPError):
        raise HTTPException(
            status_code=503, detail="Evidence store unavailable, try again"
        ) from None
    tenant = await _get(db, tenant_id)
    await db.delete(tenant)
