"""Audit log: who changed what in the account, newest first."""

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.tenancy import Tenant

router = APIRouter(prefix="/v1/audit-log", tags=["audit"])


class AuditEventOut(BaseModel):
    id: int
    tenant_id: uuid.UUID | None
    actor: str
    actor_kind: str
    action: str
    summary: str
    target_id: str | None
    details: dict
    ip: str | None
    created_at: datetime


async def query(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID | None = None,
    staff_only: bool = False,
    q: str | None = None,
    action: str | None = None,
    before: int | None = None,
    limit: int = 50,
) -> list[AuditEventOut]:
    # One fixed statement: each filter is off when its value is NULL.
    rows = await db.execute(
        text("""
            SELECT id, tenant_id, actor, actor_kind, action, summary, target_id, details, ip,
                   created_at
              FROM audit_events
             WHERE (CAST(:tenant_id AS uuid) IS NULL OR tenant_id = CAST(:tenant_id AS uuid))
               AND (NOT :staff_only OR actor_kind = 'staff')
               AND (CAST(:action AS text) IS NULL OR action LIKE :action)
               AND (CAST(:q AS text) IS NULL OR summary ILIKE :q OR actor ILIKE :q
                    OR target_id = :exact)
               AND (CAST(:before AS bigint) IS NULL OR id < :before)
             ORDER BY id DESC
             LIMIT :limit
        """),
        {
            "tenant_id": tenant_id,
            "staff_only": staff_only,
            "action": action.rstrip("*") + "%" if action else None,
            "q": f"%{q}%" if q else None,
            "exact": q,
            "before": before,
            "limit": limit,
        },
    )
    return [AuditEventOut(**r._mapping) for r in rows]


@router.get("")
async def audit_log(
    t: Tenant,
    q: Annotated[str | None, Query(max_length=100, description="text, actor or target id")] = None,
    action: Annotated[str | None, Query(max_length=60, description="e.g. alert_rule.*")] = None,
    before: Annotated[int | None, Query(description="paging: events before this id")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[AuditEventOut]:
    # RLS keeps it to the account; the filter says so too.
    return await query(t.db, tenant_id=t.tenant_id, q=q, action=action, before=before, limit=limit)
