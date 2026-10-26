"""Notification delivery log: every alert, escalation and test sent to a
contact, and what happened to it (sent, held for quiet hours, retrying,
failed)."""

import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Query
from pydantic import BaseModel
from sqlalchemy import select

from app.models import Incident, NotificationChannel, OutboundMessage
from app.routes.channels import mask_target
from app.tenancy import Tenant, TenantContext

router = APIRouter(prefix="/v1", tags=["deliveries"])


class DeliveryOut(BaseModel):
    id: uuid.UUID
    kind: str
    status: str  # sent, failed, pending, held
    channel_id: uuid.UUID | None
    channel_type: str | None
    channel_label: str | None
    channel_target: str | None
    incident_id: uuid.UUID | None
    incident_summary: str | None
    subject: str | None
    attempts: int
    last_error: str | None
    created_at: datetime
    sent_at: datetime | None
    held_until: datetime | None


async def _query(
    t: TenantContext,
    *,
    incident_id: uuid.UUID | None = None,
    channel_id: uuid.UUID | None = None,
    host_id: uuid.UUID | None = None,
    status: str | None = None,
    limit: int = 100,
) -> list[DeliveryOut]:
    q = (
        select(OutboundMessage, NotificationChannel, Incident.summary)
        .outerjoin(NotificationChannel, NotificationChannel.id == OutboundMessage.channel_id)
        .outerjoin(Incident, Incident.id == OutboundMessage.incident_id)
        .where(
            OutboundMessage.tenant_id == t.tenant_id,
            OutboundMessage.kind != "verification",
        )
    )
    if incident_id:
        q = q.where(OutboundMessage.incident_id == incident_id)
    if channel_id:
        q = q.where(OutboundMessage.channel_id == channel_id)
    if host_id:
        q = q.where(Incident.host_id == host_id)
    if status == "held":
        q = q.where(OutboundMessage.status == "pending", OutboundMessage.held_until.is_not(None))
    elif status:
        q = q.where(OutboundMessage.status == status)
    rows = await t.db.execute(q.order_by(OutboundMessage.created_at.desc()).limit(limit))
    out = []
    for m, c, summary in rows:
        held = m.status == "pending" and m.held_until is not None
        out.append(
            DeliveryOut(
                id=m.id,
                kind=m.kind,
                status="held" if held else m.status,
                channel_id=m.channel_id,
                channel_type=c.type if c else None,
                channel_label=c.label if c else None,
                channel_target=mask_target(c.type, c.target) if c else None,
                incident_id=m.incident_id,
                incident_summary=summary,
                subject=(m.payload or {}).get("subject"),
                attempts=m.attempts,
                last_error=m.last_error,
                created_at=m.created_at,
                sent_at=m.sent_at,
                held_until=m.held_until,
            )
        )
    return out


@router.get("/deliveries")
async def list_deliveries(
    t: Tenant,
    channel_id: uuid.UUID | None = None,
    host_id: Annotated[uuid.UUID | None, Query(description="alerts about this server")] = None,
    status: Literal["sent", "failed", "pending", "held"] | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[DeliveryOut]:
    return await _query(t, channel_id=channel_id, host_id=host_id, status=status, limit=limit)


@router.get("/incidents/{incident_id}/deliveries")
async def incident_deliveries(incident_id: uuid.UUID, t: Tenant) -> list[DeliveryOut]:
    return await _query(t, incident_id=incident_id, limit=200)
