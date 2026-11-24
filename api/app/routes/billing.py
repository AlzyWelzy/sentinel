"""Plans and Razorpay subscriptions (services/billing.py).

Owners subscribe and cancel; anyone in the organisation sees the plan and
usage. Razorpay's webhook (`/webhooks/razorpay`, signed with
RAZORPAY_WEBHOOK_SECRET) is what changes an organisation's plan.
"""

import json
import logging
import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db import service_session
from app.models import Tenant as TenantRow
from app.services import billing
from app.tenancy import Tenant, UserTenant

log = logging.getLogger("sentinel.billing")
router = APIRouter(prefix="/v1/billing")
hooks = APIRouter(prefix="/webhooks", include_in_schema=False)
ServiceDB = Annotated[AsyncSession, Depends(service_session, scope="function")]


class PlanOut(BaseModel):
    id: str
    name: str
    price_monthly: int
    blurb: str
    limits: dict[str, Any]
    buyable: bool


class BillingOut(BaseModel):
    enabled: bool
    currency: str
    plan: PlanOut
    plan_status: str
    renews_at: datetime | None
    subscribed: bool
    usage: dict[str, int]
    plans: list[PlanOut]


def _plan_out(p: dict[str, Any]) -> PlanOut:
    return PlanOut(
        id=p["id"],
        name=p["name"],
        price_monthly=p["price_monthly"],
        blurb=p.get("blurb", ""),
        limits=p["limits"],
        buyable=billing.enabled() and bool(billing.razorpay_plan_id(p["id"])),
    )


@router.get("")
async def get_billing(t: Tenant) -> BillingOut:
    row = await t.db.get(TenantRow, t.tenant_id)
    current = billing.plan(row.plan if row else "free")
    u = await billing.usage(t.db, t.tenant_id)
    return BillingOut(
        enabled=billing.enabled(),
        currency=billing.catalog()["currency"],
        plan=_plan_out(current),
        plan_status=row.plan_status if row else "active",
        renews_at=row.plan_renews_at if row else None,
        subscribed=bool(row and row.razorpay_subscription_id),
        usage={
            "hosts": u.hosts,
            "checks": u.checks,
            "status_pages": u.status_pages,
            "members": u.members,
        },
        plans=[_plan_out(p) for p in billing.plans() if not p.get("hidden")],
    )


def _owner(t) -> None:
    if t.role != "owner" or t.principal.impersonated:
        raise HTTPException(status_code=403, detail="Only the organisation's owner manages billing")


class SubscribeIn(BaseModel):
    plan: Literal["pro", "business"]


class SubscribeOut(BaseModel):
    subscription_id: str
    key_id: str
    plan: str
    name: str
    email: str | None


@router.post("/subscribe")
async def subscribe(body: SubscribeIn, t: UserTenant) -> SubscribeOut:
    _owner(t)
    row = await t.db.get(TenantRow, t.tenant_id)
    if row and row.razorpay_subscription_id and row.plan_status == "active":
        raise HTTPException(
            status_code=409, detail="Cancel the current subscription before changing plans"
        )
    sub = await billing.create_subscription(body.plan, t.tenant_id, t.principal.email or "")
    return SubscribeOut(
        subscription_id=sub["id"],
        key_id=settings.RAZORPAY_KEY_ID,
        plan=body.plan,
        name=billing.plan(body.plan)["name"],
        email=t.principal.email,
    )


@router.post("/cancel", status_code=204)
async def cancel(t: UserTenant) -> None:
    _owner(t)
    row = await t.db.get(TenantRow, t.tenant_id)
    if not row or not row.razorpay_subscription_id:
        raise HTTPException(status_code=409, detail="There's no subscription to cancel")
    await billing.cancel_subscription(row.razorpay_subscription_id)


@hooks.post("/razorpay", status_code=204)
async def razorpay(request: Request, db: ServiceDB) -> None:
    if not settings.RAZORPAY_WEBHOOK_SECRET:
        raise HTTPException(status_code=404)
    body = await request.body()
    if not billing.webhook_signature_ok(body, request.headers.get("x-razorpay-signature", "")):
        raise HTTPException(status_code=401, detail="bad signature")
    try:
        payload = json.loads(body)
    except ValueError:
        raise HTTPException(status_code=400, detail="not JSON") from None
    event = str(payload.get("event", ""))
    sub = ((payload.get("payload") or {}).get("subscription") or {}).get("entity") or {}
    event_id = (
        request.headers.get("x-razorpay-event-id")
        or f"{event}:{sub.get('id')}:{payload.get('created_at')}"
    )
    try:
        tenant_id = uuid.UUID(str((sub.get("notes") or {}).get("tenant_id")))
    except ValueError:
        tenant_id = None
    # Razorpay retries; an event seen before changes nothing again.
    fresh = (
        await db.execute(
            text(
                "INSERT INTO billing_events (id, tenant_id, event, payload)"
                " VALUES (:i, :t, :e, CAST(:p AS jsonb)) ON CONFLICT (id) DO NOTHING RETURNING id"
            ),
            {"i": event_id, "t": tenant_id, "e": event, "p": body.decode()},
        )
    ).first()
    changes = billing.apply_event(event, sub) if fresh else None
    if changes and tenant_id:
        row = await db.get(TenantRow, tenant_id)
        # A late event for an older subscription doesn't undo a newer one.
        if row and (
            event in billing.ACTIVE
            or not row.razorpay_subscription_id
            or row.razorpay_subscription_id == sub.get("id")
        ):
            for k, v in changes.items():
                setattr(row, k, v)
            log.info("plan changed", extra={"tenant": str(tenant_id), "event": event})
    await db.commit()
