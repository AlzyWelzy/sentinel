"""Plans, limits and Razorpay subscriptions.

The catalog is app/data/plans.json (a copy of proto/plans.json, which ingest
reads to refuse a new server over the limit). Limits apply only while
billing is on, that is while RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET are
set; without them every organisation is unlimited, as before plans existed.

Razorpay flow: an owner picks a plan, the API creates a subscription for
that plan's Razorpay plan id (RAZORPAY_PLAN_<ID>) and the browser opens
Razorpay Checkout with it. Razorpay's signed webhook is what changes the
organisation's plan (routes/billing.py), so a closed tab or a forged
redirect changes nothing.
"""

import hashlib
import hmac
import json
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cache
from pathlib import Path
from typing import Any

import httpx
from fastapi import HTTPException, status
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import Check, Host, StatusPage, Tenant

PATH = Path(__file__).resolve().parent.parent / "data" / "plans.json"
API = "https://api.razorpay.com/v1"


@cache
def catalog() -> dict[str, Any]:
    return json.loads(PATH.read_text())


def plans() -> list[dict[str, Any]]:
    return catalog()["plans"]


def plan(plan_id: str) -> dict[str, Any]:
    by_id = {p["id"]: p for p in plans()}
    return by_id.get(plan_id, by_id["free"])


def enabled() -> bool:
    return bool(settings.RAZORPAY_KEY_ID and settings.RAZORPAY_KEY_SECRET)


def razorpay_plan_id(plan_id: str) -> str | None:
    """Razorpay's id for our plan, from RAZORPAY_PLAN_PRO and so on."""
    return os.environ.get(f"RAZORPAY_PLAN_{plan_id.upper()}") or None


def buyable() -> list[dict[str, Any]]:
    return [p for p in plans() if not p.get("hidden") and p["price_monthly"] > 0]


@dataclass
class Usage:
    hosts: int
    checks: int
    status_pages: int
    members: int


async def usage(db: AsyncSession, tenant_id: uuid.UUID) -> Usage:
    async def count(q) -> int:
        return int(await db.scalar(q) or 0)

    return Usage(
        hosts=await count(
            select(func.count())
            .select_from(Host)
            .where(Host.tenant_id == tenant_id, Host.revoked_at.is_(None))
        ),
        checks=await count(
            select(func.count()).select_from(Check).where(Check.tenant_id == tenant_id)
        ),
        status_pages=await count(
            select(func.count()).select_from(StatusPage).where(StatusPage.tenant_id == tenant_id)
        ),
        members=await count(
            text("SELECT count(*) FROM tenant_members WHERE tenant_id = :t").bindparams(t=tenant_id)
        ),
    )


LABELS = {
    "hosts": "servers and devices",
    "checks": "uptime checks",
    "status_pages": "status pages",
    "members": "members",
}


async def require_room(db: AsyncSession, tenant_id: uuid.UUID, what: str, adding: int = 1) -> None:
    """402 when adding `adding` more of `what` would pass the plan's limit."""
    if not enabled():
        return
    tenant = await db.get(Tenant, tenant_id)
    p = plan(tenant.plan if tenant else "free")
    limit = p["limits"].get(what)
    if limit is None:
        return
    have = getattr(await usage(db, tenant_id), what)
    if have + adding > limit:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=f"The {p['name']} plan includes {limit} {LABELS[what]}. "
            "Upgrade the plan under Organisation → Billing to add more.",
        )


async def require_ipdr(db: AsyncSession, tenant_id: uuid.UUID) -> None:
    if not enabled():
        return
    tenant = await db.get(Tenant, tenant_id)
    p = plan(tenant.plan if tenant else "free")
    if not p["limits"].get("ipdr"):
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="IPDR evidence collection is part of the Business plan.",
        )


# ── Razorpay ─────────────────────────────────────────────────────────────────


def _auth() -> tuple[str, str]:
    return (settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET)


async def create_subscription(plan_id: str, tenant_id: uuid.UUID, email: str) -> dict[str, Any]:
    rp_plan = razorpay_plan_id(plan_id)
    if not enabled() or not rp_plan:
        raise HTTPException(status_code=409, detail="That plan can't be bought yet")
    body = {
        "plan_id": rp_plan,
        "total_count": 120,  # monthly for up to ten years, until cancelled
        "customer_notify": 1,
        "notes": {"tenant_id": str(tenant_id), "plan": plan_id, "email": email},
    }
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post(f"{API}/subscriptions", json=body, auth=_auth())
    if r.status_code >= 400:
        raise HTTPException(status_code=502, detail="Razorpay refused the subscription")
    return r.json()


async def cancel_subscription(subscription_id: str) -> None:
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post(
            f"{API}/subscriptions/{subscription_id}/cancel",
            json={"cancel_at_cycle_end": 1},
            auth=_auth(),
        )
    # 400 is Razorpay's answer for a subscription that already ended.
    if r.status_code >= 400 and r.status_code != 400:
        raise HTTPException(status_code=502, detail="Razorpay didn't cancel the subscription")


def webhook_signature_ok(body: bytes, signature: str) -> bool:
    secret = settings.RAZORPAY_WEBHOOK_SECRET
    if not secret or not signature:
        return False
    want = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, signature)


def checkout_signature_ok(payment_id: str, subscription_id: str, signature: str) -> bool:
    """The signature Checkout hands the browser after paying."""
    want = hmac.new(
        settings.RAZORPAY_KEY_SECRET.encode(),
        f"{payment_id}|{subscription_id}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return bool(signature) and hmac.compare_digest(want, signature)


# What a subscription event means for the organisation's plan.
ACTIVE = {"subscription.activated", "subscription.charged", "subscription.resumed"}
LAPSED = {"subscription.halted", "subscription.pending"}
ENDED = {"subscription.cancelled", "subscription.completed", "subscription.expired"}


def apply_event(event: str, sub: dict[str, Any]) -> dict[str, Any] | None:
    """The tenant columns to set for a subscription event, or None."""
    notes = sub.get("notes") or {}
    ends = sub.get("current_end")
    renews = datetime.fromtimestamp(ends, UTC) if isinstance(ends, int) else None
    if event in ACTIVE:
        return {
            "plan": notes.get("plan") or "free",
            "plan_status": "active",
            "razorpay_subscription_id": sub.get("id"),
            "plan_renews_at": renews,
        }
    if event in LAPSED:
        return {"plan_status": "past_due"}
    if event in ENDED:
        return {
            "plan": "free",
            "plan_status": "cancelled",
            "razorpay_subscription_id": None,
            "plan_renews_at": None,
        }
    return None
