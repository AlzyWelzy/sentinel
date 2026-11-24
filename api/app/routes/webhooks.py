"""Reports from the email provider after a message was accepted.

Resend posts `email.bounced` and `email.complained` here, signed the Svix
way (`svix-id`, `svix-timestamp`, `svix-signature`: HMAC-SHA256 of
`id.timestamp.body` with the base64 secret after `whsec_`). A permanent
bounce or a complaint marks every email contact at that address
undeliverable, as a refusal at send time already does (alerter/dispatch.go):
alerts stop going there until the contact is verified again.
"""

import base64
import hashlib
import hmac
import json
import logging
import time
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db import service_session

log = logging.getLogger("sentinel.webhooks")
router = APIRouter(prefix="/webhooks", include_in_schema=False)
ServiceDB = Annotated[AsyncSession, Depends(service_session, scope="function")]

TOLERANCE = 300  # seconds either side of now


def verify_svix(
    secret: str, headers: dict[str, str], body: bytes, now: float | None = None
) -> bool:
    msg_id = headers.get("svix-id", "")
    ts = headers.get("svix-timestamp", "")
    sigs = headers.get("svix-signature", "")
    if not (secret and msg_id and ts and sigs):
        return False
    try:
        if abs((now or time.time()) - int(ts)) > TOLERANCE:
            return False
        key = base64.b64decode(secret.removeprefix("whsec_"))
    except ValueError:
        return False
    want = base64.b64encode(
        hmac.new(key, f"{msg_id}.{ts}.".encode() + body, hashlib.sha256).digest()
    ).decode()
    return any(
        hmac.compare_digest(s.split(",", 1)[1], want) for s in sigs.split() if s.startswith("v1,")
    )


def undeliverable_reason(event: dict) -> str | None:
    """Why the address should stop getting mail, or None to ignore."""
    kind = event.get("type")
    data = event.get("data") or {}
    if kind == "email.complained":
        return "The recipient marked an alert as spam"
    if kind == "email.bounced":
        bounce = data.get("bounce") or {}
        if str(bounce.get("type", "")).lower() in ("transient", "undetermined"):
            return None  # a full mailbox or a greylist: the next alert may get through
        detail = bounce.get("message") or bounce.get("subType") or "the mail server refused it"
        return f"Bounced: {detail}"[:300]
    return None


@router.post("/resend", status_code=204)
async def resend(request: Request, db: ServiceDB) -> None:
    if not settings.RESEND_WEBHOOK_SECRET:
        raise HTTPException(status_code=404)
    body = await request.body()
    if not verify_svix(settings.RESEND_WEBHOOK_SECRET, dict(request.headers), body):
        raise HTTPException(status_code=401, detail="bad signature")
    try:
        event = json.loads(body)
    except ValueError:
        raise HTTPException(status_code=400, detail="not JSON") from None
    reason = undeliverable_reason(event)
    if reason is None:
        return
    to = (event.get("data") or {}).get("to") or []
    addresses = sorted({a.strip().lower() for a in (to if isinstance(to, list) else [to]) if a})
    if not addresses:
        return
    res = await db.execute(
        text(
            "UPDATE notification_channels"
            "   SET undeliverable_at = now(), undeliverable_reason = :r, verified_at = NULL"
            " WHERE type = 'email' AND lower(target) = ANY(:a) AND undeliverable_at IS NULL"
        ),
        {"r": reason, "a": addresses},
    )
    await db.commit()
    log.info("email provider report", extra={"type": event.get("type"), "contacts": res.rowcount})
