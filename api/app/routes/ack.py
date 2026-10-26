"""One-click acknowledge or snooze from an alert, no login needed.

Alerts carry /v1/ack/<incident id>.<signature>; the signature is an HMAC of
the incident id with ACK_SIGNING_SECRET, made by the alerter (alerter/ack.go).
GET shows the incident and buttons; only POST changes anything, so link
previewers and mail scanners that fetch the URL change nothing. Snoozing
holds escalations and reminders for 1 hour, 4 hours, or until the incident
resolves (at most a week).
"""

import base64
import hashlib
import hmac
import html
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db import service_session
from app.models import Incident, IncidentEvent
from app.services import audit

router = APIRouter(prefix="/v1/ack", include_in_schema=False)


def ack_token(incident_id: str, secret: str) -> str:
    mac = hmac.new(secret.encode(), f"ack:{incident_id}".encode(), hashlib.sha256).digest()
    return f"{incident_id}.{base64.urlsafe_b64encode(mac[:18]).decode().rstrip('=')}"


def _incident_id(token: str) -> uuid.UUID | None:
    if not settings.ACK_SIGNING_SECRET:
        return None
    incident_id, _, _ = token.partition(".")
    try:
        parsed = uuid.UUID(incident_id)
    except ValueError:
        return None
    if not hmac.compare_digest(token, ack_token(str(parsed), settings.ACK_SIGNING_SECRET)):
        return None
    return parsed


STYLE = (
    "body{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;"
    "color:#0f172a}.card{border:1px solid #e2e8f0;border-radius:12px;padding:1.5rem}"
    "h1{font-size:1.25rem;margin:0 0 .5rem}p{color:#475569}"
    "button{background:#0f172a;color:#fff;border:0;border-radius:8px;padding:.6rem 1.2rem;"
    "font-size:1rem;cursor:pointer}form{display:inline-block;margin:0 .5rem .5rem 0}"
    "button.light{background:#fff;color:#0f172a;border:1px solid #cbd5e1}"
)
ACTOR = "alert email link"
# Snooze choices on the page: path value → (minutes, label).
SNOOZES = {
    "60": (60, "1 hour"),
    "240": (240, "4 hours"),
    "resolved": (7 * 24 * 60, "until resolved"),
}


def _buttons(acknowledged: bool) -> str:
    out = (
        ""
        if acknowledged
        else '<form method="post"><button type="submit">Acknowledge</button></form>'
    )
    for key, (_, label) in SNOOZES.items():
        out += (
            f'<form method="post" action="?snooze={key}">'
            f'<button class="light" type="submit">Snooze {label}</button></form>'
        )
    return out


def _page(title: str, body: str, status_code: int = 200) -> HTMLResponse:
    return HTMLResponse(
        status_code=status_code,
        headers={
            "Cache-Control": "no-store",
            "X-Robots-Tag": "noindex",
            "Referrer-Policy": "no-referrer",
        },
        content=f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title><style>{STYLE}</style>
</head><body><div class="card">{body}</div></body></html>""",
    )


async def _load(token: str, db: AsyncSession) -> Incident | None:
    incident_id = _incident_id(token)
    if incident_id is None:
        return None
    return await db.scalar(select(Incident).where(Incident.id == incident_id))


INVALID = (
    "Link not valid",
    "<h1>This link isn't valid</h1><p>Open the alert from your dashboard instead.</p>",
)


@router.get("/{token}")
async def show(
    token: str, db: AsyncSession = Depends(service_session, scope="function")
) -> HTMLResponse:
    incident = await _load(token, db)
    if incident is None:
        return _page(*INVALID, status_code=404)
    summary = html.escape(incident.summary)
    if incident.status != "open":
        return _page("Resolved", f"<h1>{summary}</h1><p>This alert has already resolved.</p>")
    snoozed = incident.snoozed_until and incident.snoozed_until > datetime.now(UTC)
    note = f" Snoozed until {incident.snoozed_until:%Y-%m-%d %H:%M} UTC." if snoozed else ""
    if incident.acknowledged_at is not None:
        who = html.escape(incident.acknowledged_by or "someone")
        return _page(
            "Acknowledged",
            f"<h1>{summary}</h1><p>Already acknowledged by {who}.{note}</p>{_buttons(True)}",
        )
    return _page(
        "Acknowledge alert",
        f"<h1>{summary}</h1><p>Opened {incident.opened_at:%Y-%m-%d %H:%M} UTC on "
        f"{html.escape(incident.hostname)}. Acknowledging stops further escalation; snoozing "
        f"holds it for a while.{note}</p>{_buttons(False)}",
    )


@router.post("/{token}")
async def acknowledge(
    token: str,
    request: Request,
    snooze: str | None = None,
    db: AsyncSession = Depends(service_session, scope="function"),
) -> HTMLResponse:
    incident = await _load(token, db)
    if incident is None:
        return _page(*INVALID, status_code=404)
    summary = html.escape(incident.summary)
    if incident.status != "open":
        return _page("Resolved", f"<h1>{summary}</h1><p>This alert has already resolved.</p>")
    if snooze is not None:
        if snooze not in SNOOZES:
            return _page(*INVALID, status_code=404)
        minutes, label = SNOOZES[snooze]
        incident.snoozed_until = datetime.now(UTC) + timedelta(minutes=minutes)
        incident.snoozed_by = ACTOR
        message = f"Snoozed {label} from the link in an alert"
        db.add(
            IncidentEvent(
                tenant_id=incident.tenant_id,
                incident_id=incident.id,
                kind="snoozed",
                message=message,
                actor=ACTOR,
            )
        )
        await audit.record(
            db,
            tenant_id=incident.tenant_id,
            actor=ACTOR,
            actor_kind="system",
            action="incident.snooze",
            summary=f"Snoozed an incident {label} from an alert email",
            target_id=str(incident.id),
            request=request,
        )
        return _page(
            "Snoozed",
            f"<h1>{summary}</h1><p>Snoozed {label}: no escalations or reminders until "
            f"{incident.snoozed_until:%Y-%m-%d %H:%M} UTC, or until it resolves.</p>",
        )
    if incident.acknowledged_at is None:
        incident.acknowledged_at = datetime.now(UTC)
        incident.acknowledged_by = ACTOR
        db.add(
            IncidentEvent(
                tenant_id=incident.tenant_id,
                incident_id=incident.id,
                kind="acknowledged",
                message="Acknowledged from the link in an alert: escalation stopped",
                actor=ACTOR,
            )
        )
        await audit.record(
            db,
            tenant_id=incident.tenant_id,
            actor=ACTOR,
            actor_kind="system",
            action="incident.acknowledge",
            summary="Acknowledged an incident from an alert email",
            target_id=str(incident.id),
            request=request,
        )
    return _page(
        "Acknowledged",
        f"<h1>{summary}</h1><p>Acknowledged. No further escalation will be sent.</p>",
    )
