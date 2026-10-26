"""Audit log. A successful change through the API is recorded in the same
transaction as the change (tenancy.tenant_context, admin.staff_audit), so a
change that fails or rolls back leaves no event. Request bodies are kept
with anything secret-looking redacted."""

import json
import logging
import uuid
from typing import Any

from fastapi import Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger("pulsegrid.audit")

MAX_DETAILS = 4000
REDACT = ("password", "secret", "token", "key", "auth", "code", "p256dh", "webhook_url")
# Not changes worth recording: dry runs and per-person conveniences.
SKIP = {
    ("POST", "/v1/alert-rules/preview"),
    ("POST", "/v1/channels/{channel_id}/test"),
    ("POST", "/v1/channels/{channel_id}/verification"),
}

# Method, route, action, what happened. "{name}" is the body's name or title
# when it has one, "{email}" an invited member's address.
_LABEL_TABLE = """
POST /v1/agent-keys agent_key.create Created install key {name}
DELETE /v1/agent-keys/{key_id} agent_key.revoke Revoked an install key
POST /v1/alert-rules alert_rule.create Created alert rule {name}
POST /v1/alert-rules/recommended alert_rule.recommended Added the recommended alert rules
POST /v1/alert-rules/{rule_id}/test alert_rule.test Sent a test alert for a rule
PUT /v1/alert-rules/{rule_id} alert_rule.update Changed alert rule {name}
DELETE /v1/alert-rules/{rule_id} alert_rule.delete Deleted an alert rule
POST /v1/api-tokens api_token.create Created API token {name}
DELETE /v1/api-tokens/{token_id} api_token.revoke Revoked an API token
POST /v1/channels contact.create Added alert contact {name}
POST /v1/channels/push contact.push Turned on push in a browser
PATCH /v1/channels/{channel_id} contact.update Changed an alert contact
DELETE /v1/channels/{channel_id} contact.delete Removed an alert contact
POST /v1/channels/{channel_id}/default contact.default Made a contact the default
POST /v1/channels/{channel_id}/verify contact.verify Verified an alert contact
POST /v1/checks check.create Created check {name}
PUT /v1/checks/{check_id} check.update Changed check {name}
DELETE /v1/checks/{check_id} check.delete Deleted a check
PATCH /v1/hosts/{host_id} server.update Changed a server's settings
DELETE /v1/hosts/{host_id} server.delete Removed a server
POST /v1/hosts/bulk server.bulk Changed several servers at once
POST /v1/hosts/{host_id}/actions server.action Ran action {name} on a server
POST /v1/incidents/{incident_id}/acknowledge incident.acknowledge Acknowledged an incident
POST /v1/incidents/{incident_id}/notes incident.note Added a note to an incident
POST /v1/incidents/{incident_id}/resolve incident.resolve Resolved an incident
POST /v1/incidents/{incident_id}/reopen incident.reopen Reopened an incident
POST /v1/incidents/{incident_id}/snooze incident.snooze Snoozed an incident
DELETE /v1/incidents/{incident_id}/snooze incident.unsnooze Ended an incident's snooze
POST /v1/incidents/merge incident.merge Merged incidents
POST /v1/maintenance maintenance.create Scheduled maintenance {name}
PUT /v1/maintenance/{window_id} maintenance.update Changed maintenance {name}
DELETE /v1/maintenance/{window_id} maintenance.delete Deleted a maintenance window
POST /v1/members member.invite Invited {email} to the team
PATCH /v1/members/{member_id} member.role Changed a team member's role
DELETE /v1/members/{member_id} member.remove Removed a team member
PUT /v1/reports/settings reports.settings Changed report settings
POST /v1/saved-views saved_view.create Saved view {name}
PUT /v1/saved-views/{view_id} saved_view.update Changed saved view {name}
DELETE /v1/saved-views/{view_id} saved_view.delete Deleted a saved view
POST /v1/status-pages status_page.create Created status page {name}
PUT /v1/status-pages/{page_id} status_page.update Changed status page {name}
DELETE /v1/status-pages/{page_id} status_page.delete Deleted a status page
POST /v1/status-pages/{page_id}/updates status_update.create Posted status update {name}
PUT /v1/status-pages/{page_id}/updates/{update_id} status_update.update Changed status update {name}
DELETE /v1/status-pages/{page_id}/updates/{update_id} status_update.delete Deleted a status update
POST /v1/oncall/schedules oncall.create Created on-call schedule {name}
PUT /v1/oncall/schedules/{schedule_id} oncall.update Changed on-call schedule {name}
DELETE /v1/oncall/schedules/{schedule_id} oncall.delete Deleted an on-call schedule
POST /v1/oncall/schedules/{schedule_id}/overrides oncall.override Added an on-call override
DELETE /v1/oncall/overrides/{override_id} oncall.override_delete Removed an on-call override
PUT /admin/v1/agent-rollout rollout.update Changed the agent rollout
POST /admin/v1/agent-rollout/promote rollout.promote Promoted the agent candidate
POST /admin/v1/agent-rollout/rollback rollout.rollback Rolled back the agent candidate
PUT /admin/v1/tenants/{tenant_id}/agent-pin rollout.pin Pinned an account's agent version
PUT /admin/v1/hosts/{host_id}/probe probe.update Changed a probe
"""  # noqa: E501 (one change per line reads best)
LABELS: dict[tuple[str, str], tuple[str, str]] = {
    (m, r): (a, " ".join(t))
    for m, r, a, *t in (line.split() for line in _LABEL_TABLE.strip().splitlines())
}


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: ("[redacted]" if any(r in k.lower() for r in REDACT) else redact(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact(v) for v in value[:50]]
    return value


def _body(request: Request) -> Any:
    """The JSON body, only if the route already read it. Reading it here
    would wait on the client after the response went out (a request with no
    body then raises ClientDisconnect), so a body nobody read is skipped."""
    raw = getattr(request, "_body", None)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


def route_of(request: Request) -> str:
    route = request.scope.get("route")
    return getattr(route, "path", request.url.path)


async def record(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID | None,
    actor: str,
    actor_kind: str,
    action: str,
    summary: str,
    target_id: str | None = None,
    details: dict | None = None,
    request: Request | None = None,
) -> None:
    payload = json.dumps(details or {}, default=str)
    if len(payload) > MAX_DETAILS:
        payload = json.dumps({"truncated": True, "keys": sorted((details or {}).keys())})
    await db.execute(
        text("""
            INSERT INTO audit_events (tenant_id, actor, actor_kind, action, summary, target_id,
                                      method, path, details, ip)
            VALUES (:tenant_id, :actor, :actor_kind, :action, :summary, :target_id,
                    :method, :path, CAST(:details AS jsonb), :ip)
        """),
        {
            "tenant_id": tenant_id,
            "actor": actor[:200],
            "actor_kind": actor_kind,
            "action": action,
            "summary": summary[:300],
            "target_id": target_id,
            "method": request.method if request else None,
            "path": request.url.path if request else None,
            "details": payload,
            "ip": (
                request.headers.get("x-forwarded-for", "").split(",")[0].strip()
                or (request.client.host if request.client else None)
            )
            if request
            else None,
        },
    )


async def record_request(
    db: AsyncSession,
    request: Request,
    *,
    tenant_id: uuid.UUID | None,
    actor: str,
    actor_kind: str,
) -> None:
    """Record a successful mutating request from its route."""
    method, route = request.method.upper(), route_of(request)
    if method in ("GET", "HEAD", "OPTIONS") or (method, route) in SKIP:
        return
    action, template = LABELS.get(
        (method, route), (f"{method.lower()} {route}", f"{method} {route}")
    )
    body = _body(request)
    name = ""
    if isinstance(body, dict):
        name = str(body.get("name") or body.get("title") or body.get("email") or "")
    summary = template.replace("{name}", f"“{name}”" if name else "").replace(
        "{email}", name or "someone"
    )
    params = dict(request.path_params)
    target = next((str(v) for k, v in params.items() if k.endswith("_id")), None)
    await record(
        db,
        tenant_id=tenant_id,
        actor=actor,
        actor_kind=actor_kind,
        action=action,
        summary=" ".join(summary.split()),
        target_id=target,
        details={"params": params, "body": redact(body)}
        if body is not None
        else {"params": params},
        request=request,
    )


async def record_safely(db: AsyncSession, request: Request, **kw: Any) -> None:
    """record_request in a savepoint: the audit log must never undo the
    change it describes (a failed insert would abort the transaction)."""
    try:
        async with db.begin_nested():
            await record_request(db, request, **kw)
    except Exception:  # noqa: BLE001 (logged; the change itself goes through)
        log.exception("audit event not recorded for %s %s", request.method, request.url.path)
