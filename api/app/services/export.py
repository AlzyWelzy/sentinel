"""Everything an organisation has in Sentinel, as one JSON document: its
settings, servers, rules, checks, contacts, incidents with timelines, status
pages and audit log. Metric history isn't included (it's in the reports and
CSV exports); secrets are masked or left out (tokens, keys, webhook URLs).

Runs in the caller's tenant-scoped transaction, so RLS limits every query to
the organisation even without the WHERE clauses below.
"""

import uuid
from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    AlertRule,
    Check,
    Dashboard,
    Host,
    Incident,
    IncidentEvent,
    MaintenanceWindow,
    NetworkInterface,
    NotificationChannel,
    OncallSchedule,
    SNMPCredential,
    StatusPage,
    StatusPageItem,
    Tenant,
    TenantMember,
)
from app.routes.channels import mask_target
from app.routes.checks import mask as mask_check

# Never exported: credential hashes, machine ids, the agent's state.
SKIP = {"tenant_id", "token_hash", "key_hash", "machine_id", "invite_hash"}


def _check_row(c: Check) -> dict:
    row = _row(c)
    row["target"], row["params"] = mask_check(c.type, c.target, dict(c.params or {}))
    return row


def _json(v: Any) -> Any:
    """Column values as JSON: numerics, times and ids as plain values."""
    if isinstance(v, Decimal):
        return float(v)
    if isinstance(v, (datetime, date, time)):
        return v.isoformat()
    if isinstance(v, timedelta):
        return v.total_seconds()
    if isinstance(v, uuid.UUID):
        return str(v)
    if isinstance(v, list):
        return [_json(x) for x in v]
    if isinstance(v, dict):
        return {k: _json(x) for k, x in v.items()}
    return v


def _row(obj: Any) -> dict:
    return {
        col.key: _json(getattr(obj, col.key))
        for col in obj.__table__.columns
        if col.key not in SKIP
    }


async def _all(db: AsyncSession, model: Any, tenant_id: uuid.UUID) -> list:
    return list(await db.scalars(select(model).where(model.tenant_id == tenant_id)))


async def build(db: AsyncSession, tenant_id: uuid.UUID) -> dict:
    tenant = await db.get_one(Tenant, tenant_id)
    channels = []
    for c in await _all(db, NotificationChannel, tenant_id):
        row = _row(c)
        row["target"] = mask_target(c.type, c.target)
        row.pop("config", None)
        channels.append(row)
    events: dict[str, list] = {}
    for e in await _all(db, IncidentEvent, tenant_id):
        events.setdefault(str(e.incident_id), []).append(_row(e))
    incidents = []
    for i in await _all(db, Incident, tenant_id):
        row = _row(i)
        row["events"] = events.get(str(i.id), [])
        incidents.append(row)
    audit = (
        await db.execute(
            text(
                "SELECT created_at, actor, actor_kind, action, summary FROM audit_events "
                "WHERE tenant_id = :t ORDER BY created_at DESC LIMIT 10000"
            ),
            {"t": tenant_id},
        )
    ).all()
    return {
        "format": "sentinel-export-v1",
        "exported_at": datetime.now(UTC).isoformat(),
        "organisation": {
            "id": str(tenant.id),
            "name": tenant.display_name,
            "email": tenant.email,
            "created_at": tenant.created_at.isoformat(),
            "status": tenant.status,
        },
        "members": [
            {
                "email": m.email,
                "name": m.display_name,
                "role": m.role,
                "joined_at": m.joined_at.isoformat() if m.joined_at else None,
            }
            for m in await _all(db, TenantMember, tenant_id)
        ],
        "servers": [_row(h) for h in await _all(db, Host, tenant_id)],
        # Device credentials by name and version only: their secrets stay out.
        "network_credentials": [
            {"id": str(c.id), "name": c.name, "version": c.version}
            for c in await _all(db, SNMPCredential, tenant_id)
        ],
        "network_billing_tags": [
            {"device_id": str(i.host_id), "interface": i.name, "billing_tag": i.billing_tag}
            for i in await _all(db, NetworkInterface, tenant_id)
            if i.billing_tag
        ],
        "alert_rules": [_row(r) for r in await _all(db, AlertRule, tenant_id)],
        "checks": [_check_row(c) for c in await _all(db, Check, tenant_id)],
        "contacts": channels,
        "maintenance_windows": [_row(w) for w in await _all(db, MaintenanceWindow, tenant_id)],
        "oncall_schedules": [_row(s) for s in await _all(db, OncallSchedule, tenant_id)],
        "dashboards": [_row(d) for d in await _all(db, Dashboard, tenant_id)],
        "status_pages": [_row(p) for p in await _all(db, StatusPage, tenant_id)],
        "status_page_items": [_row(i) for i in await _all(db, StatusPageItem, tenant_id)],
        "incidents": incidents,
        "audit_log": [
            {
                "at": a.created_at.isoformat(),
                "actor": a.actor,
                "actor_kind": a.actor_kind,
                "action": a.action,
                "summary": a.summary,
            }
            for a in audit
        ],
    }
