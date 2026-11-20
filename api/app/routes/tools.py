"""Everyday tools: search across monitoring, bulk changes to servers, and the
agent doctor (what's wrong with a server's agent, and how to fix it)."""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import any_, literal, or_, select

from app.models import (
    AlertRule,
    Check,
    Dashboard,
    Host,
    Incident,
    MaintenanceWindow,
    OncallSchedule,
)
from app.models import (
    Tenant as TenantRow,
)
from app.services import heartbeats, metrics, rollout
from app.services.metrics import MetricsUnavailable
from app.tenancy import Tenant
from app.validation import normalize_tag

router = APIRouter(prefix="/v1", tags=["tools"])


# ── Search ───────────────────────────────────────────────────────────────────


class SearchHit(BaseModel):
    kind: Literal["server", "check", "rule", "incident", "dashboard", "schedule"]
    id: uuid.UUID
    title: str
    subtitle: str | None = None


@router.get("/search")
async def search(
    t: Tenant, q: Annotated[str, Query(min_length=2, max_length=100)]
) -> list[SearchHit]:
    """Servers (name, tag or IP), checks, rules, open incidents, dashboards
    and on-call schedules matching the text, a few of each."""
    like = f"%{q.strip()}%"
    hits: list[SearchHit] = []
    for h in await t.db.scalars(
        select(Host)
        .where(
            Host.tenant_id == t.tenant_id,
            Host.revoked_at.is_(None),
            or_(
                Host.hostname.ilike(like),
                Host.public_ip.ilike(like),
                literal(q.strip().lower()) == any_(Host.tags),
            ),
        )
        .order_by(Host.hostname)
        .limit(6)
    ):
        sub = " · ".join(filter(None, [h.platform, ", ".join(h.tags or []), h.public_ip]))
        hits.append(SearchHit(kind="server", id=h.id, title=h.hostname, subtitle=sub or None))
    for c in await t.db.scalars(
        select(Check)
        .where(
            Check.tenant_id == t.tenant_id, or_(Check.name.ilike(like), Check.target.ilike(like))
        )
        .limit(5)
    ):
        hits.append(
            SearchHit(kind="check", id=c.id, title=c.name, subtitle=f"{c.type} · {c.target}")
        )
    for r in await t.db.scalars(
        select(AlertRule)
        .where(
            AlertRule.tenant_id == t.tenant_id,
            AlertRule.kind != "check",
            AlertRule.name.ilike(like),
        )
        .limit(5)
    ):
        hits.append(
            SearchHit(kind="rule", id=r.id, title=r.name, subtitle=f"Alert rule · {r.kind}")
        )
    for i in await t.db.scalars(
        select(Incident)
        .where(
            Incident.tenant_id == t.tenant_id,
            Incident.status == "open",
            Incident.summary.ilike(like),
        )
        .order_by(Incident.opened_at.desc())
        .limit(5)
    ):
        hits.append(
            SearchHit(
                kind="incident", id=i.id, title=i.summary, subtitle=f"Open incident · {i.severity}"
            )
        )
    for d in await t.db.scalars(
        select(Dashboard)
        .where(Dashboard.tenant_id == t.tenant_id, Dashboard.name.ilike(like))
        .limit(3)
    ):
        hits.append(SearchHit(kind="dashboard", id=d.id, title=d.name, subtitle="Dashboard"))
    for s in await t.db.scalars(
        select(OncallSchedule)
        .where(OncallSchedule.tenant_id == t.tenant_id, OncallSchedule.name.ilike(like))
        .limit(3)
    ):
        hits.append(SearchHit(kind="schedule", id=s.id, title=s.name, subtitle="On-call schedule"))
    return hits


# ── Bulk changes ─────────────────────────────────────────────────────────────


class BulkIn(BaseModel):
    host_ids: list[uuid.UUID] = Field(min_length=1, max_length=500)
    action: Literal["add_tag", "remove_tag", "mute", "pause", "resume", "delete"]
    tag: str | None = None
    minutes: int | None = Field(default=None, ge=15, le=7 * 24 * 60, description="mute: how long")

    @field_validator("tag")
    @classmethod
    def _tag(cls, v: str | None) -> str | None:
        return None if v is None or not v.strip() else normalize_tag(v)

    @model_validator(mode="after")
    def _needs(self) -> "BulkIn":
        if self.action in ("add_tag", "remove_tag") and not self.tag:
            raise ValueError("adding or removing a tag needs the tag")
        if self.action == "mute" and not self.minutes:
            raise ValueError("muting needs minutes")
        return self


class BulkOut(BaseModel):
    action: str
    changed: int


@router.post("/hosts/bulk")
async def bulk(body: BulkIn, t: Tenant) -> BulkOut:
    """Tag, untag, mute (a maintenance window per server), pause, resume or
    remove many servers at once. Removing works as removing one: open incidents resolve."""
    hosts = list(
        await t.db.scalars(
            select(Host).where(
                Host.tenant_id == t.tenant_id,
                Host.id.in_(body.host_ids),
                Host.revoked_at.is_(None),
            )
        )
    )
    if len(hosts) != len(set(body.host_ids)):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Server not found")
    now = datetime.now(UTC)
    if body.action == "add_tag":
        for h in hosts:
            tag = body.tag or ""
            if tag not in (h.tags or []):
                h.tags = sorted({*(h.tags or []), tag})
    elif body.action == "remove_tag":
        for h in hosts:
            h.tags = [x for x in (h.tags or []) if x != body.tag]
    elif body.action == "mute":
        for h in hosts:
            t.db.add(
                MaintenanceWindow(
                    tenant_id=t.tenant_id,
                    name=f"Muted {h.hostname}",
                    host_id=h.id,
                    schedule="once",
                    starts_at=now,
                    ends_at=now + timedelta(minutes=body.minutes or 60),
                    timezone="UTC",
                )
            )
    elif body.action == "pause":
        from app.routes.v1 import pause_hosts

        await pause_hosts(t, hosts)
    elif body.action == "resume":
        from app.routes.v1 import resume_hosts

        resume_hosts(hosts)
    else:
        from app.routes.v1 import delete_host

        # Devices first: a server that polls them can go in the same request.
        for h in sorted(hosts, key=lambda h: h.kind != "network"):
            await delete_host(h.id, t)
            await t.db.flush()
    await t.db.flush()
    return BulkOut(action=body.action, changed=len(hosts))


# ── Agent doctor ─────────────────────────────────────────────────────────────


class Finding(BaseModel):
    level: Literal["ok", "warning", "problem"]
    title: str
    detail: str
    fix: str | None = None


class DoctorOut(BaseModel):
    host_id: uuid.UUID
    hostname: str
    healthy: bool
    findings: list[Finding]


def _version(v: str) -> tuple[int, ...]:
    """ "0.9.10" > "0.9.9"; anything that isn't numbers sorts first."""
    try:
        return tuple(int(p) for p in v.split("-")[0].split("."))
    except ValueError:
        return ()


@router.get("/hosts/{host_id}/doctor")
async def doctor(host_id: uuid.UUID, t: Tenant) -> DoctorOut:
    """Why a server's data might be missing or wrong: reporting, version,
    clock, plugins, logs."""
    host = await t.db.scalar(select(Host).where(Host.id == host_id, Host.tenant_id == t.tenant_id))
    if host is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Server not found")
    out: list[Finding] = []
    seen = (await heartbeats.last_seen([host.id])).get(host.id)
    now = datetime.now(UTC).timestamp()
    if seen is None:
        out.append(
            Finding(
                level="problem",
                title="Never reported",
                detail="The agent registered but has sent no data.",
                fix=(
                    "On the server: systemctl status sentinel-agent (Windows: Get-Service "
                    "sentinel-agent). It needs outbound HTTPS to the ingest URL."
                ),
            )
        )
    elif not heartbeats.is_online(seen):
        mins = int((now - seen) // 60)
        out.append(
            Finding(
                level="problem",
                title=f"Silent for {mins} minute{'s' if mins != 1 else ''}",
                detail=(
                    "No data recently: the server is down, the agent stopped, or the network "
                    "blocks it."
                ),
                fix=(
                    "Check the server is up, then: systemctl restart sentinel-agent, and "
                    "journalctl -u sentinel-agent."
                ),
            )
        )
    else:
        out.append(
            Finding(level="ok", title="Reporting", detail="Data arrived within the last minute.")
        )

    ahead = await heartbeats.clock_ahead(host.id)
    if ahead:
        mins = max(1, round(ahead / 60))
        dropped = ahead > 600
        out.append(
            Finding(
                level="problem" if dropped else "warning",
                title=f"Clock {mins} minute{'s' if mins != 1 else ''} fast",
                detail=(
                    "Samples stamped more than 10 minutes ahead are discarded, so this server's "
                    "charts stay empty."
                    if dropped
                    else "Its samples are stamped in the future, so charts and alerts run early."
                ),
                fix="Turn on time sync: timedatectl set-ntp true (Windows: w32tm /resync).",
            )
        )

    plan = await rollout.current(t.db)
    pin = await t.db.scalar(select(TenantRow.agent_version_pin).where(TenantRow.id == t.tenant_id))
    offered = rollout.version_for(plan, host.id, pin)
    running = host.agent_version
    if running and offered not in ("", "latest", "dev") and running != offered:
        if _version(running) > _version(offered):
            out.append(
                Finding(
                    level="ok",
                    title=f"Agent {running}, newer than {offered}",
                    detail=(
                        f"It moves to {offered} at its next hourly update, as a rollback or "
                        "pin asks."
                    ),
                )
            )
        else:
            out.append(
                Finding(
                    level="warning",
                    title=f"Agent {running}, {offered} offered",
                    detail=(
                        "Agents update themselves within the hour. One that stays behind can't "
                        "reach the download URL, or runs in a container without the "
                        "self-updating image."
                    ),
                    fix="On the server, as root: sentinel-agent update",
                )
            )
    else:
        out.append(Finding(level="ok", title=f"Agent {running or 'unknown'}", detail="Up to date."))

    try:
        series = await metrics.query_range(
            t.tenant_id, host.id, "processes", int(now) - 900, int(now), 60
        )
        if seen is not None and heartbeats.is_online(seen) and not any(s["points"] for s in series):
            out.append(
                Finding(
                    level="warning",
                    title="Reporting, but no metrics stored",
                    detail="Heartbeats arrive but no samples were stored in the last 15 minutes.",
                    fix=(
                        "The server's clock may be far off: turn on time sync "
                        "(timedatectl set-ntp true)."
                    ),
                )
            )
        elif series and series[0]["points"]:
            lag = now - series[0]["points"][-1][0]
            if lag > 300 and seen is not None and heartbeats.is_online(seen):
                out.append(
                    Finding(
                        level="warning",
                        title="Samples arrive late",
                        detail=(
                            f"The newest sample is {int(lag // 60)} minutes old: the server's "
                            f"clock may be behind."
                        ),
                        fix="Turn on time sync: timedatectl set-ntp true",
                    )
                )
    except MetricsUnavailable:
        out.append(
            Finding(
                level="warning",
                title="Metrics unavailable",
                detail="Couldn't read metrics just now.",
            )
        )

    try:
        plugins = await metrics.query_instant(
            t.tenant_id, f'sentinel_plugin_up{{host_id="{host.id}"}} == 0'
        )
        for labels, _ in plugins:
            name = labels.get("plugin", "a plugin")
            out.append(
                Finding(
                    level="warning",
                    title=f"Plugin {name} failing",
                    detail="It runs but can't collect (wrong credentials, socket or URL).",
                    fix=(
                        "On the server: sentinel-agent plugins (tests every plugin file and says "
                        "what's wrong)"
                    ),
                )
            )
    except MetricsUnavailable:
        pass

    if host.depends_on_host_id:
        parent = await t.db.get(Host, host.depends_on_host_id)
        if parent is not None:
            pseen = (await heartbeats.last_seen([parent.id])).get(parent.id)
            if not heartbeats.is_online(pseen):
                out.append(
                    Finding(
                        level="warning",
                        title=f"Depends on {parent.hostname}, which is silent",
                        detail=(
                            "This server's alerts are held back while the server it depends on "
                            "is down."
                        ),
                    )
                )
    healthy = not any(f.level == "problem" for f in out)
    return DoctorOut(host_id=host.id, hostname=host.hostname, healthy=healthy, findings=out)
