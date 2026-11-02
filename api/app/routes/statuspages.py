# ruff: noqa: E501 -- the public page is an inline HTML template
"""Status pages: a public page per account showing chosen servers and
checks, their 90-day uptime, any current incidents, the owner's own
announcements (incident updates, planned maintenance) and upcoming one-off
maintenance windows for the servers on the page.

The public view (/public/status/{slug} as JSON, /status/{slug} as HTML) is
unauthenticated, so it shows only what the owner picked: labels, up/down,
uptime percentages and incident summaries; never hostnames, IPs or targets.
"""

import html
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal, cast

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError

from app.db import ServiceSession
from app.models import (
    AlertRule,
    Check,
    Host,
    Incident,
    MaintenanceWindow,
    StatusPage,
    StatusPageItem,
    StatusPageUpdate,
)
from app.services import checkresults
from app.services.heartbeats import is_online, last_seen
from app.services.metrics import MetricsUnavailable, query_instant, query_series
from app.tenancy import Tenant, TenantContext
from app.validation import Trimmed

router = APIRouter(prefix="/v1/status-pages")
public = APIRouter()

MAX_PAGES = 10
MAX_ITEMS = 50
DAYS = 90
# Hosts push every 30 s.
PUSH_SECONDS = 30


class ItemIn(BaseModel):
    label: Annotated[str, Trimmed, Field(min_length=1, max_length=100)]
    host_id: uuid.UUID | None = None
    check_id: uuid.UUID | None = None


class PageIn(BaseModel):
    slug: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,62}$")
    title: Annotated[str, Trimmed, Field(min_length=1, max_length=100)]
    description: str | None = Field(default=None, max_length=2000)
    show_values: bool = True
    published: bool = True
    items: list[ItemIn] = Field(default_factory=list, max_length=MAX_ITEMS)


class ItemOut(ItemIn):
    id: uuid.UUID


class PageOut(BaseModel):
    id: uuid.UUID
    slug: str
    title: str
    description: str | None
    show_values: bool
    published: bool
    items: list[ItemOut]
    created_at: datetime
    updated_at: datetime


async def _page_out(t: TenantContext, p: StatusPage) -> PageOut:
    items = await t.db.scalars(
        select(StatusPageItem)
        .where(StatusPageItem.page_id == p.id, StatusPageItem.tenant_id == t.tenant_id)
        .order_by(StatusPageItem.position)
    )
    return PageOut(
        id=p.id,
        slug=p.slug,
        title=p.title,
        description=p.description,
        show_values=p.show_values,
        published=p.published,
        items=[
            ItemOut(
                id=i.id,
                label=i.label,
                host_id=i.host_id,
                check_id=i.check_id,
            )
            for i in items
        ],
        created_at=p.created_at,
        updated_at=p.updated_at,
    )


async def _set_items(t: TenantContext, page: StatusPage, items: list[ItemIn]) -> None:
    host_ids = {i.host_id for i in items if i.host_id}
    check_ids = {i.check_id for i in items if i.check_id}
    for i in items:
        if sum(x is not None for x in (i.host_id, i.check_id)) != 1:
            raise HTTPException(status_code=422, detail="each item shows one server or check")
    if host_ids:
        found = set(
            await t.db.scalars(
                select(Host.id).where(Host.id.in_(host_ids), Host.tenant_id == t.tenant_id)
            )
        )
        if found != host_ids:
            raise HTTPException(status_code=422, detail="unknown host in items")
    if check_ids:
        found = set(
            await t.db.scalars(
                select(Check.id).where(Check.id.in_(check_ids), Check.tenant_id == t.tenant_id)
            )
        )
        if found != check_ids:
            raise HTTPException(status_code=422, detail="unknown check in items")
    await t.db.execute(
        delete(StatusPageItem).where(
            StatusPageItem.page_id == page.id, StatusPageItem.tenant_id == t.tenant_id
        )
    )
    for pos, i in enumerate(items):
        t.db.add(
            StatusPageItem(
                tenant_id=t.tenant_id,
                page_id=page.id,
                label=i.label,
                host_id=i.host_id,
                check_id=i.check_id,
                position=pos,
            )
        )
    _cache.pop(page.slug, None)


async def _get(t: TenantContext, page_id: uuid.UUID) -> StatusPage:
    p = await t.db.scalar(
        select(StatusPage).where(StatusPage.id == page_id, StatusPage.tenant_id == t.tenant_id)
    )
    if p is None:
        raise HTTPException(status_code=404, detail="Status page not found")
    return p


async def _slug_free(slug: str, page_id: uuid.UUID | None) -> bool:
    # Slugs are unique across accounts, which RLS can't see: ask the service role.
    async with ServiceSession() as db:
        owner = await db.scalar(select(StatusPage.id).where(StatusPage.slug == slug))
    return owner is None or owner == page_id


@router.get("")
async def list_pages(t: Tenant) -> list[PageOut]:
    rows = await t.db.scalars(
        select(StatusPage)
        .where(StatusPage.tenant_id == t.tenant_id)
        .order_by(StatusPage.created_at)
    )
    return [await _page_out(t, p) for p in rows]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_page(body: PageIn, t: Tenant) -> PageOut:
    count = len(
        list(await t.db.scalars(select(StatusPage.id).where(StatusPage.tenant_id == t.tenant_id)))
    )
    if count >= MAX_PAGES:
        raise HTTPException(status_code=422, detail=f"at most {MAX_PAGES} status pages")
    if not await _slug_free(body.slug, None):
        raise HTTPException(status_code=409, detail="That address is taken")
    page = StatusPage(tenant_id=t.tenant_id, **body.model_dump(exclude={"items"}))
    t.db.add(page)
    try:
        await t.db.flush()
    except IntegrityError:
        raise HTTPException(status_code=409, detail="That address is taken") from None
    await _set_items(t, page, body.items)
    await t.db.flush()
    await t.db.refresh(page)
    return await _page_out(t, page)


@router.get("/{page_id}")
async def get_page(page_id: uuid.UUID, t: Tenant) -> PageOut:
    return await _page_out(t, await _get(t, page_id))


@router.put("/{page_id}")
async def update_page(page_id: uuid.UUID, body: PageIn, t: Tenant) -> PageOut:
    page = await _get(t, page_id)
    if body.slug != page.slug and not await _slug_free(body.slug, page.id):
        raise HTTPException(status_code=409, detail="That address is taken")
    _cache.pop(page.slug, None)
    for field, value in body.model_dump(exclude={"items"}).items():
        setattr(page, field, value)
    page.updated_at = datetime.now(UTC)
    await _set_items(t, page, body.items)
    await t.db.flush()
    return await _page_out(t, page)


@router.delete("/{page_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_page(page_id: uuid.UUID, t: Tenant) -> None:
    page = await _get(t, page_id)
    _cache.pop(page.slug, None)
    await t.db.delete(page)


# ── Announcements ────────────────────────────────────────────────────────────

UpdateKind = Literal["incident", "maintenance", "info"]
UpdateState = Literal[
    "investigating",
    "identified",
    "monitoring",
    "resolved",
    "scheduled",
    "in_progress",
    "completed",
    "posted",
]
STATES: dict[str, set[str]] = {
    "incident": {"investigating", "identified", "monitoring", "resolved"},
    "maintenance": {"scheduled", "in_progress", "completed"},
    "info": {"posted"},
}
CLOSED = {"resolved", "completed"}
MAX_UPDATES = 200


class UpdateIn(BaseModel):
    kind: UpdateKind
    state: UpdateState
    title: Annotated[str, Trimmed, Field(min_length=1, max_length=200)]
    body: str = Field(default="", max_length=5000)
    starts_at: datetime | None = None
    ends_at: datetime | None = None

    @model_validator(mode="after")
    def _check(self) -> "UpdateIn":
        if self.state not in STATES[self.kind]:
            raise ValueError(f"{self.kind} updates are {', '.join(sorted(STATES[self.kind]))}")
        if self.kind == "maintenance" and (self.starts_at is None or self.ends_at is None):
            raise ValueError("maintenance needs starts_at and ends_at")
        if self.starts_at and self.ends_at and self.ends_at <= self.starts_at:
            raise ValueError("ends_at must be after starts_at")
        return self


class UpdateOut(UpdateIn):
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime


def _update_out(u: StatusPageUpdate) -> UpdateOut:
    return UpdateOut(
        id=u.id,
        kind=cast(UpdateKind, u.kind),
        state=cast(UpdateState, u.state),
        title=u.title,
        body=u.body,
        starts_at=u.starts_at,
        ends_at=u.ends_at,
        created_at=u.created_at,
        updated_at=u.updated_at,
    )


async def _get_update(t: TenantContext, page: StatusPage, update_id: uuid.UUID) -> StatusPageUpdate:
    u = await t.db.scalar(
        select(StatusPageUpdate).where(
            StatusPageUpdate.id == update_id,
            StatusPageUpdate.page_id == page.id,
            StatusPageUpdate.tenant_id == t.tenant_id,
        )
    )
    if u is None:
        raise HTTPException(status_code=404, detail="Update not found")
    return u


@router.get("/{page_id}/updates")
async def list_updates(page_id: uuid.UUID, t: Tenant) -> list[UpdateOut]:
    page = await _get(t, page_id)
    rows = await t.db.scalars(
        select(StatusPageUpdate)
        .where(StatusPageUpdate.page_id == page.id, StatusPageUpdate.tenant_id == t.tenant_id)
        .order_by(StatusPageUpdate.created_at.desc())
        .limit(MAX_UPDATES)
    )
    return [_update_out(u) for u in rows]


@router.post("/{page_id}/updates", status_code=status.HTTP_201_CREATED)
async def create_update(page_id: uuid.UUID, body: UpdateIn, t: Tenant) -> UpdateOut:
    page = await _get(t, page_id)
    u = StatusPageUpdate(tenant_id=t.tenant_id, page_id=page.id, **body.model_dump())
    t.db.add(u)
    _cache.pop(page.slug, None)
    await t.db.flush()
    await t.db.refresh(u)
    return _update_out(u)


@router.put("/{page_id}/updates/{update_id}")
async def edit_update(
    page_id: uuid.UUID, update_id: uuid.UUID, body: UpdateIn, t: Tenant
) -> UpdateOut:
    page = await _get(t, page_id)
    u = await _get_update(t, page, update_id)
    for field, value in body.model_dump().items():
        setattr(u, field, value)
    u.updated_at = datetime.now(UTC)
    _cache.pop(page.slug, None)
    await t.db.flush()
    return _update_out(u)


@router.delete("/{page_id}/updates/{update_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_update(page_id: uuid.UUID, update_id: uuid.UUID, t: Tenant) -> None:
    page = await _get(t, page_id)
    await t.db.delete(await _get_update(t, page, update_id))
    _cache.pop(page.slug, None)


# ── Public view ──────────────────────────────────────────────────────────────

ItemStatus = Literal["up", "down", "unknown"]


class PublicDay(BaseModel):
    date: str
    uptime: float | None


class PublicItem(BaseModel):
    label: str
    status: ItemStatus
    uptime_90d: float | None
    response_ms: float | None
    days: list[PublicDay]


class PublicIncident(BaseModel):
    title: str
    started_at: datetime
    resolved_at: datetime | None


class PublicUpdate(BaseModel):
    kind: str
    state: str
    title: str
    body: str
    starts_at: datetime | None
    ends_at: datetime | None
    updated_at: datetime


class PublicPage(BaseModel):
    title: str
    description: str | None
    status: Literal["operational", "degraded", "outage", "maintenance"]
    items: list[PublicItem]
    incidents: list[PublicIncident]
    updated_at: datetime
    # Open incident updates and maintenance that's coming or under way.
    active: list[PublicUpdate] = []
    # Closed ones from the last 14 days.
    history: list[PublicUpdate] = []


CACHE_SECONDS = 30
_cache: dict[str, tuple[float, PublicPage]] = {}


async def _daily(
    tenant_id: uuid.UUID, expr: str, per_second: float | None, since: int | None = None
) -> list[PublicDay]:
    """Uptime per UTC day for the last DAYS days. expr has WINDOW where the
    range goes. per_second set: expr counts pushes, turned into a percentage
    of the pushes expected (per_second of them per second) over the part of
    each day after `since` (when the server was added); otherwise expr is
    already a 0-1 ratio."""
    now = int(time.time())
    today = now // 86400 * 86400
    start = today - (DAYS - 1) * 86400
    points: dict[int, float] = {}
    try:
        # Whole days, each evaluated at its end (the next midnight).
        if DAYS > 1:
            for s_ in await query_series(
                tenant_id, expr.replace("WINDOW", "1d"), start + 86400, today, 86400, []
            ):
                points.update({int(ts) - 86400: v for ts, v in s_["points"]})
        # Today so far.
        elapsed = max(now - today, 60)
        for _, v in await query_instant(tenant_id, expr.replace("WINDOW", f"{elapsed}s")):
            points[today] = v
    except MetricsUnavailable:
        pass
    days = []
    for d in range(DAYS):
        ts = start + d * 86400
        v = points.get(ts)
        if v is not None and per_second:
            observed = min(ts + 86400, now) - max(ts, since or ts)
            v = v / (observed * per_second) if observed >= 60 else None
        days.append(
            PublicDay(
                date=datetime.fromtimestamp(ts, UTC).date().isoformat(),
                uptime=None if v is None else round(min(v * 100, 100.0), 3),
            )
        )
    return days


async def build_public(slug: str) -> PublicPage | None:
    cached = _cache.get(slug)
    if cached and time.monotonic() - cached[0] < CACHE_SECONDS:
        return cached[1]
    async with ServiceSession() as db:
        page = await db.scalar(
            select(StatusPage).where(StatusPage.slug == slug, StatusPage.published)
        )
        if page is None:
            return None
        items = list(
            await db.scalars(
                select(StatusPageItem)
                .where(
                    StatusPageItem.page_id == page.id, StatusPageItem.tenant_id == page.tenant_id
                )
                .order_by(StatusPageItem.position)
            )
        )
        host_ids = [i.host_id for i in items if i.host_id]
        check_ids = [i.check_id for i in items if i.check_id]
        hosts_created = {
            h.id: h.created_at
            for h in await db.scalars(
                select(Host).where(Host.id.in_(host_ids), Host.tenant_id == page.tenant_id)
            )
        }
        checks = {
            c.id: c
            for c in await db.scalars(
                select(Check).where(Check.id.in_(check_ids), Check.tenant_id == page.tenant_id)
            )
        }
        since = datetime.fromtimestamp(time.time() - 7 * 86400, UTC)
        # Only outages belong on a public page: a server that stopped
        # reporting, or an uptime check that's down. Not every alert rule.
        host_down_rules = select(AlertRule.id).where(
            AlertRule.tenant_id == page.tenant_id, AlertRule.kind == "host_down"
        )
        incidents = list(
            await db.scalars(
                select(Incident)
                .where(
                    Incident.tenant_id == page.tenant_id,
                    (
                        Incident.host_id.in_(host_ids)
                        & Incident.check_id.is_(None)
                        & Incident.rule_id.in_(host_down_rules)
                    )
                    | (Incident.check_id.in_(check_ids) & Incident.host_id.is_(None)),
                    (Incident.status == "open") | (Incident.opened_at >= since),
                )
                .order_by(Incident.opened_at.desc())
                .limit(20)
            )
        )
        now = datetime.now(UTC)
        updates = list(
            await db.scalars(
                select(StatusPageUpdate)
                .where(
                    StatusPageUpdate.page_id == page.id,
                    StatusPageUpdate.tenant_id == page.tenant_id,
                    StatusPageUpdate.state.not_in(CLOSED)
                    | (StatusPageUpdate.updated_at >= now - timedelta(days=14)),
                )
                .order_by(StatusPageUpdate.created_at.desc())
                .limit(30)
            )
        )
        # One-off maintenance windows on the page's servers, coming within a
        # week or under way, announce themselves (weekly ones would be noise).
        windows = list(
            await db.scalars(
                select(MaintenanceWindow).where(
                    MaintenanceWindow.tenant_id == page.tenant_id,
                    MaintenanceWindow.enabled,
                    MaintenanceWindow.schedule == "once",
                    MaintenanceWindow.host_id.in_(host_ids),
                    MaintenanceWindow.ends_at > now,
                    MaintenanceWindow.starts_at < now + timedelta(days=7),
                )
            )
        )
    seen = await last_seen(host_ids)
    results = await checkresults.latest(check_ids)
    labels = {i.host_id or i.check_id: i.label for i in items}
    out_items = []
    for i in items:
        if i.host_id:
            st = (
                "up"
                if is_online(seen.get(i.host_id))
                else ("down" if seen.get(i.host_id) else "unknown")
            )
            days = await _daily(
                page.tenant_id,
                f'count_over_time(sentinel_uptime_seconds{{host_id="{i.host_id}"}}[WINDOW])',
                1 / PUSH_SECONDS,
                since=int(hosts_created[i.host_id].timestamp())
                if i.host_id in hosts_created
                else None,
            )
            response = None
        else:
            c = checks.get(i.check_id)  # type: ignore[arg-type]
            if c is None:
                continue
            res = results.get(c.id, [])
            failing = sum(1 for r in res if not r.get("ok"))
            need = min(c.min_failing, len(res)) if c.on_probes else 1
            st = "unknown" if not res else ("down" if failing >= max(need, 1) else "up")
            days = await _daily(
                page.tenant_id,
                f'avg(avg_over_time(sentinel_check_up{{check_id="{c.id}"}}[WINDOW]))',
                None,
            )
            lat = [r["latency_ms"] for r in res if r.get("latency_ms")]
            response = round(sum(lat) / len(lat), 1) if lat and page.show_values else None
        known = [d.uptime for d in days if d.uptime is not None]
        out_items.append(
            PublicItem(
                label=i.label,
                status=st,
                uptime_90d=round(sum(known) / len(known), 3)
                if known and page.show_values
                else None,
                response_ms=response,
                days=days
                if page.show_values
                else [PublicDay(date=d.date, uptime=None) for d in days],
            )
        )
    labels_by_host = {i.host_id: i.label for i in items if i.host_id}
    active = [
        PublicUpdate(
            kind=u.kind,
            state=u.state,
            title=u.title,
            body=u.body,
            starts_at=u.starts_at,
            ends_at=u.ends_at,
            updated_at=u.updated_at,
        )
        for u in updates
        if u.state not in CLOSED
    ]
    for w in windows:
        if w.starts_at is None or w.ends_at is None:
            continue
        under_way = w.starts_at <= now
        active.append(
            PublicUpdate(
                kind="maintenance",
                state="in_progress" if under_way else "scheduled",
                title=f"Planned maintenance: {labels_by_host.get(w.host_id, 'Service')}",
                body="Some services may be briefly unavailable during this window.",
                starts_at=w.starts_at,
                ends_at=w.ends_at,
                updated_at=w.starts_at,
            )
        )
    history = [
        PublicUpdate(
            kind=u.kind,
            state=u.state,
            title=u.title,
            body=u.body,
            starts_at=u.starts_at,
            ends_at=u.ends_at,
            updated_at=u.updated_at,
        )
        for u in updates
        if u.state in CLOSED
    ]
    down = sum(1 for i in out_items if i.status == "down")
    overall = "operational" if down == 0 else ("outage" if down == len(out_items) else "degraded")
    # The owner's word counts: an open incident announcement means something's wrong.
    if overall == "operational" and any(a.kind == "incident" for a in active):
        overall = "degraded"
    if overall == "operational" and any(
        a.kind == "maintenance" and a.state == "in_progress" for a in active
    ):
        overall = "maintenance"
    result = PublicPage(
        title=page.title,
        description=page.description,
        status=overall,
        items=out_items,
        incidents=[
            PublicIncident(
                # The owner's label, not the internal summary (which names hosts).
                title=f"{labels.get(inc.host_id or inc.check_id, 'Service')}: "
                + ("investigating" if inc.status == "open" else "resolved"),
                started_at=inc.opened_at,
                resolved_at=inc.resolved_at,
            )
            for inc in incidents
        ],
        updated_at=datetime.now(UTC),
        active=active,
        history=history,
    )
    _cache[slug] = (time.monotonic(), result)
    return result


@public.get("/public/status/{slug}", tags=["public"])
async def public_status(slug: str) -> PublicPage:
    page = await build_public(slug)
    if page is None:
        raise HTTPException(status_code=404, detail="Status page not found")
    return page


COLOURS = {"up": "#16a34a", "down": "#dc2626", "unknown": "#94a3b8"}
BANNER = {
    "operational": ("#16a34a", "All systems operational"),
    "degraded": ("#d97706", "Some systems are having problems"),
    "outage": ("#dc2626", "Major outage"),
    "maintenance": ("#2563eb", "Planned maintenance in progress"),
}
STATE_LABEL = {
    "investigating": "Investigating",
    "identified": "Identified",
    "monitoring": "Monitoring",
    "resolved": "Resolved",
    "scheduled": "Scheduled",
    "in_progress": "In progress",
    "completed": "Completed",
    "posted": "Update",
}


def _bar(uptime: float | None) -> str:
    if uptime is None:
        colour = "#e2e8f0"
    elif uptime >= 99.9:
        colour = "#16a34a"
    elif uptime >= 99:
        colour = "#84cc16"
    elif uptime >= 95:
        colour = "#f59e0b"
    else:
        colour = "#dc2626"
    return f'<i style="background:{colour}"></i>'


@public.get("/status/{slug}", response_class=HTMLResponse, include_in_schema=False)
async def public_status_html(slug: str) -> HTMLResponse:
    page = await build_public(slug)
    if page is None:
        return HTMLResponse("<h1>Status page not found</h1>", status_code=404)
    e = html.escape
    colour, text = BANNER[page.status]
    rows = []
    for i in page.items:
        bars = "".join(_bar(d.uptime) for d in i.days)
        stats = []
        if i.uptime_90d is not None:
            stats.append(f"{i.uptime_90d:.2f}% uptime (90 days)")
        if i.response_ms is not None:
            stats.append(f"{i.response_ms:.0f} ms")
        rows.append(
            f'<section><div class="row"><b>{e(i.label)}</b>'
            f'<span class="dot" style="background:{COLOURS[i.status]}"></span>'
            f'<span class="st">{e(i.status.title() if i.status != "unknown" else "No data")}</span></div>'
            f'<div class="bars">{bars}</div><small>{e(" · ".join(stats))}</small></section>'
        )

    def update_html(u: PublicUpdate) -> str:
        when = ""
        if u.starts_at and u.ends_at:
            when = f"<small>{u.starts_at:%d %b %H:%M} – {u.ends_at:%d %b %H:%M} UTC</small>"
        tone = (
            "#16a34a"
            if u.state in CLOSED
            else {"incident": "#dc2626", "maintenance": "#2563eb"}.get(u.kind, "#64748b")
        )
        return (
            f'<div class="card" style="border-left:4px solid {tone}"><div class="row"><b>{e(u.title)}</b>'
            f'<span class="st">{e(STATE_LABEL.get(u.state, u.state))}</span></div>'
            + (f"<p>{e(u.body)}</p>" if u.body else "")
            + f"{when}<br><small>Updated {u.updated_at:%d %b %Y %H:%M} UTC</small></div>"
        )

    active = "".join(update_html(u) for u in page.active)
    history = "".join(update_html(u) for u in page.history)
    incidents = (
        "".join(
            f"<li><b>{e(inc.title)}</b> <small>{inc.started_at:%d %b %Y %H:%M} UTC"
            + (f" – {inc.resolved_at:%H:%M}" if inc.resolved_at else "")
            + "</small></li>"
            for inc in page.incidents
        )
        or "<li><small>No incidents in the last 7 days.</small></li>"
    )
    body = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="60">
<title>{e(page.title)}</title><style>
:root{{--bg:#f8fafc;--card:#fff;--text:#0f172a;--muted:#64748b;--line:#e2e8f0}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0b1120;--card:#111827;--text:#f1f5f9;--muted:#94a3b8;--line:#1f2937}}}}
body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}}
main{{max-width:760px;margin:0 auto;padding:32px 16px}}h1{{margin:0 0 4px;font-size:26px}}
.banner{{margin:20px 0;padding:14px 18px;border-radius:10px;color:#fff;font-weight:600;background:{colour}}}
section,.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 18px;margin-bottom:12px}}
.row{{display:flex;align-items:center;gap:8px}}.row b{{flex:1}}.dot{{width:10px;height:10px;border-radius:50%}}
.st{{color:var(--muted);font-size:13px}}.bars{{display:flex;gap:2px;margin:10px 0 4px;height:28px}}
.bars i{{flex:1;border-radius:2px}}small{{color:var(--muted)}}ul{{padding-left:18px;margin:0}}
footer{{margin-top:24px;color:var(--muted);font-size:12px;text-align:center}}</style></head>
<body><main><h1>{e(page.title)}</h1>{f"<p>{e(page.description)}</p>" if page.description else ""}
<div class="banner">{text}</div>{active}{"".join(rows)}
<div class="card"><b>Recent incidents</b><ul>{incidents}</ul></div>
{f"<h3>Past updates</h3>{history}" if history else ""}
<footer>Updated {page.updated_at:%d %b %Y %H:%M} UTC · Powered by Sentinel</footer></main></body></html>"""
    return HTMLResponse(body, headers={"Cache-Control": f"public, max-age={CACHE_SECONDS}"})
