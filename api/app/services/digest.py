# ruff: noqa: E501 -- the email is an inline HTML template
"""Digest emails: what happened over the last day or week, in one message
instead of a stream of alerts. Sent by the jobs worker (jobs.send_digests)
to the account's verified email contacts."""

import html
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Host, Incident, OutboundMessage
from app.services import heartbeats, insights
from app.services.reports import human_duration


@dataclass
class Digest:
    start: datetime
    end: datetime
    opened: int = 0
    resolved: int = 0
    critical: int = 0
    mtta_seconds: float | None = None
    mttr_seconds: float | None = None
    open_now: list[str] = field(default_factory=list)
    open_count: int = 0
    noisy: list[tuple[str, int, str | None]] = field(
        default_factory=list
    )  # rule, incidents, advice
    slos: list[tuple[str, float | None, float, str]] = field(default_factory=list)
    silent: list[str] = field(default_factory=list)
    failed_deliveries: int = 0
    servers: int = 0

    @property
    def quiet(self) -> bool:
        """Nothing worth a message: no incidents, nothing open, all fine."""
        return not (
            self.opened
            or self.open_count
            or self.silent
            or self.failed_deliveries
            or any(s[3] in ("at_risk", "breached") for s in self.slos)
        )


async def build(db: AsyncSession, tenant_id: uuid.UUID, start: datetime, end: datetime) -> Digest:
    d = Digest(start=start, end=end)
    period = (
        (Incident.tenant_id == tenant_id)
        & (Incident.opened_at >= start)
        & (Incident.opened_at < end)
    )
    row = (
        await db.execute(
            select(
                func.count(),
                func.count().filter(Incident.status == "resolved"),
                func.count().filter(Incident.severity == "critical"),
                func.avg(func.extract("epoch", Incident.acknowledged_at - Incident.opened_at)),
                func.avg(func.extract("epoch", Incident.resolved_at - Incident.opened_at)),
            ).where(period, Incident.merged_into.is_(None))
        )
    ).one()
    d.opened, d.resolved, d.critical = row[0] or 0, row[1] or 0, row[2] or 0
    d.mtta_seconds = float(row[3]) if row[3] is not None else None
    d.mttr_seconds = float(row[4]) if row[4] is not None else None
    open_rows = list(
        await db.scalars(
            select(Incident.summary)
            .where(Incident.tenant_id == tenant_id, Incident.status == "open")
            .order_by(Incident.opened_at)
        )
    )
    d.open_count, d.open_now = len(open_rows), open_rows[:8]
    days = max(1, round((end - start).total_seconds() / 86400))
    ins = await insights.build(db, tenant_id, days)
    d.noisy = [(r.rule_name, r.incidents, r.advice) for r in ins.rules[:3] if r.incidents]
    d.slos = [(s.name, s.availability, s.target, s.status) for s in ins.slos]
    hosts = list(
        await db.scalars(
            select(Host).where(
                Host.tenant_id == tenant_id, Host.revoked_at.is_(None), Host.probe_region.is_(None)
            )
        )
    )
    d.servers = len(hosts)
    seen = await heartbeats.last_seen([h.id for h in hosts])
    d.silent = sorted(h.hostname for h in hosts if not heartbeats.is_online(seen.get(h.id)))
    d.failed_deliveries = (
        await db.scalar(
            select(func.count())
            .select_from(OutboundMessage)
            .where(
                OutboundMessage.tenant_id == tenant_id,
                OutboundMessage.status == "failed",
                OutboundMessage.created_at >= start,
            )
        )
        or 0
    )
    return d


def _period_name(d: Digest) -> str:
    return "day" if d.end - d.start <= timedelta(days=1, hours=1) else "week"


def render_text(d: Digest, account: str) -> str:
    lines = [
        f"Your monitoring {_period_name(d)} — {account}",
        f"{d.start:%d %b %H:%M} – {d.end:%d %b %H:%M} UTC",
        "",
        f"Incidents: {d.opened} opened ({d.critical} critical), {d.resolved} resolved",
        f"Time to acknowledge: {human_duration(d.mtta_seconds)} · to resolve: {human_duration(d.mttr_seconds)}",
        f"Open now: {d.open_count}",
    ]
    lines += [f"  - {s}" for s in d.open_now]
    if d.silent:
        lines.append(f"Not reporting: {', '.join(d.silent[:10])}")
    if d.noisy:
        lines.append("Noisiest rules:")
        lines += [
            f"  - {name}: {n}" + (f" ({advice})" if advice else "") for name, n, advice in d.noisy
        ]
    bad = [s for s in d.slos if s[3] in ("at_risk", "breached")]
    if bad:
        lines.append("SLOs needing attention:")
        lines += [
            f"  - {n}: {a if a is not None else '—'}% of {t}% ({st.replace('_', ' ')})"
            for n, a, t, st in bad
        ]
    if d.failed_deliveries:
        lines.append(
            f"{d.failed_deliveries} alert(s) couldn't be delivered: check your alert contacts."
        )
    return "\n".join(lines)


def render_html(d: Digest, account: str, dashboard_url: str) -> str:
    e = html.escape
    tiles = [
        ("Opened", f"{d.opened}"),
        ("Critical", f"{d.critical}"),
        ("To acknowledge", human_duration(d.mtta_seconds)),
        ("To resolve", human_duration(d.mttr_seconds)),
    ]
    tile_html = "".join(
        f'<td style="padding:12px;border:1px solid #e2e8f0;border-radius:8px;width:25%">'
        f'<div style="font-size:12px;color:#64748b">{label}</div>'
        f'<div style="font-size:20px;font-weight:700">{value}</div></td>'
        for label, value in tiles
    )

    def section(title: str, items: list[str], colour: str = "#0f172a") -> str:
        if not items:
            return ""
        li = "".join(f'<li style="margin:4px 0;color:{colour}">{item}</li>' for item in items)
        return f'<h2 style="font-size:15px;margin:20px 0 6px">{title}</h2><ul style="margin:0;padding-left:18px;font-size:14px">{li}</ul>'

    open_items = [e(s) for s in d.open_now] + (
        [f"…and {d.open_count - len(d.open_now)} more"] if d.open_count > len(d.open_now) else []
    )
    noisy = [
        f"{e(n)}: {c}" + (f' <span style="color:#64748b">— {e(a)}</span>' if a else "")
        for n, c, a in d.noisy
    ]
    slo_colour = {
        "healthy": "#16a34a",
        "at_risk": "#d97706",
        "breached": "#dc2626",
        "unknown": "#64748b",
    }
    slos = [
        f'<span style="color:{slo_colour.get(st, "#64748b")};font-weight:600">{e(st.replace("_", " "))}</span> '
        f"{e(n)}: {a if a is not None else '—'}% of {t}%"
        for n, a, t, st in d.slos
    ]
    warn = (
        f'<p style="margin-top:16px;padding:10px 12px;background:#fef2f2;border-radius:8px;color:#991b1b;font-size:14px">'
        f"{d.failed_deliveries} alert(s) couldn't be delivered in this period. Check your alert contacts.</p>"
        if d.failed_deliveries
        else ""
    )
    link = (
        f'<p style="margin-top:24px"><a href="{e(dashboard_url)}" style="background:#0f172a;color:#fff;'
        f'padding:10px 18px;border-radius:8px;text-decoration:none;font-weight:600">Open the dashboard</a></p>'
        if dashboard_url
        else ""
    )
    return f"""<!doctype html><html><body style="margin:0;padding:24px;background:#f1f5f9;font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#0f172a">
<div style="max-width:640px;margin:0 auto;background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:24px">
<h1 style="margin:0;font-size:22px">Your monitoring {_period_name(d)}</h1>
<p style="margin:4px 0 20px;color:#64748b">{e(account)} · {d.servers} server(s) · {d.start:%d %b %H:%M} – {d.end:%d %b %H:%M} UTC</p>
<table width="100%" cellspacing="6"><tr>{tile_html}</tr></table>
{section(f"Open now ({d.open_count})", open_items)}
{section("Not reporting", [e(h) for h in d.silent[:15]], "#dc2626")}
{section("Noisiest rules", noisy)}
{section("SLOs", slos)}
{warn}{link}
<p style="margin-top:24px;font-size:12px;color:#94a3b8">Change how often this arrives, or turn it off, under Monitoring → Servers → Reports.</p>
</div></body></html>"""
