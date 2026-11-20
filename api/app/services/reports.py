# ruff: noqa: E501 -- the email is an inline HTML template
"""Availability and incident reports for one account over a period.

Built from Postgres (incidents, hosts, checks) and VictoriaMetrics (uptime,
resource use, trends). The same summary feeds the dashboard's Reports view,
its CSV export and the monthly email.
"""

import html
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Check, Host, Incident
from app.services.metrics import MetricsUnavailable, query_instant

PUSH_SECONDS = 30


@dataclass
class HostReport:
    host_id: str
    hostname: str
    availability: float | None
    incidents: int
    cpu_avg: float | None = None
    cpu_max: float | None = None
    memory_avg: float | None = None
    memory_max: float | None = None
    disk_max: float | None = None
    disk_full_in_days: float | None = None
    kind: str = "server"


@dataclass
class CheckReport:
    check_id: str
    name: str
    type: str
    uptime: float | None
    avg_latency_ms: float | None
    incidents: int


@dataclass
class RuleReport:
    rule_name: str
    incidents: int


@dataclass
class Summary:
    start: datetime
    end: datetime
    hosts: list[HostReport] = field(default_factory=list)
    checks: list[CheckReport] = field(default_factory=list)
    incidents_total: int = 0
    incidents_critical: int = 0
    mtta_seconds: float | None = None
    mttr_seconds: float | None = None
    noisiest_rules: list[RuleReport] = field(default_factory=list)
    availability: float | None = None
    metrics_available: bool = True


async def _by_host(tenant_id: uuid.UUID, query: str) -> dict[str, float]:
    return {labels.get("host_id", ""): v for labels, v in await query_instant(tenant_id, query)}


async def build_summary(
    db: AsyncSession, tenant_id: uuid.UUID, start: datetime, end: datetime
) -> Summary:
    s = Summary(start=start, end=end)
    seconds = max(int((end - start).total_seconds()), 3600)
    at = int(end.timestamp())
    window = f"{seconds}s"

    hosts = list(
        await db.scalars(
            select(Host)
            .where(
                Host.tenant_id == tenant_id, Host.revoked_at.is_(None), Host.probe_region.is_(None)
            )
            .order_by(Host.hostname)
        )
    )
    checks = list(
        await db.scalars(select(Check).where(Check.tenant_id == tenant_id).order_by(Check.name))
    )
    in_period = (
        (Incident.tenant_id == tenant_id)
        & (Incident.opened_at >= start)
        & (Incident.opened_at < end)
    )
    per_host = {
        r[0]: r[1]
        for r in await db.execute(
            select(Incident.host_id, func.count()).where(in_period).group_by(Incident.host_id)
        )
    }
    per_check = {
        r[0]: r[1]
        for r in await db.execute(
            select(Incident.check_id, func.count()).where(in_period).group_by(Incident.check_id)
        )
    }
    row = (
        await db.execute(
            select(
                func.count(),
                func.count().filter(Incident.severity == "critical"),
                func.avg(func.extract("epoch", Incident.acknowledged_at - Incident.opened_at)),
                func.avg(func.extract("epoch", Incident.resolved_at - Incident.opened_at)),
            ).where(in_period)
        )
    ).one()
    s.incidents_total, s.incidents_critical = row[0] or 0, row[1] or 0
    s.mtta_seconds = float(row[2]) if row[2] is not None else None
    s.mttr_seconds = float(row[3]) if row[3] is not None else None
    s.noisiest_rules = [
        RuleReport(rule_name=r[0], incidents=r[1])
        for r in await db.execute(
            select(Incident.rule_name, func.count())
            .where(in_period)
            .group_by(Incident.rule_name)
            .order_by(func.count().desc())
            .limit(5)
        )
    ]

    def q(expr: str) -> str:
        # Evaluate at the period's end, looking back over the period.
        return expr.replace("WINDOW", window) + f" @ {at}"

    metrics: dict[str, dict[str, float]] = {}
    check_up: dict[str, float] = {}
    check_lat: dict[str, float] = {}
    try:
        metrics["pushes"] = await _by_host(
            tenant_id, q("count_over_time(sentinel_uptime_seconds[WINDOW])")
        )
        metrics["cpu_avg"] = await _by_host(
            tenant_id, q("avg_over_time(sentinel_cpu_usage_percent[WINDOW])")
        )
        metrics["cpu_max"] = await _by_host(
            tenant_id, q("max_over_time(sentinel_cpu_usage_percent[WINDOW])")
        )
        metrics["memory_avg"] = await _by_host(
            tenant_id, q("avg_over_time(sentinel_memory_used_percent[WINDOW])")
        )
        metrics["memory_max"] = await _by_host(
            tenant_id, q("max_over_time(sentinel_memory_used_percent[WINDOW])")
        )
        metrics["disk_max"] = await _by_host(
            tenant_id, q("max by (host_id) (max_over_time(sentinel_disk_used_percent[WINDOW]))")
        )
        # Days until the fullest-growing filesystem fills, from the last week's trend.
        metrics["disk_full"] = await _by_host(
            tenant_id,
            f"min by (host_id) (((100 - sentinel_disk_used_percent) / (deriv(sentinel_disk_used_percent[7d]) * 86400)) > 0) @ {at}",
        )
        for labels, v in await query_instant(
            tenant_id, q("avg by (check_id) (avg_over_time(sentinel_check_up[WINDOW])) * 100")
        ):
            check_up[labels.get("check_id", "")] = v
        for labels, v in await query_instant(
            tenant_id,
            q("avg by (check_id) (avg_over_time(sentinel_check_latency_seconds[WINDOW])) * 1000"),
        ):
            check_lat[labels.get("check_id", "")] = v
    except MetricsUnavailable:
        s.metrics_available = False

    def r(v: float | None, digits: int = 1) -> float | None:
        return None if v is None else round(v, digits)

    availabilities = []
    for h in hosts:
        hid = str(h.id)
        observed = min(seconds, max(int((end - max(h.created_at, start)).total_seconds()), 0))
        expected = observed / PUSH_SECONDS
        pushes = metrics.get("pushes", {}).get(hid)
        availability = None
        if expected >= 1 and s.metrics_available:
            availability = min((pushes or 0) / expected * 100, 100.0)
            availabilities.append(availability)
        full = metrics.get("disk_full", {}).get(hid)
        s.hosts.append(
            HostReport(
                host_id=hid,
                hostname=h.hostname,
                kind="device" if h.kind == "network" else "server",
                availability=r(availability, 3),
                incidents=per_host.get(h.id, 0),
                cpu_avg=r(metrics.get("cpu_avg", {}).get(hid)),
                cpu_max=r(metrics.get("cpu_max", {}).get(hid)),
                memory_avg=r(metrics.get("memory_avg", {}).get(hid)),
                memory_max=r(metrics.get("memory_max", {}).get(hid)),
                disk_max=r(metrics.get("disk_max", {}).get(hid)),
                disk_full_in_days=r(full) if full is not None and full < 365 else None,
            )
        )
    for c in checks:
        cid = str(c.id)
        s.checks.append(
            CheckReport(
                check_id=cid,
                name=c.name,
                type=c.type,
                uptime=r(check_up.get(cid), 3),
                avg_latency_ms=r(check_lat.get(cid)),
                incidents=per_check.get(c.id, 0),
            )
        )
    if availabilities:
        s.availability = round(sum(availabilities) / len(availabilities), 3)
    return s


def previous_month(now: datetime) -> tuple[datetime, datetime]:
    first = now.astimezone(UTC).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if first.month == 1:
        prev = first.replace(year=first.year - 1, month=12)
    else:
        prev = first.replace(month=first.month - 1)
    return prev, first


def human_duration(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m"
    if s < 86400:
        return f"{s // 3600}h {s % 3600 // 60}m"
    return f"{s // 86400}d {s % 86400 // 3600}h"


def render_text(summary: Summary, account: str) -> str:
    lines = [
        f"Sentinel monthly report for {account}",
        f"{summary.start:%d %b %Y} – {summary.end:%d %b %Y}",
        "",
        f"Average availability: {summary.availability if summary.availability is not None else '—'}%",
        f"Incidents: {summary.incidents_total} ({summary.incidents_critical} critical)",
        f"Mean time to acknowledge: {human_duration(summary.mtta_seconds)}",
        f"Mean time to resolve: {human_duration(summary.mttr_seconds)}",
        "",
        "Servers:",
    ]
    for h in summary.hosts:
        extra = f", disk full in ~{h.disk_full_in_days:.0f} days" if h.disk_full_in_days else ""
        lines.append(
            f"  {h.hostname}: {h.availability if h.availability is not None else '—'}% available, "
            f"{h.incidents} incidents, CPU avg {h.cpu_avg or '—'}%{extra}"
        )
    if summary.checks:
        lines += ["", "Checks:"]
        for c in summary.checks:
            lines.append(
                f"  {c.name}: {c.uptime if c.uptime is not None else '—'}% up, "
                f"{c.avg_latency_ms or '—'} ms avg, {c.incidents} incidents"
            )
    return "\n".join(lines) + "\n"


def render_html(summary: Summary, account: str, dashboard_url: str) -> str:
    e = html.escape

    def pct(v: float | None) -> str:
        return "—" if v is None else f"{v:.2f}%"

    def colour(v: float | None) -> str:
        if v is None:
            return "#64748b"
        return "#16a34a" if v >= 99.9 else "#d97706" if v >= 99 else "#dc2626"

    host_rows = "".join(
        f'<tr><td style="padding:6px 8px">{e(h.hostname)}</td>'
        f'<td style="padding:6px 8px;color:{colour(h.availability)};font-weight:600">{pct(h.availability)}</td>'
        f'<td style="padding:6px 8px">{h.incidents}</td>'
        f'<td style="padding:6px 8px">{"—" if h.cpu_avg is None else f"{h.cpu_avg:.0f}%"}</td>'
        f'<td style="padding:6px 8px">{"—" if h.disk_full_in_days is None else f"{h.disk_full_in_days:.0f} days"}</td></tr>'
        for h in summary.hosts
    )
    check_rows = "".join(
        f'<tr><td style="padding:6px 8px">{e(c.name)}</td>'
        f'<td style="padding:6px 8px;color:{colour(c.uptime)};font-weight:600">{pct(c.uptime)}</td>'
        f'<td style="padding:6px 8px">{"—" if c.avg_latency_ms is None else f"{c.avg_latency_ms:.0f} ms"}</td>'
        f'<td style="padding:6px 8px">{c.incidents}</td></tr>'
        for c in summary.checks
    )
    th = 'style="text-align:left;padding:6px 8px;color:#64748b;font-weight:600;border-bottom:1px solid #e2e8f0"'
    checks_table = (
        f'<h2 style="font-size:16px;margin:24px 0 8px">Checks</h2><table width="100%" cellspacing="0" style="font-size:14px">'
        f"<tr><th {th}>Check</th><th {th}>Uptime</th><th {th}>Response</th><th {th}>Incidents</th></tr>{check_rows}</table>"
        if summary.checks
        else ""
    )
    tiles = [
        ("Availability", pct(summary.availability)),
        ("Incidents", str(summary.incidents_total)),
        ("Time to acknowledge", human_duration(summary.mtta_seconds)),
        ("Time to resolve", human_duration(summary.mttr_seconds)),
    ]
    tile_html = "".join(
        f'<td style="padding:12px;border:1px solid #e2e8f0;border-radius:8px;width:25%">'
        f'<div style="font-size:12px;color:#64748b">{label}</div><div style="font-size:20px;font-weight:700">{value}</div></td>'
        for label, value in tiles
    )
    link = (
        f'<p style="margin-top:24px"><a href="{e(dashboard_url)}" style="background:#0f172a;color:#fff;padding:10px 18px;'
        f'border-radius:8px;text-decoration:none;font-weight:600">Open the dashboard</a></p>'
        if dashboard_url
        else ""
    )
    return f"""<!doctype html><html><body style="margin:0;padding:24px;background:#f1f5f9;font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#0f172a">
<div style="max-width:640px;margin:0 auto;background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:24px">
<h1 style="margin:0;font-size:22px">Monthly monitoring report</h1>
<p style="margin:4px 0 20px;color:#64748b">{e(account)} · {summary.start:%d %b %Y} – {summary.end:%d %b %Y}</p>
<table width="100%" cellspacing="6"><tr>{tile_html}</tr></table>
<h2 style="font-size:16px;margin:24px 0 8px">Servers</h2>
<table width="100%" cellspacing="0" style="font-size:14px"><tr><th {th}>Server</th><th {th}>Available</th><th {th}>Incidents</th><th {th}>CPU avg</th><th {th}>Disk full in</th></tr>{host_rows}</table>
{checks_table}{link}
<p style="margin-top:24px;font-size:12px;color:#94a3b8">You get this report because monitoring is set up for your account. Turn it off under Monitoring → Servers → Reports.</p>
</div></body></html>"""
