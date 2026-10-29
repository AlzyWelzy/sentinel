"""Server reports as PDF: for one or more hosts over any period (an hour to
their whole life), a cover with the fleet summary, then per server its
overview, statistics, charts and incidents."""

import io
import math
import re
import statistics
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from reportlab.graphics.charts.lineplots import LinePlot
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Host, Incident
from app.services import metrics
from app.services.reports import build_summary

# Points per chart: enough for detail, few enough to keep the file small.
CHART_POINTS = 600

BRAND = colors.HexColor("#0ea5e9")
INK = colors.HexColor("#0f172a")
MUTED = colors.HexColor("#64748b")
RULE = colors.HexColor("#e2e8f0")
PANEL = colors.HexColor("#f8fafc")
GOOD = colors.HexColor("#059669")
WARN = colors.HexColor("#d97706")
BAD = colors.HexColor("#dc2626")
# Series colours, in a fixed order (never cycled by rank).
SERIES = [
    colors.HexColor(c)
    for c in ("#2563eb", "#ea580c", "#16a34a", "#9333ea", "#db2777", "#0891b2", "#ca8a04")
]

# (catalog metric, chart title)
CHARTS = [
    ("cpu", "CPU usage"),
    ("memory", "Memory used"),
    ("swap", "Swap used"),
    ("disk", "Disk used"),
    ("load", "Load average"),
    ("network", "Network"),
    ("disk_io", "Disk throughput"),
    ("processes", "Processes"),
]


@dataclass
class HostData:
    host: Host
    availability: float | None
    incidents: list[Incident]
    series: dict[str, list[dict]] = field(default_factory=dict)


def step_for(seconds: int) -> int:
    return max(15, -(-seconds // CHART_POINTS // 15) * 15)


def fmt_value(v: float | None, unit: str) -> str:
    if v is None:
        return "—"
    if unit == "percent":
        return f"{v:.1f}%"
    if unit in ("bytes_per_second", "bytes"):
        suffix = "/s" if unit == "bytes_per_second" else ""
        for u in ("B", "KB", "MB", "GB", "TB"):
            if abs(v) < 1024 or u == "TB":
                return f"{v:.1f} {u}{suffix}"
            v /= 1024
    if unit == "load":
        return f"{v:.2f}"
    return f"{v:,.0f}"


def fmt_duration(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60}s"
    if s < 86400:
        return f"{s // 3600}h {s % 3600 // 60}m"
    return f"{s // 86400}d {s % 86400 // 3600}h"


def nice_top(v: float) -> float:
    """A round axis maximum just above v (1, 2, 2.5 or 5 times a power of ten)."""
    if v <= 0:
        return 1
    mag = 10 ** math.floor(math.log10(v))
    for m in (1, 2, 2.5, 5, 10):
        if v <= m * mag:
            return m * mag
    return 10 * mag


def fmt_period(seconds: float) -> str:
    days = seconds / 86400
    if days >= 1 and abs(days - round(days)) < 0.05:
        n = round(days)
        return f"{n} day" + ("s" if n != 1 else "")
    return fmt_duration(seconds)


def natural(name: str) -> list:
    """Sort key putting "5m" before "15m" and "core 2" before "core 10"."""
    return [int(p) if p.isdigit() else p for p in re.split(r"(\d+)", name)]


def segments(points: list[list[float]]) -> list[list[list[float]]]:
    """Split a series where samples stop for over three typical steps."""
    if len(points) < 3:
        return [points]
    gaps = sorted(b[0] - a[0] for a, b in zip(points, points[1:], strict=False))
    limit = gaps[len(gaps) // 2] * 3
    runs, run = [], [points[0]]
    for a, b in zip(points, points[1:], strict=False):
        if b[0] - a[0] > limit:
            runs.append(run)
            run = []
        run.append(b)
    runs.append(run)
    # A lone sample can't be drawn as a line; keep it as a two-point dot.
    return [r if len(r) > 1 else [r[0], [r[0][0] + 1, r[0][1]]] for r in runs]


def series_name(labels: dict[str, str], fallback: str) -> str:
    return " ".join(labels.values()) or fallback


async def collect(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    hosts: list[Host],
    start: datetime,
    end: datetime,
) -> list[HostData]:
    summary = await build_summary(db, tenant_id, start, end)
    availability = {h.host_id: h.availability for h in summary.hosts}
    a, b = int(start.timestamp()), int(end.timestamp())
    step = step_for(b - a)
    out = []
    for host in hosts:
        incidents = list(
            await db.scalars(
                select(Incident)
                .where(
                    Incident.tenant_id == tenant_id,
                    Incident.host_id == host.id,
                    Incident.opened_at >= start,
                    Incident.opened_at < end,
                )
                .order_by(Incident.opened_at.desc())
            )
        )
        data = HostData(host, availability.get(str(host.id)), incidents)
        for metric, _ in CHARTS:
            try:
                data.series[metric] = await metrics.query_range(
                    tenant_id, host.id, metric, a, b, step
                )
            except metrics.MetricsUnavailable:
                data.series[metric] = []
        out.append(data)
    return out


# ── Rendering ────────────────────────────────────────────────────────────────

_styles = getSampleStyleSheet()
H1 = ParagraphStyle("h1", _styles["Title"], fontSize=22, leading=26, textColor=INK, alignment=0)
H2 = ParagraphStyle("h2", _styles["Heading2"], fontSize=15, leading=19, textColor=INK)
H3 = ParagraphStyle(
    "h3", _styles["Heading3"], fontSize=10.5, leading=14, textColor=INK, spaceBefore=8
)
BODY = ParagraphStyle("body", _styles["BodyText"], fontSize=9, leading=12, textColor=INK)
SMALL = ParagraphStyle("small", BODY, fontSize=8, leading=10, textColor=MUTED)
RIGHT = ParagraphStyle("right", SMALL, alignment=TA_RIGHT)


def _table(rows: list[list], widths: list[float], header: bool = True, left: int = 1) -> Table:
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("FONT", (0, 0), (-1, -1), "Helvetica", 8.5),
        ("TEXTCOLOR", (0, 0), (-1, -1), INK),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
        ("ALIGN", (left, 0), (-1, -1), "RIGHT"),
    ]
    if header:
        style += [
            ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8),
            ("TEXTCOLOR", (0, 0), (-1, 0), MUTED),
            ("LINEBELOW", (0, 0), (-1, 0), 0.8, MUTED),
        ]
    t.setStyle(TableStyle(style))
    return t


def _availability_color(v: float | None):
    if v is None:
        return MUTED
    return GOOD if v >= 99.9 else WARN if v >= 99 else BAD


def _tiles(items: list[tuple[str, str, Any]], width: float) -> Table:
    """A row of headline numbers."""
    cells = [
        [
            Paragraph(f'<font size="7.5" color="#64748b">{label.upper()}</font>', BODY),
            Paragraph(f'<font size="15" color="#{color.hexval()[2:]}"><b>{value}</b></font>', BODY),
        ]
        for label, value, color in items
    ]
    t = Table([cells], colWidths=[width / len(items)] * len(items))
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), PANEL),
                ("BOX", (0, 0), (-1, -1), 0.5, RULE),
                ("LINEAFTER", (0, 0), (-2, -1), 0.5, RULE),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return t


def _chart(title: str, unit: str, series: list[dict], width: float, tz: ZoneInfo) -> Drawing:
    height = 58 * mm
    d = Drawing(width, height)
    d.add(String(0, height - 10, title, fontName="Helvetica-Bold", fontSize=9, fillColor=INK))
    shown = sorted(
        (s for s in series if s["points"]), key=lambda s: natural(series_name(s["labels"], ""))
    )[: len(SERIES)]
    if not shown:
        d.add(String(0, height / 2, "No data in this period", fontSize=8, fillColor=MUTED))
        return d
    # reportlab sets these attributes dynamically; its types don't know them.
    plot: Any = LinePlot()
    plot.x, plot.y = 38, 26
    plot.width, plot.height = width - 46, height - 52
    # One plotted line per unbroken stretch, so outages show as gaps (not a
    # straight line drawn across them), each in its series' colour.
    plot.data, line_colors = [], []
    for i, s in enumerate(shown):
        for run in segments(s["points"]):
            plot.data.append([(p[0], p[1]) for p in run])
            line_colors.append(SERIES[i])
    for i, c in enumerate(line_colors):
        plot.lines[i].strokeColor = c
        plot.lines[i].strokeWidth = 1.1
    xs = [p[0] for s in plot.data for p in s]
    ys = [p[1] for s in plot.data for p in s]
    lo, hi = min(xs), max(xs)
    plot.xValueAxis.valueMin, plot.xValueAxis.valueMax = lo, max(hi, lo + 1)
    span = hi - lo
    fmt = "%H:%M" if span <= 2 * 86400 else "%d %b" if span <= 400 * 86400 else "%b %Y"
    plot.xValueAxis.valueSteps = [lo + (hi - lo) * i / 5 for i in range(6)]
    plot.xValueAxis.labelTextFormat = lambda ts: datetime.fromtimestamp(ts, tz).strftime(fmt)
    plot.xValueAxis.labels.fontSize = 6.5
    plot.xValueAxis.labels.fillColor = MUTED
    plot.xValueAxis.strokeColor = RULE
    top = 100 if unit == "percent" else nice_top(max(ys))
    plot.yValueAxis.valueMin, plot.yValueAxis.valueMax = 0, top
    plot.yValueAxis.valueSteps = [top * i / 4 for i in range(5)]
    plot.yValueAxis.labelTextFormat = lambda v: fmt_value(v, unit).replace(".0%", "%")
    plot.yValueAxis.labels.fontSize = 6.5
    plot.yValueAxis.labels.fillColor = MUTED
    plot.yValueAxis.strokeColor = RULE
    plot.yValueAxis.visibleGrid = True
    plot.yValueAxis.gridStrokeColor = RULE
    plot.yValueAxis.gridStrokeWidth = 0.3
    d.add(plot)
    if len(shown) > 1:
        x = 38
        for i, s in enumerate(shown):
            name = series_name(s["labels"], title)[:18]
            d.add(String(x, 6, "●", fontSize=7, fillColor=SERIES[i]))
            d.add(String(x + 8, 6, name, fontSize=6.5, fillColor=MUTED))
            x += 14 + len(name) * 3.6
    return d


def _stats_rows(data: HostData) -> list[list[str]]:
    rows = [["Metric", "Average", "95th pct", "Minimum", "Peak"]]
    for metric, title in CHARTS:
        unit = metrics.CATALOG[metric].unit
        for s in data.series.get(metric, []):
            vals = [p[1] for p in s["points"]]
            if not vals:
                continue
            p95 = sorted(vals)[max(0, int(len(vals) * 0.95) - 1)]
            name = title if not s["labels"] else f"{title} · {series_name(s['labels'], '')}"
            rows.append(
                [
                    name[:48],
                    fmt_value(statistics.fmean(vals), unit),
                    fmt_value(p95, unit),
                    fmt_value(min(vals), unit),
                    fmt_value(max(vals), unit),
                ]
            )
    return rows


def render(
    datas: list[HostData],
    start: datetime,
    end: datetime,
    *,
    account: str,
    tz_name: str = "Asia/Kolkata",
) -> bytes:
    tz = ZoneInfo(tz_name)
    buf = io.BytesIO()
    width = A4[0] - 30 * mm
    when = (
        f"{start.astimezone(tz):%d %b %Y, %H:%M} – {end.astimezone(tz):%d %b %Y, %H:%M} ({tz_name})"
    )
    made = datetime.now(UTC).astimezone(tz)

    def page(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(BRAND)
        canvas.rect(0, A4[1] - 4, A4[0], 4, fill=1, stroke=0)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(15 * mm, 10 * mm, f"Server report · {account} · {when}")
        canvas.drawRightString(A4[0] - 15 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=16 * mm,
        bottomMargin=18 * mm,
        title="Server report",
        author="Pulsegrid",
    )
    story: list = [
        Paragraph("Server report", H1),
        Paragraph(f"{account} · {when}", SMALL),
        Paragraph(f"Generated {made:%d %b %Y, %H:%M}", SMALL),
        Spacer(1, 8 * mm),
    ]
    avail = [d.availability for d in datas if d.availability is not None]
    story.append(
        _tiles(
            [
                ("Servers", str(len(datas)), INK),
                (
                    "Availability",
                    f"{statistics.fmean(avail):.3f}%" if avail else "—",
                    _availability_color(statistics.fmean(avail) if avail else None),
                ),
                ("Incidents", str(sum(len(d.incidents) for d in datas)), INK),
                ("Period", fmt_period((end - start).total_seconds()), INK),
            ],
            width,
        )
    )
    story += [Spacer(1, 6 * mm), Paragraph("Servers in this report", H3)]
    rows = [["Server", "Availability", "Incidents", "CPU avg", "Memory avg", "Disk peak"]]
    for d in datas:

        def avg(metric: str, d: HostData = d) -> str:
            vals = [p[1] for s in d.series.get(metric, []) for p in s["points"]]
            return fmt_value(statistics.fmean(vals), "percent") if vals else "—"

        disk = [p[1] for s in d.series.get("disk", []) for p in s["points"]]
        rows.append(
            [
                d.host.hostname[:40],
                f"{d.availability:.3f}%" if d.availability is not None else "—",
                str(len(d.incidents)),
                avg("cpu"),
                avg("memory"),
                fmt_value(max(disk), "percent") if disk else "—",
            ]
        )
    story.append(_table(rows, [width * 0.32] + [width * 0.136] * 5))

    for d in datas:
        h = d.host
        story += [PageBreak(), Paragraph(h.hostname, H2)]
        facts = " · ".join(
            x
            for x in (
                " ".join(filter(None, [h.platform, h.platform_version, h.arch])),
                f"agent {h.agent_version}" if h.agent_version else "",
                f"{h.cpu_cores} cores" if h.cpu_cores else "",
                fmt_value(h.memory_bytes, "bytes") + " RAM" if h.memory_bytes else "",
                f"added {h.created_at.astimezone(tz):%d %b %Y}",
                ("tags " + ", ".join(h.tags)) if h.tags else "",
            )
            if x
        )
        story += [Paragraph(facts, SMALL), Spacer(1, 4 * mm)]
        resolved = [
            (i.resolved_at - i.opened_at).total_seconds() for i in d.incidents if i.resolved_at
        ]
        story.append(
            _tiles(
                [
                    (
                        "Availability",
                        f"{d.availability:.3f}%" if d.availability is not None else "—",
                        _availability_color(d.availability),
                    ),
                    ("Incidents", str(len(d.incidents)), INK),
                    (
                        "Critical",
                        str(sum(i.severity == "critical" for i in d.incidents)),
                        BAD if any(i.severity == "critical" for i in d.incidents) else INK,
                    ),
                    (
                        "Mean time to resolve",
                        fmt_duration(statistics.fmean(resolved)) if resolved else "—",
                        INK,
                    ),
                ],
                width,
            )
        )
        story += [Spacer(1, 3 * mm), Paragraph("Statistics", H3)]
        stats = _stats_rows(d)
        if len(stats) > 1:
            story.append(_table(stats, [width * 0.4] + [width * 0.15] * 4))
        else:
            story.append(Paragraph("No metrics were recorded in this period.", SMALL))
        story.append(Paragraph("Charts", H3))
        half = (width - 6 * mm) / 2
        charts = [
            _chart(title, metrics.CATALOG[m].unit, d.series.get(m, []), half, tz)
            for m, title in CHARTS
        ]
        for i in range(0, len(charts), 2):
            pair = charts[i : i + 2] + [""] * (2 - len(charts[i : i + 2]))
            t = Table([pair], colWidths=[half + 3 * mm, half + 3 * mm])
            t.setStyle(TableStyle([("LEFTPADDING", (0, 0), (-1, -1), 0)]))
            story.append(KeepTogether(t))
        story.append(Paragraph("Incidents", H3))
        if d.incidents:
            rows = [["Opened", "Alert", "Severity", "Duration", "Resolved by"]]
            for i in d.incidents[:200]:
                dur = ((i.resolved_at or datetime.now(UTC)) - i.opened_at).total_seconds()
                rows.append(
                    [
                        f"{i.opened_at.astimezone(tz):%d %b %Y %H:%M}",
                        Paragraph(i.rule_name or i.summary, BODY),
                        i.severity,
                        fmt_duration(dur) + ("" if i.resolved_at else " (open)"),
                        (i.resolved_by or ("—" if i.resolved_at else "open"))[:24],
                    ]
                )
            story.append(
                _table(
                    rows,
                    [width * 0.2, width * 0.36, width * 0.12, width * 0.14, width * 0.18],
                    left=2,
                )
            )
            if len(d.incidents) > 200:
                story.append(
                    Paragraph(f"Showing the latest 200 of {len(d.incidents)} incidents.", SMALL)
                )
        else:
            story.append(Paragraph("No incidents in this period.", SMALL))

    doc.build(story, onFirstPage=page, onLaterPages=page)
    return buf.getvalue()


def lifetime_start(hosts: list[Host]) -> datetime:
    return min(h.created_at for h in hosts) if hosts else datetime.now(UTC) - timedelta(days=30)
