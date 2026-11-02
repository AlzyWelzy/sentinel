"""Server reports as PDF: for one or more hosts over any period (an hour to
their whole life).

A fleet report opens with the headline numbers, what needs attention across
the servers and rankings (least available, busiest, fullest disks, most
incidents). Each server then gets its own section: findings in plain words,
availability by day with every downtime and reboot, disk capacity with a
days-until-full forecast, statistics, charts for CPU, memory, disks, network
and the system, its checks, its busiest processes and its incidents."""

import asyncio
import io
import math
import re
import statistics
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from reportlab.graphics.charts.barcharts import VerticalBarChart
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

from app.models import Check, Host, Incident
from app.services import metrics
from app.services.reports import build_summary

# Points per chart: enough for detail, few enough to keep the file small.
CHART_POINTS = 600
# Metric queries in flight at once while collecting a fleet.
PARALLEL = 8

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

# Chart sections: (heading, [(catalog metric, chart title)]).
SECTIONS = [
    ("CPU", [("cpu", "CPU usage"), ("cpu_modes", "CPU time by mode"), ("load", "Load average")]),
    (
        "Memory",
        [
            ("memory", "Memory used"),
            ("memory_breakdown", "Memory breakdown"),
            ("swap", "Swap used"),
            ("swap_io", "Swap activity"),
        ],
    ),
    (
        "Disks",
        [
            ("disk", "Disk used"),
            ("inodes", "Inodes used"),
            ("disk_io", "Disk throughput"),
            ("disk_iops", "Disk operations"),
            ("disk_latency", "Disk latency"),
            ("disk_busy", "Disk busy time"),
        ],
    ),
    (
        "Network",
        [
            ("network", "Network traffic"),
            ("network_packets", "Network packets"),
            ("network_errors", "Network errors and drops"),
            ("tcp_connections", "TCP connections"),
        ],
    ),
    (
        "System",
        [
            ("processes", "Processes"),
            ("threads", "Threads"),
            ("context_switches", "Context switches"),
            ("pressure", "Resource pressure (PSI)"),
            ("open_files", "Open files"),
        ],
    ),
]
CHARTS = [c for _, items in SECTIONS for c in items]
# The statistics table: the metrics people compare across periods.
STATS = [
    ("cpu", "CPU usage"),
    ("memory", "Memory used"),
    ("swap", "Swap used"),
    ("disk", "Disk used"),
    ("load", "Load average"),
    ("network", "Network"),
    ("disk_io", "Disk throughput"),
    ("disk_latency", "Disk latency"),
    ("processes", "Processes"),
]


@dataclass
class DiskForecast:
    mount: str
    now: float
    avg: float
    peak: float
    per_day: float | None  # percentage points per day, from the period's trend
    full_in_days: float | None


@dataclass
class HostData:
    host: Host
    availability: float | None
    incidents: list[Incident]
    series: dict[str, list[dict]] = field(default_factory=dict)
    restarts: int | None = None
    downtimes: list[tuple[int, int]] = field(default_factory=list)
    daily: list[tuple[int, float]] = field(default_factory=list)
    # Whether the charts' samples caught the server at all: a server that
    # reported for minutes of a long period can fall between them.
    sampled: bool = True
    disks: list[DiskForecast] = field(default_factory=list)
    checks: list[dict] = field(default_factory=list)
    processes: list[dict] = field(default_factory=list)
    findings: list[tuple[str, str]] = field(default_factory=list)

    def values(self, metric: str, label: str | None = None) -> list[float]:
        return [
            p[1]
            for s in self.series.get(metric, [])
            if label is None or label in s["labels"].values()
            for p in s["points"]
        ]


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
    if unit == "ms":
        return f"{v:.1f} ms"
    if unit == "ops_per_second":
        return f"{v:,.1f}/s" if v < 100 else f"{v:,.0f}/s"
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


def _gap_limit(points: list[list[float]]) -> float:
    gaps = sorted(b[0] - a[0] for a, b in zip(points, points[1:], strict=False))
    return gaps[len(gaps) // 2] * 3


def segments(points: list[list[float]]) -> list[list[list[float]]]:
    """Split a series where samples stop for over three typical steps."""
    if len(points) < 3:
        return [points]
    limit = _gap_limit(points)
    runs, run = [], [points[0]]
    for a, b in zip(points, points[1:], strict=False):
        if b[0] - a[0] > limit:
            runs.append(run)
            run = []
        run.append(b)
    runs.append(run)
    # A lone sample can't be drawn as a line; keep it as a two-point dot.
    return [r if len(r) > 1 else [r[0], [r[0][0] + 1, r[0][1]]] for r in runs]


def downtimes(points: list[list[float]], end: int) -> list[tuple[int, int]]:
    """Stretches with no data: between samples, and from the last sample to
    the end of the period (a server that's still silent)."""
    if len(points) < 3:
        return []
    limit = _gap_limit(points)
    out = [
        (int(a[0]), int(b[0]))
        for a, b in zip(points, points[1:], strict=False)
        if b[0] - a[0] > limit
    ]
    if end - points[-1][0] > max(limit, 300):
        out.append((int(points[-1][0]), end))
    return out


def daily_availability(
    start: int, end: int, first: int | None, gaps: list[tuple[int, int]], tz: ZoneInfo
) -> list[tuple[int, float]]:
    """Share of each local day the server reported, from the gaps in its data.
    Days before the server was added are left out."""
    if first is None:
        return []
    day = datetime.fromtimestamp(max(start, first), tz).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    out = []
    while day.timestamp() < end:
        a = max(int(day.timestamp()), start, first)
        b = min(int((day + timedelta(days=1)).timestamp()), end)
        if b > a:
            down = sum(max(0, min(g[1], b) - max(g[0], a)) for g in gaps)
            out.append((int(day.timestamp()), max(0.0, 100 * (1 - down / (b - a)))))
        day += timedelta(days=1)
    return out


def trend_per_day(points: list[list[float]]) -> float | None:
    """Least-squares slope of a series, in units per day."""
    if len(points) < 10 or points[-1][0] - points[0][0] < 3600:
        return None
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    mx, my = statistics.fmean(xs), statistics.fmean(ys)
    den = sum((x - mx) ** 2 for x in xs)
    if den == 0:
        return None
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys, strict=False)) / den * 86400


def disk_forecasts(series: list[dict]) -> list[DiskForecast]:
    out = []
    for s in sorted(series, key=lambda s: natural(series_name(s["labels"], ""))):
        pts = s["points"]
        if not pts:
            continue
        vals = [p[1] for p in pts]
        per_day = trend_per_day(pts)
        now = vals[-1]
        full = (100 - now) / per_day if per_day and per_day > 0.01 and now < 100 else None
        out.append(
            DiskForecast(
                mount=series_name(s["labels"], "/"),
                now=now,
                avg=statistics.fmean(vals),
                peak=max(vals),
                per_day=per_day,
                full_in_days=full,
            )
        )
    return out


def p95(vals: list[float]) -> float:
    return sorted(vals)[max(0, int(len(vals) * 0.95) - 1)]


def series_name(labels: dict[str, str], fallback: str) -> str:
    return " ".join(labels.values()) or fallback


def findings(d: HostData) -> list[tuple[str, str]]:
    """What a reader should know, worst first: ("bad"|"warn"|"good", text)."""
    out: list[tuple[str, str]] = []
    h = d.host
    if d.availability is not None and d.availability < 99.9:
        down = sum(b - a for a, b in d.downtimes)
        longest = max((b - a for a, b in d.downtimes), default=0)
        level = "bad" if d.availability < 99 else "warn"
        if not d.sampled:
            out.append(
                (
                    level,
                    f"Availability {d.availability:.2f}%: it reported only briefly in this "
                    "period, too briefly for the charts below.",
                )
            )
        else:
            out.append(
                (
                    level,
                    f"Availability {d.availability:.2f}%: {len(d.downtimes)} gap"
                    f"{'s' if len(d.downtimes) != 1 else ''} without data, "
                    f"{fmt_duration(down)} in all"
                    + (f", the longest {fmt_duration(longest)}." if longest else "."),
                )
            )
    if d.restarts:
        out.append(("warn", f"Rebooted {d.restarts} time{'s' if d.restarts != 1 else ''}."))
    for disk in d.disks:
        if disk.full_in_days is not None and disk.full_in_days < 30:
            out.append(
                (
                    "bad" if disk.full_in_days < 7 else "warn",
                    f"Disk {disk.mount} is {disk.now:.0f}% full and growing "
                    f"{disk.per_day:.2f} points a day: full in about "
                    f"{disk.full_in_days:.0f} day{'s' if round(disk.full_in_days) != 1 else ''}.",
                )
            )
        elif disk.peak >= 90:
            out.append(("bad", f"Disk {disk.mount} reached {disk.peak:.0f}% full."))
        elif disk.peak >= 80:
            out.append(("warn", f"Disk {disk.mount} reached {disk.peak:.0f}% full."))
    cpu = d.values("cpu")
    if cpu:
        if p95(cpu) >= 85:
            out.append(
                ("bad", f"CPU was busy: 95th percentile {p95(cpu):.0f}%, peak {max(cpu):.0f}%.")
            )
        elif p95(cpu) >= 70:
            out.append(("warn", f"CPU often high: 95th percentile {p95(cpu):.0f}%."))
        elif statistics.fmean(cpu) < 5 and len(cpu) > 20:
            out.append(
                ("good", f"CPU mostly idle (average {statistics.fmean(cpu):.1f}%): room to spare.")
            )
    load = d.values("load", "1m")
    if load and h.cpu_cores and statistics.fmean(load) > h.cpu_cores:
        out.append(
            (
                "warn",
                f"Load averaged {statistics.fmean(load):.1f} on {h.cpu_cores} cores: "
                "work was queueing for the CPU.",
            )
        )
    mem = d.values("memory")
    if mem and max(mem) >= 95:
        out.append(("bad", f"Memory reached {max(mem):.0f}% used."))
    elif mem and max(mem) >= 85:
        out.append(("warn", f"Memory reached {max(mem):.0f}% used."))
    swap = d.values("swap")
    if swap and statistics.fmean(swap) >= 50:
        out.append(("warn", f"Swap averaged {statistics.fmean(swap):.0f}% used: memory is short."))
    lat = d.values("disk_latency")
    if lat and p95(lat) >= 50:
        out.append(("warn", f"Slow disks: 95th percentile latency {p95(lat):.0f} ms."))
    errs = d.values("network_errors")
    if errs and max(errs) > 1:
        out.append(("warn", f"Network errors or drops, up to {max(errs):.1f} a second."))
    crit = sum(i.severity == "critical" for i in d.incidents)
    if crit:
        out.append(("bad", f"{crit} critical incident{'s' if crit != 1 else ''}."))
    open_now = [i for i in d.incidents if i.status == "open"]
    if open_now:
        out.append(
            ("bad", f"{len(open_now)} incident{'s' if len(open_now) != 1 else ''} still open.")
        )
    if not out:
        out.append(("good", "Nothing needs attention in this period."))
    order = {"bad": 0, "warn": 1, "good": 2}
    return sorted(out, key=lambda f: order[f[0]])


async def collect(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    hosts: list[Host],
    start: datetime,
    end: datetime,
    tz_name: str = "UTC",
) -> list[HostData]:
    from app.routes.v1 import processes_of

    tz = ZoneInfo(tz_name)
    summary = await build_summary(db, tenant_id, start, end)
    availability = {h.host_id: h.availability for h in summary.hosts}
    by_check = {c.check_id: c for c in summary.checks}
    a, b = int(start.timestamp()), int(end.timestamp())
    step = step_for(b - a)
    gate = asyncio.Semaphore(PARALLEL)

    async def series(host: Host, metric: str) -> list[dict]:
        async with gate:
            try:
                return await metrics.query_range(tenant_id, host.id, metric, a, b, step)
            except (metrics.MetricsUnavailable, KeyError):
                return []

    async def restarts(host: Host) -> int | None:
        async with gate:
            try:
                rows = await metrics.query_instant(
                    tenant_id,
                    f'resets(sentinel_uptime_seconds{{host_id="{host.id}"}}'
                    f"[{max(b - a, 300)}s]) @ {b}",
                )
            except metrics.MetricsUnavailable:
                return None
        return int(sum(v for _, v in rows)) if rows else 0

    async def one(host: Host) -> HostData:
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
        d = HostData(host, availability.get(str(host.id)), incidents)
        got = await asyncio.gather(*(series(host, m) for m, _ in CHARTS))
        d.series = {m: s for (m, _), s in zip(CHARTS, got, strict=False)}
        d.restarts = await restarts(host)
        beat = max(d.series.get("cpu") or [{"points": []}], key=lambda s: len(s["points"]))
        pts = beat["points"]
        d.sampled = bool(pts)
        d.downtimes = downtimes(pts, b)
        d.daily = daily_availability(a, b, int(pts[0][0]) if pts else None, d.downtimes, tz)
        d.disks = disk_forecasts(d.series.get("disk", []))
        return d

    out = []
    for host in hosts:
        out.append(await one(host))
    checks = list(
        await db.scalars(
            select(Check)
            .where(Check.tenant_id == tenant_id, Check.host_id.in_([h.id for h in hosts]))
            .order_by(Check.name)
        )
    )
    for d in out:
        for c in checks:
            if c.host_id == d.host.id:
                r = by_check.get(str(c.id))
                d.checks.append(
                    {
                        "name": c.name,
                        "type": c.type,
                        "target": c.target,
                        "uptime": r.uptime if r else None,
                        "latency": r.avg_latency_ms if r else None,
                        "incidents": r.incidents if r else 0,
                    }
                )
        # Processes are a snapshot: only meaningful for a period ending now.
        if datetime.now(UTC) - end < timedelta(minutes=10):
            try:
                snap = await processes_of(tenant_id, d.host.id)
                d.processes = [p.model_dump() for p in snap.processes[:12]]
            except Exception:  # noqa: BLE001 - optional detail; the report stands without it
                d.processes = []
        d.findings = findings(d)
    return out


# ── Rendering ────────────────────────────────────────────────────────────────

_styles = getSampleStyleSheet()
H1 = ParagraphStyle("h1", _styles["Title"], fontSize=24, leading=28, textColor=INK, alignment=0)
H2 = ParagraphStyle("h2", _styles["Heading2"], fontSize=16, leading=20, textColor=INK)
H3 = ParagraphStyle(
    "h3", _styles["Heading3"], fontSize=11, leading=14, textColor=INK, spaceBefore=10, spaceAfter=4
)
BODY = ParagraphStyle("body", _styles["BodyText"], fontSize=9, leading=12, textColor=INK)
SMALL = ParagraphStyle("small", BODY, fontSize=8, leading=10, textColor=MUTED)
RIGHT = ParagraphStyle("right", SMALL, alignment=TA_RIGHT)
LEVEL = {"bad": BAD, "warn": WARN, "good": GOOD}
LEVEL_WORD = {"bad": "Action", "warn": "Watch", "good": "OK"}


def _hex(c: Any) -> str:
    return "#" + c.hexval()[2:]


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


def _pct_color(v: float | None, warn: float = 80, bad: float = 90):
    if v is None:
        return INK
    return BAD if v >= bad else WARN if v >= warn else INK


def _tiles(items: list[tuple[str, str, Any]], width: float, sub: list[str] | None = None) -> Table:
    """A row of headline numbers."""
    cells = []
    for i, (label, value, color) in enumerate(items):
        cell = [
            Paragraph(f'<font size="7" color="#64748b">{label.upper()}</font>', BODY),
            Paragraph(f'<font size="15" color="{_hex(color)}"><b>{value}</b></font>', BODY),
        ]
        if sub and sub[i]:
            cell.append(Paragraph(sub[i], SMALL))
        cells.append(cell)
    t = Table([cells], colWidths=[width / len(items)] * len(items))
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), PANEL),
                ("BOX", (0, 0), (-1, -1), 0.5, RULE),
                ("LINEAFTER", (0, 0), (-2, -1), 0.5, RULE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return t


def _findings_box(items: list[tuple[str, str]], width: float, limit: int = 12) -> Table:
    rows = [
        [
            Paragraph(
                f'<font color="{_hex(LEVEL[level])}"><b>{LEVEL_WORD[level]}</b></font>', BODY
            ),
            Paragraph(text, BODY),
        ]
        for level, text in items[:limit]
    ]
    t = Table(rows, colWidths=[18 * mm, width - 18 * mm])
    t.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.5, RULE),
                ("LINEBELOW", (0, 0), (-1, -2), 0.3, RULE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    return t


def _chart(title: str, unit: str, series: list[dict], width: float, tz: ZoneInfo) -> Drawing:
    height = 54 * mm
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
    plot.x, plot.y = 44, 24
    plot.width, plot.height = width - 52, height - 50
    # One plotted line per unbroken stretch, so outages show as gaps (not a
    # straight line drawn across them), each in its series' colour.
    plot.data, line_colors = [], []
    for i, s in enumerate(shown):
        for run in segments(s["points"]):
            plot.data.append([(p[0], p[1]) for p in run])
            line_colors.append(SERIES[i])
    for i, c in enumerate(line_colors):
        plot.lines[i].strokeColor = c
        plot.lines[i].strokeWidth = 1.0
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
    top = 100 if unit == "percent" and max(ys) > 25 else nice_top(max(ys) or 1)
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
        x = 44
        for i, s in enumerate(shown):
            name = series_name(s["labels"], title)[:18]
            if x + 14 + len(name) * 3.6 > width:
                break
            d.add(String(x, 4, "●", fontSize=7, fillColor=SERIES[i]))
            d.add(String(x + 8, 4, name, fontSize=6.5, fillColor=MUTED))
            x += 14 + len(name) * 3.6
    return d


def _daily_chart(daily: list[tuple[int, float]], width: float, tz: ZoneInfo) -> Drawing:
    height = 42 * mm
    d = Drawing(width, height)
    d.add(
        String(
            0,
            height - 10,
            "Availability by day",
            fontName="Helvetica-Bold",
            fontSize=9,
            fillColor=INK,
        )
    )
    bars: Any = VerticalBarChart()
    bars.x, bars.y = 36, 18
    bars.width, bars.height = width - 44, height - 40
    bars.data = [[v for _, v in daily]]
    lo = min(v for _, v in daily)
    floor = 0 if lo < 90 else 90 if lo < 99 else 99
    bars.valueAxis.valueMin, bars.valueAxis.valueMax = floor, 100
    bars.valueAxis.valueSteps = [floor + (100 - floor) * i / 4 for i in range(5)]
    bars.valueAxis.labelTextFormat = lambda v: f"{v:g}%"
    bars.valueAxis.labels.fontSize = 6.5
    bars.valueAxis.labels.fillColor = MUTED
    bars.valueAxis.strokeColor = RULE
    bars.valueAxis.visibleGrid = True
    bars.valueAxis.gridStrokeColor = RULE
    bars.valueAxis.gridStrokeWidth = 0.3
    every = max(1, len(daily) // 10)
    bars.categoryAxis.categoryNames = [
        datetime.fromtimestamp(t, tz).strftime("%d %b") if i % every == 0 else ""
        for i, (t, _) in enumerate(daily)
    ]
    bars.categoryAxis.labels.fontSize = 6
    bars.categoryAxis.labels.fillColor = MUTED
    bars.categoryAxis.strokeColor = RULE
    bars.barSpacing = 1
    bars.groupSpacing = 2
    bars.bars.strokeWidth = 0
    for i, (_, v) in enumerate(daily):
        bars.bars[(0, i)].fillColor = _availability_color(v)
    d.add(bars)
    return d


def _stats_rows(data: HostData) -> list[list[str]]:
    rows = [["Metric", "Average", "95th pct", "Minimum", "Peak"]]
    for metric, title in STATS:
        unit = metrics.CATALOG[metric].unit
        for s in sorted(
            data.series.get(metric, []), key=lambda s: natural(series_name(s["labels"], ""))
        ):
            vals = [p[1] for p in s["points"]]
            if not vals:
                continue
            name = title if not s["labels"] else f"{title} · {series_name(s['labels'], '')}"
            rows.append(
                [
                    name[:48],
                    fmt_value(statistics.fmean(vals), unit),
                    fmt_value(p95(vals), unit),
                    fmt_value(min(vals), unit),
                    fmt_value(max(vals), unit),
                ]
            )
    return rows


def _pair_rows(drawings: list, width: float) -> list:
    half = (width - 6 * mm) / 2
    out = []
    for i in range(0, len(drawings), 2):
        pair = drawings[i : i + 2] + [""] * (2 - len(drawings[i : i + 2]))
        t = Table([pair], colWidths=[half + 3 * mm, half + 3 * mm])
        t.setStyle(TableStyle([("LEFTPADDING", (0, 0), (-1, -1), 0)]))
        out.append(KeepTogether(t))
    return out


def _host_section(d: HostData, width: float, tz: ZoneInfo, start: datetime, end: datetime) -> list:
    h = d.host
    story: list = [Paragraph(h.hostname, H2)]
    facts = " · ".join(
        x
        for x in (
            " ".join(filter(None, [h.platform, h.platform_version, h.arch])),
            f"agent {h.agent_version}" if h.agent_version else "",
            f"{h.cpu_cores} cores" if h.cpu_cores else "",
            fmt_value(h.memory_bytes, "bytes") + " RAM" if h.memory_bytes else "",
            ", ".join(h.ip_addresses[:3]) if getattr(h, "ip_addresses", None) else "",
            f"added {h.created_at.astimezone(tz):%d %b %Y}",
            ("tags " + ", ".join(h.tags)) if h.tags else "",
            "monitoring paused" if getattr(h, "paused_at", None) else "",
        )
        if x
    )
    story += [Paragraph(facts, SMALL), Spacer(1, 4 * mm)]
    down = sum(b - a for a, b in d.downtimes)
    resolved = [(i.resolved_at - i.opened_at).total_seconds() for i in d.incidents if i.resolved_at]
    story.append(
        _tiles(
            [
                (
                    "Availability",
                    f"{d.availability:.3f}%" if d.availability is not None else "—",
                    _availability_color(d.availability),
                ),
                ("Downtime", fmt_duration(down) if d.downtimes else "none", BAD if down else INK),
                ("Incidents", str(len(d.incidents)), BAD if d.incidents else INK),
                (
                    "Reboots",
                    "—" if d.restarts is None else str(d.restarts),
                    WARN if d.restarts else INK,
                ),
            ],
            width,
            [
                "share of reports received",
                f"{len(d.downtimes)} gap{'s' if len(d.downtimes) != 1 else ''}",
                f"mean resolve {fmt_duration(statistics.fmean(resolved))}" if resolved else "",
                "",
            ],
        )
    )
    cpu, mem, load = d.values("cpu"), d.values("memory"), d.values("load", "1m")
    fullest = max(d.disks, key=lambda x: x.peak, default=None)
    story += [
        Spacer(1, 2 * mm),
        _tiles(
            [
                (
                    "CPU avg / peak",
                    f"{statistics.fmean(cpu):.0f}% / {max(cpu):.0f}%" if cpu else "—",
                    _pct_color(p95(cpu) if cpu else None, 70, 85),
                ),
                (
                    "Memory peak",
                    f"{max(mem):.0f}%" if mem else "—",
                    _pct_color(max(mem) if mem else None, 85, 95),
                ),
                (
                    "Fullest disk",
                    f"{fullest.peak:.0f}%" if fullest else "—",
                    _pct_color(fullest.peak if fullest else None),
                ),
                (
                    "Load / core",
                    f"{statistics.fmean(load) / h.cpu_cores:.2f}" if load and h.cpu_cores else "—",
                    WARN if load and h.cpu_cores and statistics.fmean(load) > h.cpu_cores else INK,
                ),
            ],
            width,
            ["", "", fullest.mount if fullest else "", "average, 1 min"],
        ),
        Paragraph("Summary", H3),
        _findings_box(d.findings, width),
    ]

    story.append(Paragraph("Availability", H3))
    if len(d.daily) > 1:
        story.append(_daily_chart(d.daily, width, tz))
    if d.downtimes:
        rows = [["From", "To", "Lasted"]]
        for a, b in sorted(d.downtimes, key=lambda g: g[0], reverse=True)[:25]:
            rows.append(
                [
                    f"{datetime.fromtimestamp(a, tz):%d %b %Y %H:%M}",
                    "still silent"
                    if b >= int(end.timestamp()) - 60
                    else f"{datetime.fromtimestamp(b, tz):%d %b %Y %H:%M}",
                    fmt_duration(b - a),
                ]
            )
        story.append(_table(rows, [width * 0.38, width * 0.38, width * 0.24], left=2))
        if len(d.downtimes) > 25:
            story.append(Paragraph(f"Latest 25 of {len(d.downtimes)} gaps.", SMALL))
    elif not d.sampled:
        story.append(
            Paragraph(
                "Too little data at this range's resolution to show gaps: the server reported "
                "only briefly in this period. Its availability above counts every report.",
                SMALL,
            )
        )
    else:
        story.append(Paragraph("Reported throughout the period: no gaps in its data.", SMALL))

    story.append(Paragraph("Disk capacity", H3))
    if d.disks:
        rows = [["Mount", "Now", "Average", "Peak", "Change / day", "Full in"]]
        for x in d.disks:
            rows.append(
                [
                    x.mount[:40],
                    f"{x.now:.1f}%",
                    f"{x.avg:.1f}%",
                    f"{x.peak:.1f}%",
                    "—" if x.per_day is None else f"{x.per_day:+.2f} pts",
                    "—"
                    if x.full_in_days is None
                    else (f"~{x.full_in_days:.0f} days" if x.full_in_days < 3650 else "years"),
                ]
            )
        story.append(_table(rows, [width * 0.3] + [width * 0.14] * 5))
        story.append(
            Paragraph(
                "Change per day is the trend over this period; “full in” assumes it continues.",
                SMALL,
            )
        )
    else:
        story.append(Paragraph("No disk data in this period.", SMALL))

    story.append(Paragraph("Statistics", H3))
    stats = _stats_rows(d)
    if len(stats) > 1:
        story.append(_table(stats, [width * 0.4] + [width * 0.15] * 4))
    else:
        story.append(Paragraph("No metrics were recorded in this period.", SMALL))

    half = (width - 6 * mm) / 2
    for heading, items in SECTIONS:
        drawn = [
            _chart(title, metrics.CATALOG[m].unit, d.series.get(m, []), half, tz)
            for m, title in items
            if d.series.get(m)
        ]
        if not drawn:
            continue
        story.append(Paragraph(heading, H3))
        story += _pair_rows(drawn, width)

    if d.checks:
        story.append(Paragraph("Checks", H3))
        rows = [["Check", "Type", "Uptime", "Avg response", "Incidents"]]
        for c in d.checks:
            rows.append(
                [
                    Paragraph(
                        f"{c['name']}<br/><font color='#64748b' size='7'>{c['target'][:60]}</font>",
                        BODY,
                    ),
                    c["type"],
                    "—" if c["uptime"] is None else f"{c['uptime']:.2f}%",
                    "—" if c["latency"] is None else f"{c['latency']:.0f} ms",
                    str(c["incidents"]),
                ]
            )
        story.append(
            _table(
                rows, [width * 0.44, width * 0.14, width * 0.14, width * 0.16, width * 0.12], left=2
            )
        )

    if d.processes:
        story.append(Paragraph("Busiest processes now", H3))
        rows = [["Process", "CPU", "Memory", "Count"]]
        for p in d.processes:
            rows.append(
                [
                    str(p.get("name"))[:50],
                    "—" if p.get("cpu_percent") is None else f"{p['cpu_percent']:.1f}%",
                    fmt_value(p.get("memory_bytes"), "bytes"),
                    "—" if p.get("count") is None else str(p["count"]),
                ]
            )
        story.append(_table(rows, [width * 0.52, width * 0.16, width * 0.18, width * 0.14]))

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
                rows, [width * 0.2, width * 0.36, width * 0.12, width * 0.14, width * 0.18], left=2
            )
        )
        if len(d.incidents) > 200:
            story.append(
                Paragraph(f"Showing the latest 200 of {len(d.incidents)} incidents.", SMALL)
            )
    else:
        story.append(Paragraph("No incidents in this period.", SMALL))
    return story


def _ranking(title: str, rows: list[list[str]], width: float) -> list:
    if len(rows) <= 1:
        return []
    return [
        Paragraph(title, H3),
        _table(rows, [width * 0.55, width * 0.225, width * 0.225]),
    ]


def render(
    datas: list[HostData],
    start: datetime,
    end: datetime,
    *,
    account: str,
    tz_name: str = "UTC",
) -> bytes:
    tz = ZoneInfo(tz_name)
    buf = io.BytesIO()
    width = A4[0] - 30 * mm
    when = (
        f"{start.astimezone(tz):%d %b %Y, %H:%M} – {end.astimezone(tz):%d %b %Y, %H:%M} ({tz_name})"
    )
    made = datetime.now(UTC).astimezone(tz)
    title = datas[0].host.hostname if len(datas) == 1 else f"{len(datas)} servers"

    def page(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(BRAND)
        canvas.rect(0, A4[1] - 4, A4[0], 4, fill=1, stroke=0)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(15 * mm, 10 * mm, f"Server report · {title} · {account} · {when}"[:150])
        canvas.drawRightString(A4[0] - 15 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=16 * mm,
        bottomMargin=18 * mm,
        title=f"Server report: {title}",
        author="Sentinel",
    )
    story: list = [
        Paragraph("Server report", H1),
        Paragraph(f"<b>{title}</b> · {account}", BODY),
        Paragraph(f"{when} · generated {made:%d %b %Y, %H:%M}", SMALL),
        Spacer(1, 7 * mm),
    ]

    if len(datas) == 1:
        story += _host_section(datas[0], width, tz, start, end)
        doc.build(story, onFirstPage=page, onLaterPages=page)
        return buf.getvalue()

    avail = [d.availability for d in datas if d.availability is not None]
    incidents = sum(len(d.incidents) for d in datas)
    downtime = sum(b - a for d in datas for a, b in d.downtimes)
    story.append(
        _tiles(
            [
                ("Servers", str(len(datas)), INK),
                (
                    "Availability",
                    f"{statistics.fmean(avail):.3f}%" if avail else "—",
                    _availability_color(statistics.fmean(avail) if avail else None),
                ),
                ("Incidents", str(incidents), BAD if incidents else INK),
                (
                    "Downtime",
                    fmt_duration(downtime) if downtime else "none",
                    BAD if downtime else INK,
                ),
            ],
            width,
            [
                "",
                "average across servers",
                f"{sum(i.severity == 'critical' for d in datas for i in d.incidents)} critical",
                f"over {fmt_period((end - start).total_seconds())}",
            ],
        )
    )
    attention = [
        (lvl, f"<b>{d.host.hostname}</b>: {text}")
        for d in datas
        for lvl, text in d.findings
        if lvl != "good"
    ]
    order = {"bad": 0, "warn": 1}
    attention.sort(key=lambda f: order[f[0]])
    story.append(Paragraph("Needs attention", H3))
    story.append(
        _findings_box(attention, width, limit=25)
        if attention
        else _findings_box([("good", "Every server was healthy in this period.")], width)
    )
    if len(attention) > 25:
        story.append(
            Paragraph(f"25 of {len(attention)} findings; each server's page lists its own.", SMALL)
        )

    def top(key, fmt, reverse=True, n=5):
        scored = [(key(d), d) for d in datas]
        scored = [(v, d) for v, d in scored if v is not None]
        scored.sort(key=lambda x: x[0], reverse=reverse)
        return scored[:n]

    rows = [["Server", "Availability", "Downtime"]]
    for v, d in top(lambda d: d.availability, None, reverse=False):
        rows.append(
            [d.host.hostname[:48], f"{v:.3f}%", fmt_duration(sum(b - a for a, b in d.downtimes))]
        )
    story += _ranking("Least available", rows, width)
    rows = [["Server", "CPU p95", "CPU peak"]]
    for v, d in top(lambda d: p95(d.values("cpu")) if d.values("cpu") else None, None):
        rows.append([d.host.hostname[:48], f"{v:.0f}%", f"{max(d.values('cpu')):.0f}%"])
    story += _ranking("Busiest CPUs", rows, width)
    rows = [["Server · disk", "Peak", "Full in"]]
    disks = sorted(((x, d) for d in datas for x in d.disks), key=lambda t: t[0].peak, reverse=True)[
        :8
    ]
    for x, d in disks:
        rows.append(
            [
                f"{d.host.hostname[:36]} · {x.mount[:20]}",
                f"{x.peak:.0f}%",
                "—" if x.full_in_days is None else f"~{x.full_in_days:.0f} days",
            ]
        )
    story += _ranking("Fullest disks", rows, width)
    rows = [["Server", "Memory peak", "Swap avg"]]
    for v, d in top(lambda d: max(d.values("memory")) if d.values("memory") else None, None):
        sw = d.values("swap")
        rows.append(
            [d.host.hostname[:48], f"{v:.0f}%", f"{statistics.fmean(sw):.0f}%" if sw else "—"]
        )
    story += _ranking("Most memory used", rows, width)
    rows = [["Server", "Incidents", "Critical"]]
    for v, d in top(lambda d: len(d.incidents) or None, None):
        rows.append(
            [d.host.hostname[:48], str(v), str(sum(i.severity == "critical" for i in d.incidents))]
        )
    story += _ranking("Most incidents", rows, width)

    story.append(Paragraph("All servers", H3))
    rows = [["Server", "Avail.", "Incid.", "Reboots", "CPU avg", "Mem peak", "Disk peak"]]
    for d in sorted(datas, key=lambda d: natural(d.host.hostname)):
        cpu, mem = d.values("cpu"), d.values("memory")
        fullest = max((x.peak for x in d.disks), default=None)
        rows.append(
            [
                d.host.hostname[:36],
                f"{d.availability:.2f}%" if d.availability is not None else "—",
                str(len(d.incidents)),
                "—" if d.restarts is None else str(d.restarts),
                f"{statistics.fmean(cpu):.0f}%" if cpu else "—",
                f"{max(mem):.0f}%" if mem else "—",
                f"{fullest:.0f}%" if fullest is not None else "—",
            ]
        )
    story.append(_table(rows, [width * 0.31] + [width * 0.115] * 6))

    for d in sorted(datas, key=lambda d: natural(d.host.hostname)):
        story.append(PageBreak())
        story += _host_section(d, width, tz, start, end)

    doc.build(story, onFirstPage=page, onLaterPages=page)
    return buf.getvalue()


def lifetime_start(hosts: list[Host]) -> datetime:
    return min(h.created_at for h in hosts) if hosts else datetime.now(UTC) - timedelta(days=30)
