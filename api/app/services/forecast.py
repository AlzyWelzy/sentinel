"""Where a server's CPU, memory and disks are heading: a straight-line
trend fitted to hourly averages, carried forward, with a band above it as
wide as the usual peaks, and when that band first reaches a limit."""

from dataclasses import dataclass

MIN_POINTS = 24  # a day of hourly averages before projecting anything


@dataclass
class Projection:
    points: list[list[float]]  # [ts, trend]
    upper: list[list[float]]  # [ts, trend + usual peak]
    slope_per_day: float
    reaches_at: int | None  # when the upper band first reaches the limit


def project(
    history: list[list[float]], horizon: int, step: int, limit: float = 90.0
) -> Projection | None:
    """Fit y = a + b·t by least squares to (ts, value) points and carry it
    forward `horizon` seconds in `step`s. The band adds the 95th percentile
    of how far values rose above the trend, so a server that peaks daily
    is projected by its peaks, not its average."""
    pts = [(float(t), float(v)) for t, v in history if v is not None]
    if len(pts) < MIN_POINTS:
        return None
    n = len(pts)
    mt = sum(t for t, _ in pts) / n
    mv = sum(v for _, v in pts) / n
    var = sum((t - mt) ** 2 for t, _ in pts)
    b = sum((t - mt) * (v - mv) for t, v in pts) / var if var else 0.0
    a = mv - b * mt
    above = sorted(max(0.0, v - (a + b * t)) for t, v in pts)
    peak = above[min(len(above) - 1, int(0.95 * len(above)))]
    last = pts[-1][0]
    out, upper, reaches = [], [], None
    t = last
    while t <= last + horizon:
        trend = min(100.0, max(0.0, a + b * t))
        top = min(100.0, trend + peak)
        out.append([int(t), round(trend, 2)])
        upper.append([int(t), round(top, 2)])
        if reaches is None and top >= limit:
            reaches = int(t)
        t += step
    return Projection(out, upper, round(b * 86400, 3), reaches)
