"""On-call schedules and quiet hours. The alerter decides the same way
(alerter/oncall.go); keep the two in step.

A schedule's shifts follow each other every shift_hours from start_at and
its responders take turns in order. An override (the newest one covering the
moment) replaces whoever's turn it is. Quiet hours hold a contact's alerts
until the window ends, unless the alert is critical and the contact lets
critical alerts break through.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, time, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


@dataclass
class Shift:
    starts_at: datetime
    ends_at: datetime
    responder: dict
    override: bool = False


def _boundary(schedule, k: int) -> datetime:
    """When shift k begins. Shifts of whole days keep their local start time
    across daylight-saving changes (a 09:00 handoff stays at 09:00); other
    lengths are exact hours."""
    if schedule.shift_hours % 24 == 0:
        local = schedule.start_at.astimezone(zone(getattr(schedule, "timezone", None)))
        # Aware arithmetic is wall-clock: the offset is worked out afresh.
        return (local + timedelta(days=k * schedule.shift_hours // 24)).astimezone(UTC)
    return schedule.start_at + k * timedelta(hours=schedule.shift_hours)


def _turn(schedule, n: int, at: datetime) -> tuple[int, int, datetime]:
    """Whose turn it is at `at` (index), the shift's number, and its start."""
    if at < schedule.start_at:
        return 0, 0, schedule.start_at
    k = int((at - schedule.start_at) // timedelta(hours=schedule.shift_hours))
    # A daylight-saving change moves whole-day boundaries by up to an hour.
    while _boundary(schedule, k + 1) <= at:
        k += 1
    while k > 0 and _boundary(schedule, k) > at:
        k -= 1
    return k % n, k, _boundary(schedule, k)


def current(schedule, overrides: list, at: datetime) -> dict | None:
    for o in sorted(overrides, key=lambda o: o.created_at or at, reverse=True):
        if o.starts_at <= at < o.ends_at:
            return o.responder
    responders = schedule.responders or []
    if not responders:
        return None
    i, _, _ = _turn(schedule, len(responders), at)
    return responders[i]


def shifts(schedule, overrides: list, start: datetime, end: datetime) -> list[Shift]:
    """The rotation between start and end, with overrides cut in."""
    responders = schedule.responders or []
    out: list[Shift] = []
    if responders:
        i, k, at = _turn(schedule, len(responders), start)
        while at < end:
            nxt = _boundary(schedule, k + 1)
            out.append(Shift(max(at, start), min(nxt, end), responders[i]))
            at, k, i = nxt, k + 1, (i + 1) % len(responders)
    for o in sorted(overrides, key=lambda o: o.starts_at):
        if o.ends_at <= start or o.starts_at >= end:
            continue
        s, e = max(o.starts_at, start), min(o.ends_at, end)
        cut: list[Shift] = []
        for sh in out:
            if sh.ends_at <= s or sh.starts_at >= e:
                cut.append(sh)
                continue
            if sh.starts_at < s:
                cut.append(Shift(sh.starts_at, s, sh.responder, sh.override))
            if sh.ends_at > e:
                cut.append(Shift(e, sh.ends_at, sh.responder, sh.override))
        cut.append(Shift(s, e, o.responder, True))
        out = sorted(cut, key=lambda sh: sh.starts_at)
    return out


def zone(name: str | None) -> ZoneInfo:
    try:
        return ZoneInfo(name or "UTC")
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo("UTC")


def parse_hhmm(value: str) -> time:
    h, m = value.split(":")
    return time(int(h), int(m))


def quiet_until(quiet: dict | None, severity: str, at: datetime) -> datetime | None:
    """When a held message may go out, or None to send now."""
    if not quiet or not quiet.get("start") or not quiet.get("end"):
        return None
    if severity == "critical" and quiet.get("critical_breaks_through", True):
        return None
    tz = zone(quiet.get("timezone"))
    local = at.astimezone(tz)
    start, end = parse_hhmm(quiet["start"]), parse_hhmm(quiet["end"])
    if start == end:
        return None
    now_t = local.timetz().replace(tzinfo=None)
    overnight = start > end
    inside = (now_t >= start or now_t < end) if overnight else (start <= now_t < end)
    if not inside:
        return None
    day = local.date()
    if overnight and now_t >= start:
        day = day + timedelta(days=1)
    return datetime.combine(day, end, tzinfo=tz).astimezone(UTC)
