"""When a maintenance window is active. Mirrors alerter/maintenance.go, which
is what actually holds alerts back; this copy only labels things in the
dashboard ("in maintenance"), so the two must agree."""

from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from app.models import Host, MaintenanceWindow


def covers(w: MaintenanceWindow, host: Host) -> bool:
    if w.host_id is not None:
        return w.host_id == host.id
    if w.tag is not None:
        return w.tag in (host.tags or [])
    return True


def active_at(w: MaintenanceWindow, now: datetime) -> bool:
    if not w.enabled:
        return False
    if w.schedule == "once":
        return bool(w.starts_at and w.ends_at and w.starts_at <= now < w.ends_at)
    if not (w.weekdays and w.start_time and w.duration_minutes):
        return False
    try:
        tz = ZoneInfo(w.timezone)
    except ZoneInfoNotFoundError:
        tz = UTC
    local = now.astimezone(tz)
    length = timedelta(minutes=w.duration_minutes)
    # A window lasts at most a week, so one that began on any of the last
    # seven days (or today) may still be running.
    for back in range(8):
        day = (local - timedelta(days=back)).date()
        if day.isoweekday() not in w.weekdays:
            continue
        # In UTC, so the length is elapsed time across a DST change (as in Go).
        begin = datetime.combine(day, w.start_time, tzinfo=tz).astimezone(UTC)
        if begin <= now < begin + length:
            return True
    return False


def in_maintenance(windows: list[MaintenanceWindow], host: Host, now: datetime) -> bool:
    return any(covers(w, host) and active_at(w, now) for w in windows)
