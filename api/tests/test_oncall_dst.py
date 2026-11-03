"""On-call rotations across daylight-saving changes (pure logic, no database)."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from zoneinfo import ZoneInfo

from app.services import oncall

LONDON = ZoneInfo("Europe/London")


def schedule(start: datetime, hours: int) -> SimpleNamespace:
    return SimpleNamespace(
        start_at=start.astimezone(UTC),
        shift_hours=hours,
        timezone="Europe/London",
        responders=[{"name": "a"}, {"name": "b"}],
    )


def test_daily_handoff_keeps_local_time_when_clocks_change():
    s = schedule(datetime(2026, 10, 20, 9, 0, tzinfo=LONDON), 24)
    for day in (26, 27, 28):  # after the change back on 25 Oct
        before = datetime(2026, 10, day, 8, 59, tzinfo=LONDON)
        after = datetime(2026, 10, day, 9, 1, tzinfo=LONDON)
        assert oncall.current(s, [], before) != oncall.current(s, [], after), day
    shifts = oncall.shifts(
        s, [], datetime(2026, 10, 24, tzinfo=UTC), datetime(2026, 10, 28, tzinfo=UTC)
    )
    starts = {sh.starts_at.astimezone(LONDON).strftime("%H:%M") for sh in shifts[1:]}
    assert starts == {"09:00"}
    # The day the clocks change is 25 hours long; the others 24.
    lengths = sorted((sh.ends_at - sh.starts_at) for sh in shifts[1:-1])
    assert lengths[-1] == timedelta(hours=25)


def test_twelve_hour_rotation_stays_exact():
    s = schedule(datetime(2026, 10, 24, 9, 0, tzinfo=LONDON), 12)
    at = s.start_at + timedelta(hours=36, minutes=1)
    assert oncall.current(s, [], at) == {"name": "b"}
