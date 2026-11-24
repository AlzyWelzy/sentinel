import uuid
from datetime import UTC, datetime, timedelta

from app.services.insights import outage_groups, suggest_dependencies

T0 = datetime(2026, 11, 1, tzinfo=UTC)
router, web1, web2, db = (uuid.uuid4() for _ in range(4))


def outage(day: int, *hosts: uuid.UUID, gap: int = 20) -> list[tuple[uuid.UUID, datetime]]:
    start = T0 + timedelta(days=day)
    return [(h, start + timedelta(seconds=i * gap)) for i, h in enumerate(hosts)]


def test_groups_split_on_gaps():
    events = outage(0, router, web1) + outage(1, web2) + outage(2, web1, web2)
    assert outage_groups(events) == [[router, web1], [web1, web2]]


def test_upstream_that_goes_first():
    events = []
    for d in range(4):
        events += outage(d, router, web1, web2)
    events += outage(9, db)  # alone: never suggested
    ((followers, together, upstream),) = suggest_dependencies(outage_groups(events), {})
    assert upstream == router
    assert set(followers) == {web1, web2}
    assert together == 4


def test_peers_without_an_upstream():
    events = (
        outage(0, web1, web2)
        + outage(1, web2, web1)
        + outage(2, web1, web2)
        + outage(3, web2, web1)
    )
    ((followers, _, upstream),) = suggest_dependencies(outage_groups(events), {})
    assert upstream is None
    assert set(followers) == {web1, web2}


def test_too_rare_or_already_set():
    rare = outage(0, router, web1) + outage(1, router, web1)
    assert suggest_dependencies(outage_groups(rare), {}) == []
    events = []
    for d in range(3):
        events += outage(d, router, web1)
    assert suggest_dependencies(outage_groups(events), {web1: router}) == []
