"""On-call schedules, overrides, rules that page them, quiet hours and the
delivery log. Rotation cases match alerter/oncall_test.go."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone

from app.services import oncall

from .conftest import User

START = datetime(2026, 10, 26, 9, 0, tzinfo=UTC)


@dataclass
class S:
    start_at: datetime
    shift_hours: int
    responders: list


@dataclass
class Override:
    starts_at: datetime
    ends_at: datetime
    responder: dict
    created_at: datetime


def test_rotation_and_overrides():
    s = S(START, 24, [{"name": "Asha"}, {"name": "Ravi"}, {"name": "Meera"}])
    for hours, want in {
        -1: "Asha",
        0: "Asha",
        23: "Asha",
        24: "Ravi",
        72: "Asha",
        50: "Meera",
    }.items():
        assert (oncall.current(s, [], START + timedelta(hours=hours)) or {})["name"] == want
    overrides = [
        Override(
            START + timedelta(hours=24), START + timedelta(hours=48), {"name": "Cover"}, START
        ),
        Override(
            START + timedelta(hours=25),
            START + timedelta(hours=30),
            {"name": "Cover (newest)"},
            START + timedelta(minutes=1),
        ),
    ]
    newest = oncall.current(s, overrides, START + timedelta(hours=26))
    assert (newest or {})["name"] == "Cover (newest)"
    assert (oncall.current(s, overrides, START + timedelta(hours=31)) or {})["name"] == "Cover"
    shifts = oncall.shifts(s, overrides[:1], START, START + timedelta(days=3))
    assert [(sh.responder["name"], sh.override) for sh in shifts] == [
        ("Asha", False),
        ("Cover", True),
        ("Meera", False),
    ]


def test_quiet_hours():
    ist = timezone(timedelta(hours=5, minutes=30))
    q = {"start": "22:00", "end": "07:00", "timezone": "Asia/Kolkata"}
    want = datetime(2026, 10, 27, 7, 0, tzinfo=ist)
    assert oncall.quiet_until(q, "warning", datetime(2026, 10, 26, 23, 30, tzinfo=ist)) == want
    assert oncall.quiet_until(q, "warning", datetime(2026, 10, 27, 6, 0, tzinfo=ist)) == want
    assert oncall.quiet_until(q, "warning", datetime(2026, 10, 27, 12, 0, tzinfo=ist)) is None
    assert oncall.quiet_until(q, "critical", datetime(2026, 10, 26, 23, 30, tzinfo=ist)) is None
    strict = {**q, "critical_breaks_through": False}
    assert (
        oncall.quiet_until(strict, "critical", datetime(2026, 10, 26, 23, 30, tzinfo=ist)) == want
    )


async def _contact(user: User, address: str) -> str:
    r = await user.request("POST", "/v1/channels", json={"type": "webhook", "target": address})
    if r.status_code != 201:
        r = await user.request("POST", "/v1/channels", json={"type": "email", "target": address})
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def test_schedules_api(alice: User, bob: User):
    asha = await _contact(alice, "asha@example.com")
    ravi = await _contact(alice, "ravi@example.com")
    body = {
        "name": "Primary",
        "timezone": "Asia/Kolkata",
        "start_at": (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
        "shift_hours": 168,
        "responders": [
            {"name": "Asha", "channel_ids": [asha]},
            {"name": "Ravi", "channel_ids": [ravi]},
        ],
    }
    r = await alice.request("POST", "/v1/oncall/schedules", json=body)
    assert r.status_code == 201, r.text
    s = r.json()
    assert s["on_call"]["name"] == "Asha" and s["next_on_call"]["name"] == "Ravi"
    bad_tz = await alice.request(
        "POST", "/v1/oncall/schedules", json={**body, "name": "x", "timezone": "Mars/Base"}
    )
    assert bad_tz.status_code == 422
    # Bob can't use Alice's contacts or see her schedule.
    stolen = await bob.request("POST", "/v1/oncall/schedules", json={**body, "name": "Mine"})
    assert stolen.status_code == 422
    assert (await bob.request("GET", "/v1/oncall/schedules")).json() == []

    now = datetime.now(UTC)
    o = await alice.request(
        "POST",
        f"/v1/oncall/schedules/{s['id']}/overrides",
        json={
            "starts_at": now.isoformat(),
            "ends_at": (now + timedelta(hours=4)).isoformat(),
            "responder": {"name": "Ravi", "channel_ids": [ravi]},
            "note": "Asha at the dentist",
        },
    )
    assert o.status_code == 201, o.text
    assert o.json()["on_call"]["name"] == "Ravi"
    shifts = (
        await alice.request("GET", f"/v1/oncall/schedules/{s['id']}/shifts", params={"days": 8})
    ).json()
    assert shifts[0]["override"] and shifts[0]["responder"]["name"] == "Ravi"

    # A rule and an escalation step can page it.
    rule = {
        "name": "Server down",
        "kind": "host_down",
        "duration_seconds": 120,
        "schedule_ids": [s["id"]],
        "escalations": [{"delay_minutes": 15, "schedule_ids": [s["id"]]}],
    }
    created = await alice.request("POST", "/v1/alert-rules", json=rule)
    assert created.status_code == 201, created.text
    assert created.json()["schedule_ids"] == [s["id"]]
    assert created.json()["escalations"][0]["schedule_ids"] == [s["id"]]
    empty_step = {**rule, "escalations": [{"delay_minutes": 15}]}
    assert (await alice.request("POST", "/v1/alert-rules", json=empty_step)).status_code == 422
    listed = (await alice.request("GET", "/v1/oncall/schedules")).json()
    assert listed[0]["used_by_rules"] == 1
    # Deleting the schedule stops rules paging it.
    assert (await alice.request("DELETE", f"/v1/oncall/schedules/{s['id']}")).status_code == 204
    after = (await alice.request("GET", f"/v1/alert-rules/{created.json()['id']}")).json()
    # The step only paged the schedule, so it went too.
    assert after["schedule_ids"] == [] and after["escalations"] == []


async def test_quiet_hours_on_a_contact_and_deliveries(alice: User):
    cid = await _contact(alice, "night@example.com")
    q = {
        "start": "22:00",
        "end": "07:00",
        "timezone": "Asia/Kolkata",
        "critical_breaks_through": True,
    }
    r = await alice.request("PATCH", f"/v1/channels/{cid}", json={"quiet_hours": q})
    assert r.status_code == 200, r.text
    assert r.json()["quiet_hours"]["end"] == "07:00"
    bad = await alice.request(
        "PATCH", f"/v1/channels/{cid}", json={"quiet_hours": {**q, "end": "25:00"}}
    )
    assert bad.status_code == 422
    off = await alice.request("PATCH", f"/v1/channels/{cid}", json={"quiet_hours": None})
    assert off.json()["quiet_hours"] is None
    assert (await alice.request("GET", "/v1/deliveries")).status_code == 200
