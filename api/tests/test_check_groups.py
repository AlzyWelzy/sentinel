"""Check groups: a group runs nowhere, members point at it, loops and
foreign groups are refused, and its state rolls up from its members."""

import json
import time

from app.services.checkresults import CHECK_RESULT_KEY
from app.services.heartbeats import redis

from .conftest import User


async def store(cid: str, field: str, result: dict) -> None:
    await redis.hset(CHECK_RESULT_KEY.format(check_id=cid), field, json.dumps(result))


async def mk(user: User, **body):
    r = await user.request("POST", "/v1/checks", json={"name": body.get("type", "x"), **body})
    assert r.status_code == 201, r.text
    return r.json()


async def test_group_rollup_and_rules(alice: User, bob: User):
    g = await mk(alice, name="Shop", type="group")
    assert g["target"] == "group" and g["status"] == "pending" and g["members"] == []
    inner = await mk(alice, name="Payments", type="group", parent_id=g["id"])
    a = await mk(
        alice, name="web", type="http", target="https://example.com", on_probes=True,
        parent_id=g["id"],
    )  # fmt: skip
    b = await mk(alice, name="pay", type="push", interval_seconds=3600, parent_id=inner["id"])

    r = (await alice.request("GET", f"/v1/checks/{g['id']}")).json()
    assert set(r["members"]) == {inner["id"], a["id"]}

    # The push has reported up and the web check down: the group is down,
    # through the nested one for the push.
    now = int(time.time() * 1000)
    await store(b["id"], b["id"], {"ok": True, "ts": now})
    r = (await alice.request("GET", f"/v1/checks/{inner['id']}")).json()
    assert r["status"] == "up", r
    await store(a["id"], "probe:eu", {"ok": False, "ts": now, "region": "eu"})
    assert (await alice.request("GET", f"/v1/checks/{g['id']}")).json()["status"] == "down"

    # Pausing the failing member leaves the group up.
    body = {k: a[k] for k in ("name", "type", "target", "on_probes", "parent_id")}
    r = await alice.request("PUT", f"/v1/checks/{a['id']}", json={**body, "enabled": False})
    assert r.status_code == 200, r.text
    assert (await alice.request("GET", f"/v1/checks/{g['id']}")).json()["status"] == "up"

    # No loops, no members that aren't groups as parents, no foreign groups.
    loop = await alice.request(
        "PUT", f"/v1/checks/{g['id']}",
        json={"name": "Shop", "type": "group", "parent_id": inner["id"]},
    )  # fmt: skip
    assert loop.status_code == 422 and "itself" in loop.text
    selfp = await alice.request(
        "PUT", f"/v1/checks/{g['id']}", json={"name": "Shop", "type": "group", "parent_id": g["id"]}
    )
    assert selfp.status_code == 422
    r = await alice.request(
        "POST", "/v1/checks", json={"name": "x", "type": "push", "parent_id": b["id"]}
    )
    assert r.status_code == 422 and "must be a group" in r.text
    r = await bob.request(
        "POST", "/v1/checks", json={"name": "x", "type": "group", "parent_id": g["id"]}
    )
    assert r.status_code == 422 and "not found" in r.text
    r = await alice.request(
        "POST", "/v1/checks", json={"name": "x", "type": "group", "on_probes": True}
    )
    assert r.status_code == 422

    # A group with members can't turn into something else; deleting it
    # leaves its members ungrouped.
    r = await alice.request(
        "PUT", f"/v1/checks/{inner['id']}",
        json={"name": "p", "type": "tcp", "target": "example.com:443", "on_probes": True},
    )  # fmt: skip
    assert r.status_code == 422 and "members" in r.text
    assert (await alice.request("DELETE", f"/v1/checks/{inner['id']}")).status_code == 204
    r = (await alice.request("GET", f"/v1/checks/{b['id']}")).json()
    assert r["parent_id"] is None

    # Its alert rule fires at once: members already waited.
    rule = (await alice.request("GET", f"/v1/alert-rules/{g['rule_id']}")).json()
    assert rule["duration_seconds"] == 0
