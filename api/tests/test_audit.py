"""Audit log: successful changes are recorded with who made them, secrets
redacted; failed ones aren't; each account sees only its own."""

import uuid

from .conftest import User, access_token


async def events(user: User, **params) -> list[dict]:
    r = await user.request("GET", "/v1/audit-log", params=params)
    assert r.status_code == 200, r.text
    return r.json()


async def test_changes_are_recorded(alice: User, bob: User):
    rule = {
        "name": "Disk above 95%",
        "kind": "metric",
        "metric": "disk",
        "operator": ">",
        "threshold": 95,
    }
    created = (await alice.request("POST", "/v1/alert-rules", json=rule)).json()
    # A rejected request leaves nothing behind.
    bad = await alice.request("POST", "/v1/alert-rules", json={"name": "x", "kind": "metric"})
    assert bad.status_code == 422
    await alice.request("DELETE", f"/v1/alert-rules/{created['id']}")
    token = (await alice.request("POST", "/v1/api-tokens", json={"name": "ci"})).json()

    got = await events(alice)
    actions = [e["action"] for e in got]
    assert actions[:3] == ["api_token.create", "alert_rule.delete", "alert_rule.create"]
    create = got[2]
    assert create["summary"] == "Created alert rule “Disk above 95%”"
    assert create["actor"] == alice.email and create["actor_kind"] == "owner"
    assert create["details"]["body"]["threshold"] == 95
    assert got[1]["target_id"] == created["id"]
    # Reads aren't recorded, and nothing secret is kept.
    assert all(e["action"] != "get" for e in got)
    assert token.get("token") not in str(got)

    # Filters.
    assert [e["action"] for e in await events(alice, action="alert_rule.*")] == [
        "alert_rule.delete",
        "alert_rule.create",
    ]
    assert len(await events(alice, q="Disk above")) == 1
    # Bob sees none of it.
    assert await events(bob) == []


async def test_staff_changes_are_recorded(client, alice: User):
    token = access_token(str(uuid.uuid4()), "ops@example.com", superadmin=True)
    staff = {"Authorization": f"Bearer {token}"}
    tid = await alice.tenant_id()
    r = await client.put(
        f"/admin/v1/tenants/{tid}/agent-pin", headers=staff, json={"version": None}
    )
    assert r.status_code == 200
    mine = await events(alice)
    assert mine[0]["action"] == "rollout.pin" and mine[0]["actor_kind"] == "staff"
    every = (
        await client.get("/admin/v1/audit-log", headers=staff, params={"staff_only": True})
    ).json()
    assert every[0]["actor"] == "ops@example.com (superadmin)"
