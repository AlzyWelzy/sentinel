"""Channel verification, alert rules and incidents, including cross-tenant checks."""

import uuid

from sqlalchemy import text

from app.db import ServiceSession

from .conftest import User, insert_host, latest_code


async def add_channel(user: User, type_: str, target: str) -> dict:
    r = await user.request("POST", "/v1/channels", json={"type": type_, "target": target})
    assert r.status_code == 201, r.text
    return r.json()


# ── Verification ─────────────────────────────────────────────────────────────


async def test_new_channel_gets_a_code_and_verifies(alice: User):
    ch = await add_channel(alice, "email", "ops@example.com")
    assert ch["verified"] is False
    code = await latest_code(ch["id"])
    assert len(code) == 6 and code.isdigit()

    r = await alice.request("POST", f"/v1/channels/{ch['id']}/verify", json={"code": code})
    assert r.status_code == 200 and r.json()["verified"] is True


async def test_wrong_codes_are_limited(alice: User):
    ch = await add_channel(alice, "sms", "+919876543210")
    code = await latest_code(ch["id"])
    wrong = f"{(int(code) + 1) % 1_000_000:06d}"
    for _ in range(5):
        r = await alice.request("POST", f"/v1/channels/{ch['id']}/verify", json={"code": wrong})
        assert r.status_code == 400
    # Attempts survive the failed requests, so even the right code is now refused.
    r = await alice.request("POST", f"/v1/channels/{ch['id']}/verify", json={"code": code})
    assert r.status_code == 429


async def test_resend_is_rate_limited(alice: User):
    ch = await add_channel(alice, "email", "rate@example.com")
    r = await alice.request("POST", f"/v1/channels/{ch['id']}/verification")
    assert r.status_code == 429


async def test_cannot_verify_someone_elses_channel(alice: User, bob: User):
    ch = await add_channel(alice, "email", "mine@example.com")
    code = await latest_code(ch["id"])
    r = await bob.request("POST", f"/v1/channels/{ch['id']}/verify", json={"code": code})
    assert r.status_code == 404


async def test_targets_are_validated(alice: User):
    for type_, target in [
        ("email", "not-an-email"),
        ("sms", "9876543210"),
        ("webhook", "ftp://x.test"),
    ]:
        r = await alice.request("POST", "/v1/channels", json={"type": type_, "target": target})
        assert r.status_code == 422, (type_, target)


async def test_code_is_wiped_after_delivery_marker(alice: User):
    """The dispatcher strips `code` from the payload when it marks a message
    sent; simulate that and check nothing else depends on it."""
    ch = await add_channel(alice, "email", "wipe@example.com")
    async with ServiceSession() as db, db.begin():
        await db.execute(
            text(
                "UPDATE outbound_messages SET status='sent', payload = payload - 'code' "
                "WHERE channel_id = :c"
            ),
            {"c": ch["id"]},
        )
        left = (
            await db.execute(
                text("SELECT payload ? 'code' FROM outbound_messages WHERE channel_id = :c"),
                {"c": ch["id"]},
            )
        ).scalar_one()
    assert left is False


async def test_test_message_needs_verified_channel(alice: User):
    default = (await alice.request("GET", "/v1/channels")).json()[0]
    assert (await alice.request("POST", f"/v1/channels/{default['id']}/test")).status_code == 202
    ch = await add_channel(alice, "email", "unverified@example.com")
    assert (await alice.request("POST", f"/v1/channels/{ch['id']}/test")).status_code == 409


# ── Rules ────────────────────────────────────────────────────────────────────


CPU_RULE = {
    "name": "High CPU",
    "kind": "metric",
    "metric": "cpu",
    "operator": ">",
    "threshold": 90,
    "duration_seconds": 300,
}


async def test_rule_crud(alice: User):
    created = await alice.request("POST", "/v1/alert-rules", json=CPU_RULE)
    assert created.status_code == 201, created.text
    rule = created.json()
    assert rule["firing_hosts"] == 0 and rule["channel_ids"] == []

    updated = await alice.request(
        "PUT", f"/v1/alert-rules/{rule['id']}", json={**CPU_RULE, "threshold": 80}
    )
    assert updated.json()["threshold"] == 80
    assert [r["id"] for r in (await alice.request("GET", "/v1/alert-rules")).json()] == [rule["id"]]
    assert (await alice.request("DELETE", f"/v1/alert-rules/{rule['id']}")).status_code == 204
    assert (await alice.request("GET", "/v1/alert-rules")).json() == []


async def test_rule_validation(alice: User):
    bad = [
        {**CPU_RULE, "threshold": None},
        {"name": "down", "kind": "host_down", "duration_seconds": 10},
        {**CPU_RULE, "metric": "gpu"},
    ]
    for body in bad:
        assert (await alice.request("POST", "/v1/alert-rules", json=body)).status_code == 422


async def test_rules_cannot_reference_other_tenants(alice: User, bob: User):
    bob_host = await insert_host(await bob.tenant_id(), "bob-db")
    bob_channel = (await bob.request("GET", "/v1/channels")).json()[0]["id"]

    r = await alice.request("POST", "/v1/alert-rules", json={**CPU_RULE, "host_id": str(bob_host)})
    assert r.status_code == 422
    r = await alice.request(
        "POST", "/v1/alert-rules", json={**CPU_RULE, "channel_ids": [bob_channel]}
    )
    assert r.status_code == 422


async def test_rules_are_private(alice: User, bob: User):
    rule = (await alice.request("POST", "/v1/alert-rules", json=CPU_RULE)).json()
    assert (await bob.request("GET", "/v1/alert-rules")).json() == []
    for method, kw in [("GET", {}), ("DELETE", {}), ("PUT", {"json": CPU_RULE})]:
        r = await bob.request(method, f"/v1/alert-rules/{rule['id']}", **kw)
        assert r.status_code == 404, method


# ── Incidents ────────────────────────────────────────────────────────────────


async def open_incident(tenant_id: uuid.UUID, rule_id: str, host_id: uuid.UUID) -> str:
    """Open an incident and firing state the way the alerter does."""
    async with ServiceSession() as db, db.begin():
        incident_id = (
            await db.execute(
                text(
                    "INSERT INTO incidents "
                    "(tenant_id, rule_id, host_id, summary, rule_name, hostname, value) "
                    "VALUES (:t, :r, :h, 'High CPU on web-1', 'High CPU', 'web-1', 97) RETURNING id"
                ),
                {"t": tenant_id, "r": rule_id, "h": host_id},
            )
        ).scalar_one()
        await db.execute(
            text(
                "INSERT INTO alert_states "
                "(rule_id, subject_id, host_id, tenant_id, state, incident_id) "
                "VALUES (:r, :h, :h, :t, 'firing', :i)"
            ),
            {"t": tenant_id, "r": rule_id, "h": host_id, "i": incident_id},
        )
        return str(incident_id)


async def test_incidents_list_ack_and_privacy(alice: User, bob: User):
    tenant = await alice.tenant_id()
    host = await insert_host(tenant)
    rule = (await alice.request("POST", "/v1/alert-rules", json=CPU_RULE)).json()
    incident_id = await open_incident(tenant, rule["id"], host)

    assert (await alice.request("GET", f"/v1/alert-rules/{rule['id']}")).json()["firing_hosts"] == 1
    open_ = (await alice.request("GET", "/v1/incidents?status=open")).json()
    assert [i["id"] for i in open_] == [incident_id]

    assert (await bob.request("GET", "/v1/incidents")).json() == []
    assert (await bob.request("GET", f"/v1/incidents/{incident_id}")).status_code == 404
    r = await bob.request("POST", f"/v1/incidents/{incident_id}/acknowledge")
    assert r.status_code == 404

    acked = await alice.request("POST", f"/v1/incidents/{incident_id}/acknowledge")
    assert acked.json()["acknowledged_at"] is not None


async def test_changing_or_deleting_a_rule_closes_its_incidents(alice: User):
    tenant = await alice.tenant_id()
    host = await insert_host(tenant)
    rule = (await alice.request("POST", "/v1/alert-rules", json=CPU_RULE)).json()
    incident_id = await open_incident(tenant, rule["id"], host)

    # Renaming isn't a condition change: the incident stays open.
    await alice.request("PUT", f"/v1/alert-rules/{rule['id']}", json={**CPU_RULE, "name": "CPU!"})
    assert (await alice.request("GET", f"/v1/incidents/{incident_id}")).json()["status"] == "open"

    await alice.request("PUT", f"/v1/alert-rules/{rule['id']}", json={**CPU_RULE, "threshold": 50})
    got = (await alice.request("GET", f"/v1/incidents/{incident_id}")).json()
    assert got["status"] == "resolved" and got["resolved_at"] is not None
    assert (await alice.request("GET", f"/v1/alert-rules/{rule['id']}")).json()["firing_hosts"] == 0
