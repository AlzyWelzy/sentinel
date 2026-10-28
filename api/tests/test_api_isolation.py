"""API-level isolation: two real console users, every endpoint that takes an id."""

import uuid

from .conftest import User, console_token, insert_host, latest_code


async def test_requires_a_valid_console_token(client):
    assert (await client.get("/v1/hosts")).status_code == 401
    bad = {"Authorization": "Bearer not-a-jwt"}
    assert (await client.get("/v1/hosts", headers=bad)).status_code == 401


async def test_each_user_gets_their_own_tenant(alice: User, bob: User):
    assert await alice.tenant_id() != await bob.tenant_id()
    assert await alice.tenant_id() == await alice.tenant_id()


async def test_agent_keys_are_private(alice: User, bob: User):
    created = await alice.request("POST", "/v1/agent-keys", json={"name": "prod"})
    assert created.status_code == 201
    body = created.json()
    assert body["key"].startswith("pg_")
    assert body["key"] in body["install_command"]

    assert (await bob.request("GET", "/v1/agent-keys")).json() == []
    revoke = await bob.request("DELETE", f"/v1/agent-keys/{body['id']}")
    assert revoke.status_code == 404

    keys = (await alice.request("GET", "/v1/agent-keys")).json()
    assert [k["id"] for k in keys] == [body["id"]]
    assert keys[0]["revoked_at"] is None
    assert "key" not in keys[0]  # plaintext is never shown again


async def test_hosts_are_private(alice: User, bob: User):
    host_id = await insert_host(await alice.tenant_id(), "alice-web")

    assert [h["id"] for h in (await alice.request("GET", "/v1/hosts")).json()] == [str(host_id)]
    assert (await bob.request("GET", "/v1/hosts")).json() == []

    for method, path in [
        ("GET", f"/v1/hosts/{host_id}"),
        ("GET", f"/v1/hosts/{host_id}/metrics?metric=cpu"),
        ("DELETE", f"/v1/hosts/{host_id}"),
    ]:
        assert (await bob.request(method, path)).status_code == 404, path

    assert (await alice.request("GET", f"/v1/hosts/{host_id}")).status_code == 200


async def test_channels_are_private(alice: User, bob: User):
    channels = (await alice.request("GET", "/v1/channels")).json()
    assert [(c["target"], c["source"], c["is_default"]) for c in channels] == [
        (alice.email, "console", True)
    ]

    added = await alice.request(
        "POST", "/v1/channels", json={"type": "email", "target": "oncall@example.com"}
    )
    assert added.status_code == 201
    assert added.json()["verified"] is False

    assert all(
        c["target"] != "oncall@example.com"
        for c in (await bob.request("GET", "/v1/channels")).json()
    )
    assert (await bob.request("DELETE", f"/v1/channels/{added.json()['id']}")).status_code == 404


async def test_last_verified_channel_cannot_be_deleted_and_default_moves(alice: User):
    default = (await alice.request("GET", "/v1/channels")).json()[0]
    assert (await alice.request("DELETE", f"/v1/channels/{default['id']}")).status_code == 409

    extra = (
        await alice.request(
            "POST", "/v1/channels", json={"type": "webhook", "target": "https://x.test/hook"}
        )
    ).json()
    # An unverified channel doesn't count: alerts couldn't go anywhere.
    assert (await alice.request("DELETE", f"/v1/channels/{default['id']}")).status_code == 409

    code = await latest_code(extra["id"])
    verify = await alice.request("POST", f"/v1/channels/{extra['id']}/verify", json={"code": code})
    assert verify.status_code == 200
    assert (await alice.request("DELETE", f"/v1/channels/{default['id']}")).status_code == 204
    remaining = (await alice.request("GET", "/v1/channels")).json()
    assert [(c["id"], c["is_default"]) for c in remaining] == [(extra["id"], True)]


async def test_impersonated_sessions_are_read_only(client):
    headers = {
        "Authorization": f"Bearer {console_token(str(uuid.uuid4()), 'c@example.com', imp=1)}"
    }
    assert (await client.get("/v1/hosts", headers=headers)).status_code == 200
    created = await client.post("/v1/agent-keys", json={"name": "x"}, headers=headers)
    assert created.status_code == 403


async def test_internal_routes_need_the_internal_key(client, alice: User):
    await alice.tenant_id()
    assert (await client.get("/internal/v1/usage")).status_code == 401
    wrong = {"X-Internal-Api-Key": "nope"}
    assert (await client.get("/internal/v1/usage", headers=wrong)).status_code == 401
    # A customer's console token is not an internal credential.
    assert (await alice.request("GET", "/internal/v1/usage")).status_code == 401


async def test_suspended_tenant_is_locked_out(client, alice: User):
    await alice.tenant_id()
    key = {"X-Internal-Api-Key": "change-me-pulsegrid-internal-key"}
    assert (
        await client.post(f"/internal/v1/tenants/{alice.uid}/suspend", headers=key)
    ).status_code == 204
    assert (await alice.request("GET", "/v1/hosts")).status_code == 403
    assert (
        await client.post(f"/internal/v1/tenants/{alice.uid}/resume", headers=key)
    ).status_code == 204
    assert (await alice.request("GET", "/v1/hosts")).status_code == 200


async def test_revoking_a_key_keeps_it_listed_as_revoked(alice: User):
    key = (await alice.request("POST", "/v1/agent-keys", json={"name": "old"})).json()
    assert (await alice.request("DELETE", f"/v1/agent-keys/{key['id']}")).status_code == 204
    listed = (await alice.request("GET", "/v1/agent-keys")).json()
    assert listed[0]["revoked_at"] is not None


async def test_bad_token_is_rejected_even_with_dev_bypass(client, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "ALLOW_AUTH_BYPASS", True)
    bad = {"Authorization": "Bearer not.a.token"}
    assert (await client.get("/v1/hosts", headers=bad)).status_code == 401
    # With no token at all, the bypass applies.
    assert (await client.get("/v1/hosts")).status_code == 200


async def test_internal_incidents_for_ticket_rules(client, alice: User, bob: User):
    from sqlalchemy import text

    from app.db import ServiceSession

    from .conftest import insert_host

    key = {"X-Internal-Api-Key": "change-me-pulsegrid-internal-key"}
    a = await alice.tenant_id()
    await bob.tenant_id()
    host = await insert_host(a, "alice-web")
    async with ServiceSession() as db, db.begin():
        open_id, closed_id = [
            (
                await db.execute(
                    text(
                        "INSERT INTO incidents "
                        "(tenant_id, host_id, summary, rule_name, hostname, status) "
                        "VALUES (:t, :h, 'Disk full', 'Disk', 'alice-web', :s) RETURNING id"
                    ),
                    {"t": a, "h": host, "s": s},
                )
            ).scalar_one()
            for s in ("open", "resolved")
        ]
    assert (await client.get("/internal/v1/incidents")).status_code == 401
    listed = (await client.get("/internal/v1/incidents", headers=key)).json()
    mine = [i["id"] for i in listed if i["external_account_id"] == alice.uid]
    assert mine == [str(open_id)]
    both = {"ids": [str(open_id), str(closed_id)]}
    by_id = (await client.get("/internal/v1/incidents", params=both, headers=key)).json()
    assert sorted(i["status"] for i in by_id) == ["open", "resolved"]
