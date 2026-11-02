"""API-level isolation: two real users, every endpoint that takes an id."""

import uuid

from .conftest import User, access_token, impersonate, insert_host, latest_code, superadmin_headers


async def test_requires_a_valid_token(client):
    assert (await client.get("/v1/hosts")).status_code == 401
    bad = {"Authorization": "Bearer not-a-jwt"}
    assert (await client.get("/v1/hosts", headers=bad)).status_code == 401
    # Signed with another secret: refused.
    from joserfc import jwt
    from joserfc.jwk import OctKey

    forged = jwt.encode(
        {"alg": "HS256"},
        {"iss": "sentinel", "sub": str(uuid.uuid4()), "exp": 9999999999},
        OctKey.import_key(b"x" * 32),
    )
    bad = {"Authorization": f"Bearer {forged}"}
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
        (alice.email, "account", True)
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


async def test_impersonated_sessions_are_read_only(client, alice: User):
    tid = await alice.tenant_id()
    headers = await impersonate(client, tid)
    assert (await client.get("/v1/hosts", headers=headers)).status_code == 200
    assert (await client.get("/v1/me", headers=headers)).json()["tenant_id"] == str(tid)
    created = await client.post("/v1/agent-keys", json={"name": "x"}, headers=headers)
    assert created.status_code == 403
    # With writes allowed, changes go through and are audited as the superadmin.
    writes = await impersonate(client, tid, writes=True)
    created = await client.post("/v1/agent-keys", json={"name": "x"}, headers=writes)
    assert created.status_code == 201
    log = (await alice.request("GET", "/v1/audit-log")).json()
    assert log[0]["actor_kind"] == "staff" and log[0]["actor"].endswith("(superadmin)")


async def test_a_superadmin_token_alone_reaches_no_organisation(client, alice: User):
    tid = await alice.tenant_id()
    headers = await superadmin_headers()
    r = await client.get("/v1/hosts", headers={**headers, "X-Sentinel-Account": str(tid)})
    assert r.status_code == 403


async def test_forged_impersonation_claims_are_refused(client, alice: User):
    """An impersonation must exist and belong to a superadmin."""
    tid = await alice.tenant_id()
    token = access_token(alice.uid, alice.email, impersonation=(str(uuid.uuid4()), str(tid), True))
    r = await client.get("/v1/hosts", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


async def test_suspended_tenant_is_locked_out(client, alice: User):
    tid = await alice.tenant_id()
    admin = await superadmin_headers()
    assert (await client.post(f"/admin/v1/tenants/{tid}/suspend", headers=admin)).status_code == 204
    assert (await alice.request("GET", "/v1/hosts")).status_code == 403
    assert (await alice.request("GET", "/v1/hosts", headers={})).status_code == 403
    # Customers can't suspend or resume anything themselves.
    assert (await alice.request("POST", f"/admin/v1/tenants/{tid}/resume")).status_code == 403
    assert (await client.post(f"/admin/v1/tenants/{tid}/resume", headers=admin)).status_code == 204
    assert (await alice.request("GET", "/v1/hosts")).status_code == 200


async def test_revoking_a_key_keeps_it_listed_as_revoked(alice: User):
    key = (await alice.request("POST", "/v1/agent-keys", json={"name": "old"})).json()
    assert (await alice.request("DELETE", f"/v1/agent-keys/{key['id']}")).status_code == 204
    listed = (await alice.request("GET", "/v1/agent-keys")).json()
    assert listed[0]["revoked_at"] is not None
