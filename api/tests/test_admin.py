"""Staff view across accounts (read, plus editing and pausing servers), staff only."""

import uuid

import pytest

from .conftest import User, console_token, insert_host


@pytest.fixture
def staff_headers() -> dict:
    token = console_token(str(uuid.uuid4()), "support@Example.com", role="admin")
    return {"Authorization": f"Bearer {token}"}


async def test_customers_cannot_use_staff_routes(client, alice: User):
    await alice.tenant_id()
    for path in ["/admin/v1/overview", "/admin/v1/tenants", "/admin/v1/incidents"]:
        assert (await alice.request("GET", path)).status_code == 403, path
    assert (await client.get("/admin/v1/overview")).status_code == 401


async def test_unknown_roles_are_not_staff(client):
    token = console_token(str(uuid.uuid4()), "x@example.com", role="sales")
    r = await client.get("/admin/v1/overview", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403


async def test_staff_see_every_account(client, staff_headers, alice: User, bob: User):
    a, b = await alice.tenant_id(), await bob.tenant_id()
    host_a = await insert_host(a, "alice-web")
    await insert_host(b, "bob-db")

    overview = (await client.get("/admin/v1/overview", headers=staff_headers)).json()
    assert overview["tenants"] >= 2 and overview["hosts"] >= 2

    found = (
        await client.get("/admin/v1/tenants", params={"q": alice.email}, headers=staff_headers)
    ).json()
    assert [(t["email"], t["hosts"]) for t in found] == [(alice.email, 1)]

    hosts = (await client.get(f"/admin/v1/tenants/{a}/hosts", headers=staff_headers)).json()
    assert [h["hostname"] for h in hosts] == ["alice-web"]
    host = (await client.get(f"/admin/v1/hosts/{host_a}", headers=staff_headers)).json()
    assert host["hostname"] == "alice-web"


async def test_accounts_without_servers_are_hidden_by_default(client, staff_headers, alice: User):
    await alice.tenant_id()
    params = {"q": alice.email}
    assert (
        await client.get("/admin/v1/tenants", params=params, headers=staff_headers)
    ).json() == []
    params["with_hosts"] = "false"
    found = (await client.get("/admin/v1/tenants", params=params, headers=staff_headers)).json()
    assert [t["email"] for t in found] == [alice.email]


async def test_staff_routes_are_read_only(client, staff_headers, alice: User):
    host = await insert_host(await alice.tenant_id())
    for method, path in [
        ("DELETE", f"/admin/v1/hosts/{host}"),
        ("POST", "/admin/v1/tenants"),
        ("PUT", f"/admin/v1/hosts/{host}"),
    ]:
        r = await client.request(method, path, headers=staff_headers)
        assert r.status_code == 405, (method, path)


async def test_unknown_ids_are_404(client, staff_headers):
    missing = uuid.uuid4()
    for path in [f"/admin/v1/tenants/{missing}/hosts", f"/admin/v1/hosts/{missing}"]:
        assert (await client.get(path, headers=staff_headers)).status_code == 404


async def test_staff_see_processes_and_checks(client, staff_headers, alice: User):
    tid = await alice.tenant_id()
    host = await insert_host(tid)
    rule = {"name": "nginx", "kind": "service_down", "target": "nginx"}
    assert (await alice.request("POST", "/v1/alert-rules", json=rule)).status_code == 201
    for path in (f"/admin/v1/hosts/{host}/processes", f"/admin/v1/hosts/{host}/checks"):
        assert (await alice.request("GET", path)).status_code == 403, path
        r = await client.get(path, headers=staff_headers)
        assert r.status_code in (200, 503), (path, r.text)  # 503 only without VictoriaMetrics
    checks = (await client.get(f"/admin/v1/hosts/{host}/checks", headers=staff_headers)).json()
    assert [c["name"] for c in checks["checks"]] == ["nginx"]


async def test_staff_list_every_server_and_check(client, staff_headers, alice: User, bob: User):
    a, b = await alice.tenant_id(), await bob.tenant_id()
    await insert_host(a, "alice-web")
    await insert_host(b, "bob-db")
    body = {"name": "site", "type": "http", "target": "https://example.com", "on_probes": True}
    assert (await bob.request("POST", "/v1/checks", json=body)).status_code == 201
    hosts = (
        await client.get("/admin/v1/hosts", params={"q": alice.email}, headers=staff_headers)
    ).json()
    assert [(h["hostname"], h["account_email"]) for h in hosts] == [("alice-web", alice.email)]
    bobs = (
        await client.get("/admin/v1/hosts", params={"q": bob.email}, headers=staff_headers)
    ).json()
    assert [h["hostname"] for h in bobs] == ["bob-db"]
    checks = (await client.get("/admin/v1/checks", headers=staff_headers)).json()
    mine = [c for c in checks if c["account_email"] == bob.email]
    assert [(c["name"], c["status"]) for c in mine] == [("site", "pending")]
    for path in ("/admin/v1/hosts", "/admin/v1/checks"):
        assert (await alice.request("GET", path)).status_code == 403


async def test_staff_make_install_keys_for_an_account(client, staff_headers, alice: User):
    tid = await alice.tenant_id()
    r = await client.post(
        f"/admin/v1/tenants/{tid}/agent-keys",
        json={"name": "Web server", "tags": ["web"]},
        headers=staff_headers,
    )
    assert r.status_code == 201
    made = r.json()
    assert made["key"] in made["install_command"] and "web" in made["install_command"]
    assert made["name"] == "Web server (by support@Example.com)"
    # The customer sees it among their own keys and can revoke it.
    keys = (await alice.request("GET", "/v1/agent-keys")).json()
    assert [k["id"] for k in keys] == [made["id"]]
    missing = await client.post(
        f"/admin/v1/tenants/{uuid.uuid4()}/agent-keys", json={"name": "x"}, headers=staff_headers
    )
    assert missing.status_code == 404


async def test_staff_edit_pause_and_resume_a_server(client, staff_headers, alice: User):
    host = await insert_host(await alice.tenant_id(), "alice-web")
    body = {"tags": ["prod"], "notes": "Racked in DC2"}
    assert (await alice.request("PATCH", f"/admin/v1/hosts/{host}", json=body)).status_code == 403
    r = await client.patch(f"/admin/v1/hosts/{host}", json=body, headers=staff_headers)
    assert r.status_code == 200, r.text
    assert r.json()["tags"] == ["prod"] and r.json()["notes"] == "Racked in DC2"

    paused = (await client.post(f"/admin/v1/hosts/{host}/pause", headers=staff_headers)).json()
    assert paused["paused"] is True and paused["paused_by"]
    mine = (await alice.request("GET", f"/v1/hosts/{host}")).json()
    assert mine["paused"] is True and mine["tags"] == ["prod"]
    resumed = (await client.post(f"/admin/v1/hosts/{host}/resume", headers=staff_headers)).json()
    assert resumed["paused"] is False
    missing = uuid.uuid4()
    r = await client.post(f"/admin/v1/hosts/{missing}/pause", headers=staff_headers)
    assert r.status_code == 404
