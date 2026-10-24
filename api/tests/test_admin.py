"""Staff view: read-only access across accounts, for console staff only."""

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
