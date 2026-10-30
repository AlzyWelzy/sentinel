"""CUSTOMERS_READ_ONLY, view-as-staff sessions and recommended rules for
every account."""

import uuid

import pytest

from app.config import settings

from .conftest import User, console_token, insert_host


def _staff(tenant_id=None, **extra) -> dict:
    token = console_token(str(uuid.uuid4()), "support@Example.com", role="admin", **extra)
    h = {"Authorization": f"Bearer {token}"}
    return {**h, "X-Pulsegrid-Account": str(tenant_id)} if tenant_id else h


@pytest.fixture
def read_only(monkeypatch):
    monkeypatch.setattr(settings, "CUSTOMERS_READ_ONLY", True)


async def test_customers_may_only_change_contacts(client, alice: User, read_only):
    assert (await alice.request("GET", "/v1/me")).json()["contacts_only"] is True
    r = await alice.request("POST", "/v1/agent-keys", json={"name": "x"})
    assert r.status_code == 403
    r = await alice.request("POST", "/v1/alert-rules/recommended")
    assert r.status_code == 403
    r = await alice.request(
        "POST", "/v1/channels", json={"type": "email", "target": "ops@example.com", "label": "Ops"}
    )
    assert r.status_code == 201
    assert (await alice.request("GET", "/v1/hosts")).status_code == 200


async def test_staff_still_change_customer_accounts(client, alice: User, read_only):
    tid = await alice.tenant_id()
    me = (await client.get("/v1/me", headers=_staff(tid))).json()
    assert me["role"] == "staff" and me["contacts_only"] is False
    r = await client.post("/v1/agent-keys", json={"name": "for alice"}, headers=_staff(tid))
    assert r.status_code == 201
    # Their own account too.
    r = await client.post("/v1/agent-keys", json={"name": "mine"}, headers=_staff())
    assert r.status_code == 201


async def test_off_by_default(client, alice: User):
    assert (await alice.request("GET", "/v1/me")).json()["contacts_only"] is False
    assert (await alice.request("POST", "/v1/agent-keys", json={"name": "x"})).status_code == 201


async def test_view_as_staff_reads_customer_accounts(client, alice: User):
    tid = await alice.tenant_id()
    await insert_host(tid, "alice-web")
    h = _staff(tid, imp="other-staff-uid")
    hosts = (await client.get("/v1/hosts", headers=h)).json()
    assert [x["hostname"] for x in hosts] == ["alice-web"]
    r = await client.post("/v1/agent-keys", json={"name": "x"}, headers=h)
    assert r.status_code == 403


async def test_recommended_rules_for_every_account(client, alice: User, bob: User):
    await alice.tenant_id()
    await bob.tenant_id()
    await alice.request("POST", "/v1/alert-rules/recommended")
    r = await client.post("/admin/v1/alert-rules/recommended", headers=_staff())
    assert r.status_code == 200
    body = r.json()
    assert body["accounts_changed"] >= 1 and body["rules_added"] >= 8
    names = [x["name"] for x in (await bob.request("GET", "/v1/alert-rules")).json()]
    assert "CPU above 90%" in names and len(names) == len(set(names))
    # Again: nothing new.
    again = (await client.post("/admin/v1/alert-rules/recommended", headers=_staff())).json()
    assert again["rules_added"] == 0


async def test_staff_install_key_adds_recommended_rules(client, alice: User):
    tid = await alice.tenant_id()
    r = await client.post(
        f"/admin/v1/tenants/{tid}/agent-keys", json={"name": "web"}, headers=_staff()
    )
    assert r.status_code == 201
    rules = (await alice.request("GET", "/v1/alert-rules")).json()
    assert "Server not reporting" in [x["name"] for x in rules]


async def test_console_provisioned_key_adds_recommended_rules(client, alice: User):
    r = await client.post(
        f"/internal/v1/tenants/{alice.uid}/agent-keys",
        json={"key_name": "vm", "email": alice.email},
        headers={"X-Internal-Api-Key": settings.INTERNAL_API_KEY},
    )
    assert r.status_code == 201, r.text
    rules = (await alice.request("GET", "/v1/alert-rules")).json()
    assert "CPU above 90%" in [x["name"] for x in rules]
