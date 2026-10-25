from datetime import UTC, datetime, timedelta

from app.routes.statuspages import _cache

from .conftest import User, insert_host


async def _page(alice: User, slug: str, items=None) -> dict:
    r = await alice.request(
        "POST",
        "/v1/status-pages",
        json={"slug": slug, "title": "Acme status", "items": items or []},
    )
    assert r.status_code == 201, r.text
    return r.json()


async def test_announcements_lifecycle(alice: User, bob: User, client):
    page = await _page(alice, "acme-announce")
    url = f"/v1/status-pages/{page['id']}/updates"
    r = await alice.request(
        "POST",
        url,
        json={
            "kind": "incident",
            "state": "investigating",
            "title": "Checkout errors",
            "body": "Looking into it.",
        },
    )
    assert r.status_code == 201, r.text
    upd = r.json()
    pub = (await client.get("/public/status/acme-announce")).json()
    assert [a["title"] for a in pub["active"]] == ["Checkout errors"] and pub["history"] == []
    assert pub["status"] == "degraded"
    html = (await client.get("/status/acme-announce")).text
    assert "Checkout errors" in html and "Investigating" in html
    # Resolving moves it to history.
    r = await alice.request(
        "PUT",
        f"{url}/{upd['id']}",
        json={**upd, "state": "resolved", "body": "Fixed: a bad deploy."},
    )
    assert r.status_code == 200, r.text
    _cache.clear()
    pub = (await client.get("/public/status/acme-announce")).json()
    assert pub["active"] == [] and pub["history"][0]["state"] == "resolved"
    # Validation, isolation, delete.
    bad = {"kind": "incident", "state": "scheduled", "title": "x"}
    assert (await alice.request("POST", url, json=bad)).status_code == 422
    no_window = {"kind": "maintenance", "state": "scheduled", "title": "x"}
    assert (await alice.request("POST", url, json=no_window)).status_code == 422
    assert (await bob.request("GET", url)).status_code == 404
    assert (await alice.request("DELETE", f"{url}/{upd['id']}")).status_code == 204
    assert (await alice.request("GET", url)).json() == []


async def test_maintenance_windows_announce_themselves(alice: User, client):
    tid = await alice.tenant_id()
    host = await insert_host(tid, "web-1")
    await _page(alice, "acme-mw", items=[{"label": "Shop", "host_id": str(host)}])
    now = datetime.now(UTC)
    window = {
        "name": "upgrade",
        "host_id": str(host),
        "schedule": "once",
        "starts_at": (now - timedelta(minutes=5)).isoformat(),
        "ends_at": (now + timedelta(hours=1)).isoformat(),
    }
    assert (await alice.request("POST", "/v1/maintenance", json=window)).status_code == 201
    _cache.clear()
    pub = (await client.get("/public/status/acme-mw")).json()
    assert pub["active"][0]["title"] == "Planned maintenance: Shop"
    assert pub["active"][0]["state"] == "in_progress"
    assert "web-1" not in str(pub)  # labels only, never hostnames
