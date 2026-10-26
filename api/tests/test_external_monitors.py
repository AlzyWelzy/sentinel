"""Uptime monitors from the console on Pulsegrid status pages."""

import uuid

from app.config import settings

from .conftest import User


def internal() -> dict:
    return {"X-Internal-Api-Key": settings.INTERNAL_API_KEY}


async def test_sync_and_show_on_a_status_page(client, alice: User, bob: User):
    await alice.tenant_id()  # the account exists once its owner has signed in
    monitors = {
        "source": "kuma",
        "monitors": [
            {
                "key": "kuma:12",
                "name": "Shop website",
                "kind": "http",
                "status": "up",
                "uptime_24h": 99.95,
                "response_ms": 182,
                "daily": [{"date": "2026-10-25", "uptime": 99.9}],
            },
            {"key": "kuma:13", "name": "API", "kind": "keyword", "status": "down"},
        ],
    }
    r = await client.put(
        f"/internal/v1/tenants/{alice.uid}/external-monitors", json=monitors, headers=internal()
    )
    assert r.status_code == 200, r.text
    listed = (await alice.request("GET", "/v1/external-monitors")).json()
    assert [m["key"] for m in listed] == ["kuma:13", "kuma:12"]  # by name: API, Shop website
    assert (await bob.request("GET", "/v1/external-monitors")).json() == []

    slug = f"shop-{uuid.uuid4().hex[:8]}"
    page = {
        "slug": slug,
        "title": "Shop status",
        "items": [
            {"label": "Website", "external_key": "kuma:12"},
            {"label": "API", "external_key": "kuma:13"},
        ],
    }
    assert (await alice.request("POST", "/v1/status-pages", json=page)).status_code == 201
    stolen = {**page, "slug": f"x-{uuid.uuid4().hex[:8]}"}
    assert (await bob.request("POST", "/v1/status-pages", json=stolen)).status_code == 422
    public = (await client.get(f"/public/status/{slug}")).json()
    assert [(i["label"], i["status"]) for i in public["items"]] == [
        ("Website", "up"),
        ("API", "down"),
    ]
    assert public["status"] == "degraded"  # one of two down
    assert public["items"][0]["response_ms"] == 182

    # A monitor gone from the console disappears.
    monitors["monitors"] = monitors["monitors"][:1]
    await client.put(
        f"/internal/v1/tenants/{alice.uid}/external-monitors", json=monitors, headers=internal()
    )
    assert [m["key"] for m in (await alice.request("GET", "/v1/external-monitors")).json()] == [
        "kuma:12"
    ]
    bad = {"source": "kuma", "monitors": [{"key": "other:1", "name": "x", "status": "up"}]}
    r = await client.put(
        f"/internal/v1/tenants/{alice.uid}/external-monitors", json=bad, headers=internal()
    )
    assert r.status_code == 422
