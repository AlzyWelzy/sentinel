"""Badges and own domains for status pages: badges show only what the page
shows, a domain is served (and gets a certificate) only once its TXT record
proves it, and one domain belongs to one page."""

import uuid

import httpx

from app.routes import statuspages

from .conftest import User, insert_host


async def page(user: User, **extra) -> dict:
    host = await insert_host(await user.tenant_id(), "web-1")
    slug = f"p-{uuid.uuid4().hex[:8]}"
    body = {"slug": slug, "title": "Acme", "items": [{"label": "API", "host_id": str(host)}]}
    r = await user.request("POST", "/v1/status-pages", json={**body, **extra})
    assert r.status_code == 201, r.text
    return r.json()


async def test_badges(alice: User, client: httpx.AsyncClient):
    p = await page(alice)
    item = p["items"][0]["id"]
    r = await client.get(f"/public/status/{p['slug']}/badge.svg")
    assert r.status_code == 200 and r.headers["content-type"].startswith("image/svg+xml")
    assert "Acme" in r.text and "<script" not in r.text
    r = await client.get(f"/public/status/{p['slug']}/badge.svg", params={"item": item})
    assert ">API<" in r.text and ("no data" in r.text or ">down<" in r.text or ">up<" in r.text)
    r = await client.get(
        f"/public/status/{p['slug']}/badge.svg",
        params={"item": item, "show": "uptime", "label": "<b>x</b>", "style": "for-the-badge"},
    )
    assert r.status_code == 200 and "<b>" not in r.text and "&lt;B&gt;" in r.text
    assert (
        await client.get(f"/public/status/{p['slug']}/badge.svg", params={"item": "nope"})
    ).status_code == 404
    assert (await client.get("/public/status/no-such-page/badge.svg")).status_code == 404
    # Values hidden on the page are hidden on the badge.
    hidden = await page(alice, show_values=False)
    r = await client.get(
        f"/public/status/{hidden['slug']}/badge.svg",
        params={"item": hidden["items"][0]["id"], "show": "response"},
    )
    assert "hidden" in r.text
    # An unpublished page has no badge.
    await alice.request(
        "PUT", f"/v1/status-pages/{hidden['id']}",
        json={"slug": hidden["slug"], "title": "Acme", "published": False, "items": []},
    )  # fmt: skip
    statuspages._cache.clear()
    assert (await client.get(f"/public/status/{hidden['slug']}/badge.svg")).status_code == 404


async def test_own_domain(alice: User, bob: User, client: httpx.AsyncClient, monkeypatch):
    records: dict[str, list[str]] = {}

    async def fake_txt(name: str) -> list[str]:
        return records.get(name, [])

    monkeypatch.setattr(statuspages, "txt_records", fake_txt)
    p = await page(alice)
    url = f"/v1/status-pages/{p['id']}/domain"
    for bad in ("localhost", "1.2.3.4", "a b.com", "sentinel.localhost.x/..", "-x.example.com"):
        r = await alice.request("PUT", url, json={"domain": bad})
        assert r.status_code == 422, (bad, r.text)
    r = await alice.request("PUT", url, json={"domain": "https://Status.Acme-Corp.com/"})
    assert r.status_code == 200, r.text
    d = r.json()["domain"]
    assert d["domain"] == "status.acme-corp.com" and not d["verified"]
    assert d["txt_name"] == "_sentinel.status.acme-corp.com"

    host = {"X-Status-Host": "status.acme-corp.com"}
    # Not verified: no certificate, no page.
    assert (
        await client.get("/public/domain-check", params={"domain": "status.acme-corp.com"})
    ).status_code == 404
    assert (await client.get("/public/host/", headers=host)).status_code == 404
    r = await alice.request("POST", f"{url}/verify")
    assert r.status_code == 422 and "TXT" in r.text

    records[d["txt_name"]] = ["unrelated", d["txt_value"]]
    r = await alice.request("POST", f"{url}/verify")
    assert r.status_code == 200 and r.json()["domain"]["verified"], r.text
    assert (
        await client.get("/public/domain-check", params={"domain": "Status.Acme-Corp.com"})
    ).status_code == 200
    r = await client.get("/public/host/", headers=host)
    assert r.status_code == 200 and "Acme" in r.text
    r = await client.get("/public/host/badge.svg", headers=host)
    assert r.headers["content-type"].startswith("image/svg+xml")
    r = await client.get("/public/host/status.json", headers=host)
    assert r.json()["title"] == "Acme"
    assert (await client.get("/public/host/../admin", headers=host)).status_code == 404

    # Bob can set the same domain but never verify it while Alice has it.
    q = await page(bob)
    burl = f"/v1/status-pages/{q['id']}/domain"
    r = await bob.request("PUT", burl, json={"domain": "status.acme-corp.com"})
    assert r.status_code == 200
    records[r.json()["domain"]["txt_name"]].append(r.json()["domain"]["txt_value"])
    r = await bob.request("POST", f"{burl}/verify")
    assert r.status_code == 409, r.text
    # Nor touch Alice's page.
    assert (await bob.request("PUT", url, json={"domain": None})).status_code == 404

    # Changing the domain starts over; clearing it stops serving.
    r = await alice.request("PUT", url, json={"domain": None})
    assert r.status_code == 200 and r.json()["domain"] is None
    assert (
        await client.get("/public/domain-check", params={"domain": "status.acme-corp.com"})
    ).status_code == 404


async def test_own_domain_needs_cloudflare_behind_a_tunnel(alice: User, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "STATUS_DOMAIN_TARGET", "customers.example.net")
    monkeypatch.setattr(settings, "CF_API_TOKEN", "")
    p = await page(alice)
    r = await alice.request(
        "PUT", f"/v1/status-pages/{p['id']}/domain", json={"domain": "status.acme.io"}
    )
    assert r.status_code == 200 and r.json()["domain"]["cname"] == "customers.example.net"
    r = await alice.request("POST", f"/v1/status-pages/{p['id']}/domain/verify")
    assert r.status_code == 503
