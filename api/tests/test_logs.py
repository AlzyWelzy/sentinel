"""Log search: LogQL built from validated parts; Loki tenants keep accounts apart."""

import asyncio
import time
import uuid

import httpx
import pytest

from app.config import settings
from app.services.logs import BadQuery, LogFilter, build_query

from .conftest import User, insert_host

H = uuid.UUID("11111111-2222-3333-4444-555555555555")
LOKI = "http://localhost:3100"


def test_build_query():
    assert build_query(LogFilter(host_ids=[H])) == f'{{host_id=~"{H}"}}'
    q = build_query(
        LogFilter(host_ids=[H], text='a"b} | json', source="/var/log/x.log", levels=("error",))
    )
    assert q.startswith(f'{{host_id=~"{H}", source="/var/log/x.log", level=~"error"}} |~ ')
    # The text is escaped into one string literal: no way out of it.
    assert q.endswith(r'|~ "(?i)a\"b\\}\\ \\|\\ json"')
    assert build_query(LogFilter(host_ids=[H], text="err(or)?", regex=True)).endswith(
        '|~ "err(or)?"'
    )
    with pytest.raises(BadQuery):
        build_query(LogFilter(host_ids=[H], text="(", regex=True))
    with pytest.raises(BadQuery):
        build_query(LogFilter(host_ids=[H], levels=('error"}',)))
    with pytest.raises(ValueError):
        build_query(LogFilter(host_ids=['x"} or {a=~".+'], text="x"))  # type: ignore[list-item]


async def test_disabled_without_loki(alice: User, monkeypatch):
    monkeypatch.setattr(settings, "LOKI_URL", "")
    body = (await alice.request("GET", "/v1/logs")).json()
    assert body == {"enabled": False, "lines": [], "limit": 200}


def loki_up() -> bool:
    try:
        return httpx.get(f"{LOKI}/ready", timeout=2).status_code == 200
    except httpx.HTTPError:
        return False


async def push(tenant_id, host_id, line, level="error", source="/var/log/app.log"):
    now = time.time_ns()
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{LOKI}/loki/api/v1/push",
            headers={"X-Scope-OrgID": str(tenant_id)},
            json={
                "streams": [
                    {
                        "stream": {"host_id": str(host_id), "source": source, "level": level},
                        "values": [[str(now), line]],
                    }
                ]
            },
        )
    assert r.status_code == 204, r.text


@pytest.mark.skipif(not loki_up(), reason="needs Loki on localhost:3100")
async def test_search_is_per_account(alice: User, bob: User, monkeypatch):
    monkeypatch.setattr(settings, "LOKI_URL", LOKI)
    a_tid, b_tid = await alice.tenant_id(), await bob.tenant_id()
    a_host = await insert_host(a_tid, "alice-web")
    b_host = await insert_host(b_tid, "bob-web")
    marker = uuid.uuid4().hex
    await push(a_tid, a_host, f"ERROR alice {marker} payment failed")
    await push(a_tid, a_host, f"INFO alice {marker} ok", level="info")
    # Bob's line even claims Alice's host id: it's still in Bob's Loki tenant.
    await push(b_tid, a_host, f"ERROR bob {marker} secret")
    await push(b_tid, b_host, f"ERROR bob {marker} secret 2")

    found = []
    for _ in range(20):  # Loki makes pushes queryable within a moment
        r = await alice.request("GET", "/v1/logs", params={"q": marker})
        found = r.json()["lines"]
        if len(found) >= 2:
            break
        await asyncio.sleep(0.5)
    assert {line["line"].split()[1] for line in found} == {"alice"}
    assert found[0]["hostname"] == "alice-web"

    errors = await alice.request("GET", "/v1/logs", params={"q": marker, "level": "error"})
    assert [line["level"] for line in errors.json()["lines"]] == ["error"]
    upper = await alice.request("GET", "/v1/logs", params={"q": "PAYMENT FAILED"})
    assert any(marker in line["line"] for line in upper.json()["lines"])

    bob_lines = (await bob.request("GET", "/v1/logs", params={"q": marker})).json()["lines"]
    assert bob_lines and all("bob" in line["line"] for line in bob_lines)
    # Bob can't point at Alice's host.
    r = await bob.request("GET", "/v1/logs", params={"host_id": str(a_host)})
    assert r.status_code == 404

    sources = (await alice.request("GET", "/v1/logs/sources")).json()
    assert "/var/log/app.log" in sources
    volume = (await alice.request("GET", "/v1/logs/volume", params={"q": marker})).json()
    assert {s["level"] for s in volume} == {"error", "info"}

    bad = await alice.request("GET", "/v1/logs", params={"q": "(", "regex": "true"})
    assert bad.status_code == 400
