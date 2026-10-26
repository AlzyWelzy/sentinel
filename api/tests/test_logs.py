"""Log search: LogsQL built from validated parts; VictoriaLogs accounts keep
tenants apart."""

import asyncio
import json
import uuid
from datetime import UTC, datetime
from typing import cast

import httpx
import pytest
from sqlalchemy import text

from app.config import settings
from app.db import ServiceSession
from app.services.logs import BadQuery, LogFilter, build_query, escape

from .conftest import User, insert_host

H = uuid.UUID("11111111-2222-3333-4444-555555555555")
VLOGS = "http://localhost:9428"


def test_build_query():
    assert build_query(LogFilter(host_ids=[H])) == f'{{host_id=~"{H}"}}'
    q = build_query(
        LogFilter(host_ids=[H], text='a"b} | json', source="/var/log/x.log", levels=("error",))
    )
    assert q.startswith(f'{{host_id=~"{H}"}} source:="/var/log/x.log" level:in(error) _msg:~')
    # The text is escaped into one string literal: no way out of it.
    assert q.endswith(r'_msg:~"(?i)a\"b\\} \\| json"')
    assert build_query(LogFilter(host_ids=[H], text="err(or)?", regex=True)).endswith(
        '_msg:~"err(or)?"'
    )
    assert escape("a.b (c) d") == r"a\.b \(c\) d"  # spaces stay as they are (RE2)
    with pytest.raises(BadQuery):
        build_query(LogFilter(host_ids=[H], text="(", regex=True))
    with pytest.raises(BadQuery):
        build_query(LogFilter(host_ids=[H], levels=("error) or (",)))
    with pytest.raises(ValueError):
        build_query(LogFilter(host_ids=cast(list[uuid.UUID], ['x"} or {a=~".+']), text="x"))


async def test_disabled_without_victorialogs(alice: User, monkeypatch):
    monkeypatch.setattr(settings, "VICTORIALOGS_URL", "")
    body = (await alice.request("GET", "/v1/logs")).json()
    assert body == {"enabled": False, "lines": [], "limit": 200}


def vlogs_up() -> bool:
    try:
        return httpx.get(f"{VLOGS}/health", timeout=2).status_code == 200
    except httpx.HTTPError:
        return False


async def account_of(tenant_id) -> int:
    async with ServiceSession() as db:
        return (
            await db.execute(
                text("SELECT logs_account_id FROM tenants WHERE id = :t"), {"t": tenant_id}
            )
        ).scalar_one()


async def push(tenant_id, host_id, line, level="error", source="/var/log/app.log"):
    row = {
        "_time": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "_msg": line,
        "host_id": str(host_id),
        "source": source,
        "level": level,
    }
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{VLOGS}/insert/jsonline?_stream_fields=host_id,source,level",
            headers={
                "AccountID": str(await account_of(tenant_id)),
                "Content-Type": "application/stream+json",
            },
            content=json.dumps(row) + "\n",
        )
    assert r.status_code == 200, r.text


@pytest.mark.skipif(not vlogs_up(), reason="needs VictoriaLogs on localhost:9428")
async def test_search_is_per_account(alice: User, bob: User, monkeypatch):
    monkeypatch.setattr(settings, "VICTORIALOGS_URL", VLOGS)
    a_tid, b_tid = await alice.tenant_id(), await bob.tenant_id()
    a_host = await insert_host(a_tid, "alice-web")
    b_host = await insert_host(b_tid, "bob-web")
    marker = uuid.uuid4().hex
    await push(a_tid, a_host, f"ERROR alice {marker} payment failed")
    await push(a_tid, a_host, f"INFO alice {marker} ok", level="info")
    # Bob's line even claims Alice's host id: it's still in Bob's account.
    await push(b_tid, a_host, f"ERROR bob {marker} secret")
    await push(b_tid, b_host, f"ERROR bob {marker} secret 2")

    found = []
    for _ in range(60):  # pushes become searchable within a moment
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

    # Live tail: only what's newer than the last line already shown.
    newest = max(line["ts"] for line in found)
    await push(a_tid, a_host, f"ERROR alice {marker} after")
    tail = []
    for _ in range(60):
        r = await alice.request("GET", "/v1/logs", params={"q": marker, "after": newest})
        tail = r.json()["lines"]
        if tail:
            break
        await asyncio.sleep(0.5)
    assert [line["line"].split()[-1] for line in tail] == ["after"]


async def test_saved_views(alice: User, bob: User):
    body = {
        "kind": "logs",
        "name": "Payment errors",
        "params": {"q": "payment", "level": ["error"]},
    }
    r = await alice.request("POST", "/v1/saved-views", json=body)
    assert r.status_code == 201, r.text
    view = r.json()
    assert view["created_by"] == alice.email
    assert (await alice.request("POST", "/v1/saved-views", json=body)).status_code == 409
    listed = (await alice.request("GET", "/v1/saved-views", params={"kind": "logs"})).json()
    assert [v["name"] for v in listed] == ["Payment errors"]
    assert (await bob.request("GET", "/v1/saved-views")).json() == []
    assert (await bob.request("DELETE", f"/v1/saved-views/{view['id']}")).status_code == 404
    renamed = await alice.request(
        "PUT", f"/v1/saved-views/{view['id']}", json={**body, "name": "Payments"}
    )
    assert renamed.json()["name"] == "Payments"
    assert (await alice.request("DELETE", f"/v1/saved-views/{view['id']}")).status_code == 204


async def test_log_rules(alice: User):
    bad = await alice.request("POST", "/v1/alert-rules", json={"name": "x", "kind": "logs"})
    assert bad.status_code == 422
    body = {
        "name": "Payment errors",
        "kind": "logs",
        "threshold": 5,
        "window_seconds": 600,
        "duration_seconds": 0,
        "log_filter": {"q": "payment failed", "levels": ["error"]},
    }
    r = await alice.request("POST", "/v1/alert-rules", json=body)
    assert r.status_code == 201, r.text
    rule = r.json()
    assert rule["target"] == 'level:in(error) _msg:~"(?i)payment failed"'
    assert rule["log_filter"]["q"] == "payment failed" and rule["operator"] == ">"
    regex = {**body, "log_filter": {"q": "(", "regex": True}}
    assert (await alice.request("POST", "/v1/alert-rules", json=regex)).status_code == 422


@pytest.mark.skipif(not vlogs_up(), reason="needs VictoriaLogs on localhost:9428")
async def test_log_rule_preview(alice: User, monkeypatch):
    monkeypatch.setattr(settings, "VICTORIALOGS_URL", VLOGS)
    tid = await alice.tenant_id()
    host = await insert_host(tid, "pay-1")
    marker = uuid.uuid4().hex
    for _ in range(3):
        await push(tid, host, f"ERROR {marker} payment failed")
    body = {
        "name": "Payment errors",
        "kind": "logs",
        "threshold": 2,
        "window_seconds": 300,
        "duration_seconds": 0,
        "log_filter": {"q": marker, "levels": ["error"]},
    }
    preview = {}
    for _ in range(60):
        preview = (await alice.request("POST", "/v1/alert-rules/preview", json=body)).json()
        if preview.get("fires"):
            break
        await asyncio.sleep(0.5)
    assert preview["fires"] == 1
    assert preview["hosts"][0]["hostname"] == "pay-1"
