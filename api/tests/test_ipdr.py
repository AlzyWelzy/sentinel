# ruff: noqa: E501 -- request bodies read best on one line
"""IPDR: settings and roles, search with a reason and an audit row first,
one organisation never sees another's evidence, exports with a second
person's approval, and tampering shows up in the audit chain and the seals."""

import io
import json
import uuid
import zipfile
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import text

from app.config import settings
from app.db import ServiceSession
from app.services import ipdr

from .conftest import User, ensure_user, insert_host

CH = "http://localhost:8133"
CH_AUTH = ("sentinel", "sentinel")


def _ch_up() -> bool:
    try:
        r = httpx.get(
            f"{CH}/", params={"query": "EXISTS TABLE sentinel.fw_sessions"}, auth=CH_AUTH, timeout=2
        )
        return r.status_code == 200 and r.text.strip() == "1"
    except httpx.HTTPError:
        return False


pytestmark = pytest.mark.skipif(
    not _ch_up(), reason="ClickHouse with the evidence schema not running"
)


@pytest.fixture(autouse=True)
def clickhouse_settings(monkeypatch):
    monkeypatch.setattr(settings, "CLICKHOUSE_URL", CH)
    monkeypatch.setattr(settings, "CLICKHOUSE_USER", CH_AUTH[0])
    monkeypatch.setattr(settings, "CLICKHOUSE_PASSWORD", CH_AUTH[1])


def ch_insert(table: str, rows: list[dict]) -> None:
    body = "\n".join(json.dumps(r) for r in rows)
    httpx.post(
        f"{CH}/",
        params={"query": f"INSERT INTO sentinel.{table} FORMAT JSONEachRow"},
        content=body,
        auth=CH_AUTH,
    ).raise_for_status()


def now_str(delta: timedelta = timedelta()) -> str:
    return (datetime.now(UTC) + delta).strftime("%Y-%m-%d %H:%M:%S.000")


def session_row(
    tenant: uuid.UUID, src: str, dst: str, nat: str, user: str = "", at: str | None = None
) -> dict:
    return {
        "tenant_id": str(tenant), "received_at": at or now_str(), "expires": "2030-01-01",
        "event_time": at or now_str(), "source": "::ffff:192.0.2.1", "device_id": "", "devname": "FG",
        "action": "accept", "proto": 6, "src_ip": f"::ffff:{src}", "src_port": 51000,
        "dst_ip": f"::ffff:{dst}", "dst_port": 443, "nat_src_ip": f"::ffff:{nat}", "nat_src_port": 40000,
        "nat_dst_ip": "::", "user": user, "sent_bytes": 100, "rcvd_bytes": 900, "raw": "logid=1 type=traffic",
    }  # fmt: skip


async def member(owner: User, client, role: str) -> User:
    tid = await owner.tenant_id()
    uid = str(uuid.uuid4())
    email = f"{role}-{uid[:8]}@example.com"
    await ensure_user(uid, email)
    async with ServiceSession() as db, db.begin():
        await db.execute(
            text(
                "INSERT INTO tenant_members (tenant_id, email, role, user_id, joined_at)"
                " VALUES (:t, :e, :r, :u, now())"
            ),
            {"t": tid, "e": email, "r": role, "u": uid},
        )
    u = User(client, uid, email)
    u._created = True
    u.headers["X-Sentinel-Account"] = str(tid)
    return u


def window() -> dict:
    return {
        "start": (datetime.now(UTC) - timedelta(days=1)).isoformat(),
        "end": (datetime.now(UTC) + timedelta(minutes=1)).isoformat(),
    }


async def enable(owner: User) -> uuid.UUID:
    tid = await owner.tenant_id()
    host = await insert_host(tid, "collector")
    body = {
        "enabled": True,
        "retention_days": 400,
        "collector_host_id": str(host),
        "allow": ["10.20.0.0/24"],
    }
    r = await owner.request("PUT", "/v1/ipdr/settings", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] and r.json()["allow"] == ["10.20.0.0/24"]
    return tid


async def test_settings_and_roles(alice: User, bob: User, client):
    r = await alice.request(
        "PUT", "/v1/ipdr/settings", json={"enabled": True, "retention_days": 365}
    )
    assert r.status_code == 422 and "server" in r.text
    r = await alice.request(
        "PUT", "/v1/ipdr/settings",
        json={"enabled": False, "retention_days": 365, "allow": ["0.0.0.0/0"]},
    )  # fmt: skip
    assert r.status_code == 422 and "wider" in r.text
    tid = await enable(alice)
    # Bob's server can't be Alice's collector.
    bobs = await insert_host(await bob.tenant_id(), "bobs")
    r = await alice.request(
        "PUT", "/v1/ipdr/settings",
        json={"enabled": True, "retention_days": 365, "collector_host_id": str(bobs)},
    )  # fmt: skip
    assert r.status_code == 422
    viewer = await member(alice, client, "viewer")
    r = await viewer.request(
        "PUT", "/v1/ipdr/settings", json={"enabled": False, "retention_days": 365}
    )
    assert r.status_code == 403
    r = await viewer.request(
        "POST",
        "/v1/ipdr/search",
        json={"kind": "sessions", "reason": "looking", "ip": "1.1.1.1", **window()},
    )
    assert r.status_code == 403
    auditor = await member(alice, client, "auditor")
    assert (
        await auditor.request(
            "POST",
            "/v1/ipdr/search",
            json={"kind": "sessions", "reason": "looking", "ip": "1.1.1.1", **window()},
        )
    ).status_code == 403
    log = await auditor.request("GET", "/v1/ipdr/audit")
    assert log.status_code == 200 and log.json()[0]["action"] == "settings"
    # An investigator does member things, not admin things.
    inv = await member(alice, client, "investigator")
    assert (await inv.request("GET", "/v1/ipdr/audit")).status_code == 403
    assert (await inv.request("POST", "/v1/maintenance", json={})).status_code != 403
    assert (
        await inv.request(
            "PUT", "/v1/ipdr/settings", json={"enabled": False, "retention_days": 365}
        )
    ).status_code == 403
    assert tid


async def test_search_isolation_and_audit(alice: User, bob: User, client):
    tid = await enable(alice)
    bid = await bob.tenant_id()
    ch_insert("fw_sessions", [
        session_row(tid, "10.0.0.5", "93.184.216.34", "203.0.113.9", user="ada"),
        session_row(tid, "10.0.0.6", "1.1.1.1", "203.0.113.9"),
        session_row(bid, "10.0.0.5", "8.8.8.8", "198.51.100.1"),
    ])  # fmt: skip
    q = {"kind": "sessions", "reason": "case 42: abuse report", "ip": "203.0.113.9", **window()}
    r = await alice.request("POST", "/v1/ipdr/search", json=q)
    assert r.status_code == 200, r.text
    assert r.json()["total"] == 2 and {x["src_ip"] for x in r.json()["rows"]} == {
        "::ffff:10.0.0.5",
        "::ffff:10.0.0.6",
    }
    # Bob, with the same IP, sees only his.
    await enable(bob)
    r = await bob.request("POST", "/v1/ipdr/search", json={**q, "ip": "10.0.0.5"})
    assert r.json()["total"] == 1 and r.json()["rows"][0]["dst_ip"] == "::ffff:8.8.8.8"
    # By user, and the IP's history.
    r = await alice.request("POST", "/v1/ipdr/search", json={**q, "ip": None, "user": "ada"})
    assert r.json()["total"] == 1
    r = await alice.request(
        "POST",
        "/v1/ipdr/ip-history",
        json={"ip": "203.0.113.9", "reason": "case 42 history", **window()},
    )
    assert r.status_code == 200 and r.json()["rows"][0]["role"] == "nat"
    # Refused: no reason, no subject, too long a window, a port on syslog.
    assert (
        await alice.request("POST", "/v1/ipdr/search", json={**q, "reason": "x"})
    ).status_code == 422
    assert (
        await alice.request("POST", "/v1/ipdr/search", json={**q, "ip": None})
    ).status_code == 422
    long = {
        "start": (datetime.now(UTC) - timedelta(days=400)).isoformat(),
        "end": datetime.now(UTC).isoformat(),
    }
    assert (await alice.request("POST", "/v1/ipdr/search", json={**q, **long})).status_code == 422
    assert (
        await alice.request("POST", "/v1/ipdr/search", json={**q, "kind": "syslog", "port": 22})
    ).status_code == 422
    bad = await alice.request("POST", "/v1/ipdr/search", json={**q, "ip": "1.2.3.4' OR 1=1 --"})
    assert bad.status_code == 422
    # Every search is in the audit, with its reason, and the chain verifies.
    log = (await alice.request("GET", "/v1/ipdr/audit")).json()
    searches = [a for a in log if a["action"] == "search"]
    assert searches[-1]["reason"] == "case 42: abuse report" and searches[-1]["result_rows"] == 2
    v = await alice.request("POST", "/v1/ipdr/audit/verify")
    assert v.json()["ok"], v.json()
    # Tampering (a row edited by someone with database access) breaks it.
    import asyncpg

    # The table owner: beyond what the app's role may do.
    conn = await asyncpg.connect("postgresql://sentinel:sentinel@localhost:5442/sentinel")
    try:
        await conn.execute(
            "UPDATE ipdr_audit SET reason = 'nothing to see' WHERE tenant_id = $1 AND action = 'search'",
            tid,
        )
    finally:
        await conn.close()
    v = (await alice.request("POST", "/v1/ipdr/audit/verify")).json()
    assert not v["ok"] and v["broken_at"] is not None


async def test_api_tokens_and_staff_cant_search(alice: User, client):
    from .conftest import impersonate

    tid = await enable(alice)
    tok = await alice.request("POST", "/v1/api-tokens", json={"name": "ci"})
    token = tok.json()["token"]
    q = {"kind": "sessions", "reason": "automated lookup", "ip": "1.1.1.1", **window()}
    r = await client.post("/v1/ipdr/search", json=q, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
    staff = await impersonate(client, tid)
    r = await client.post("/v1/ipdr/search", json=q, headers=staff)
    assert r.status_code == 403


async def test_exports_and_approval(alice: User, client):
    tid = await enable(alice)
    ch_insert(
        "fw_sessions",
        [session_row(tid, f"10.9.0.{i}", "1.1.1.1", "203.0.113.50") for i in range(5)],
    )
    body = {"kind": "sessions", "reason": "court order 7", "ip": "203.0.113.50", **window()}
    r = await alice.request("POST", "/v1/ipdr/exports", json=body)
    assert r.status_code == 201 and r.json()["status"] == "ready", r.text
    ex = r.json()
    d = await alice.request("GET", f"/v1/ipdr/exports/{ex['id']}/download")
    assert d.status_code == 200 and d.headers["x-content-sha256"] == ex["sha256"]
    z = zipfile.ZipFile(io.BytesIO(d.content))
    man = json.loads(z.read("manifest.json"))
    assert man["rows"] == 5 and man["reason"] == "court order 7"
    import hashlib

    assert man["data_sha256"] == hashlib.sha256(z.read("data.csv")).hexdigest()
    # Above the threshold: pending until someone else approves.
    async with ServiceSession() as db, db.begin():
        await db.execute(
            text("UPDATE tenants SET ipdr_export_approval_rows = 1000 WHERE id = :t"), {"t": tid}
        )
    ch_insert(
        "fw_sessions",
        [session_row(tid, "10.8.0.1", "1.1.1.1", "203.0.113.60") for _ in range(1001)],
    )
    r = await alice.request("POST", "/v1/ipdr/exports", json={**body, "ip": "203.0.113.60"})
    big = r.json()
    assert big["status"] == "pending" and big["row_count"] == 1001
    assert (await alice.request("GET", f"/v1/ipdr/exports/{big['id']}/download")).status_code == 409
    own = await alice.request(
        "POST",
        f"/v1/ipdr/exports/{big['id']}/decision",
        json={"approve": True, "reason": "self approve"},
    )
    assert own.status_code == 403
    admin = await member(alice, client, "admin")
    inv = await member(alice, client, "investigator")
    assert (
        await inv.request(
            "POST",
            f"/v1/ipdr/exports/{big['id']}/decision",
            json={"approve": True, "reason": "looks fine"},
        )
    ).status_code == 403
    ok = await admin.request(
        "POST",
        f"/v1/ipdr/exports/{big['id']}/decision",
        json={"approve": True, "reason": "checked the order"},
    )
    assert ok.status_code == 200 and ok.json()["status"] == "ready", ok.text
    # The investigator didn't request it and isn't an approver: no download.
    assert (await inv.request("GET", f"/v1/ipdr/exports/{big['id']}/download")).status_code == 403
    actions = [a["action"] for a in (await alice.request("GET", "/v1/ipdr/audit")).json()]
    assert {"export_request", "export_approve", "export_download"} <= set(actions)


async def test_seals_detect_changes(alice: User):
    tid = await enable(alice)
    day = (datetime.now(UTC) - timedelta(days=3)).replace(hour=12)
    at = day.strftime("%Y-%m-%d %H:%M:%S.000")
    ch_insert(
        "fw_sessions",
        [session_row(tid, "10.7.0.1", "1.1.1.1", "203.0.113.70", at=at) for _ in range(3)],
    )
    async with ServiceSession() as db, db.begin():
        await db.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tid)})
        made = await ipdr.seal_day(db, tid, day.date())
        again = await ipdr.seal_day(db, tid, day.date())
    assert made == len(ipdr.SEALED_TABLES) and again == 0
    v = (await alice.request("POST", "/v1/ipdr/seals/verify", params={"days": 7})).json()
    fw = next(s for s in v if s["table"] == "fw_sessions")
    assert fw["rows"] == 3 and fw["chain_ok"] and fw["data_ok"]
    # Evidence slipped in afterwards for that day is caught.
    ch_insert("fw_sessions", [session_row(tid, "10.7.0.2", "1.1.1.1", "203.0.113.70", at=at)])
    v = (await alice.request("POST", "/v1/ipdr/seals/verify", params={"days": 7})).json()
    fw = next(s for s in v if s["table"] == "fw_sessions")
    assert fw["data_ok"] is False and fw["found_rows"] == 4
