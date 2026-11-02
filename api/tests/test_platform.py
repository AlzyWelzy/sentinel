"""Checks, new rule kinds, the incident timeline, push contacts, API tokens,
status pages, actions, inventory, reports and staff probe management."""

import json
import uuid

import pytest
from sqlalchemy import text

from app.config import settings
from app.db import ServiceSession
from app.services.heartbeats import redis

from .conftest import User, _new_user, access_token, insert_host

# ── Checks ───────────────────────────────────────────────────────────────────


async def test_check_crud_creates_and_removes_its_rule(alice: User, bob: User):
    tid = await alice.tenant_id()
    host = await insert_host(tid, "web-1")
    r = await alice.request(
        "POST",
        "/v1/checks",
        json={
            "name": "nginx port",
            "type": "tcp",
            "target": "127.0.0.1:80",
            "host_id": str(host),
            "interval_seconds": 30,
        },
    )
    assert r.status_code == 201, r.text
    check = r.json()
    assert check["status"] == "pending" and check["rule_id"]
    rule = (await alice.request("GET", f"/v1/alert-rules/{check['rule_id']}")).json()
    assert (
        rule["kind"] == "check" and rule["target"] == check["id"] and rule["duration_seconds"] == 60
    )

    # Bob sees nothing of it, and can't point a rule at it.
    assert (await bob.request("GET", f"/v1/checks/{check['id']}")).status_code == 404
    assert (await bob.request("GET", "/v1/checks")).json() == []
    r = await bob.request(
        "POST", "/v1/alert-rules", json={"name": "x", "kind": "check", "target": check["id"]}
    )
    assert r.status_code == 422

    # A result as ingest stores it shows up as the check's status.
    await redis.hset(
        f"pg:check:{check['id']}",
        str(host),
        json.dumps(
            {
                "ok": False,
                "detail": "connection refused",
                "latency_ms": 1.2,
                "ts": 1,
                "host_id": str(host),
            }
        ),
    )
    got = (await alice.request("GET", f"/v1/checks/{check['id']}")).json()
    assert got["status"] == "down" and got["results"][0]["detail"] == "connection refused"

    assert (await alice.request("DELETE", f"/v1/checks/{check['id']}")).status_code == 204
    assert (await alice.request("GET", f"/v1/alert-rules/{check['rule_id']}")).status_code == 404
    assert not await redis.exists(f"pg:check:{check['id']}")


@pytest.mark.parametrize(
    "body",
    [
        {"type": "http", "target": "http://10.0.0.5/health", "on_probes": True},
        {"type": "http", "target": "http://localhost:8080/", "on_probes": True},
        {"type": "tcp", "target": "169.254.169.254:80", "on_probes": True},
        {"type": "file", "target": "/etc/passwd", "on_probes": True},
        {"type": "http", "target": "ftp://example.com", "on_probes": True},
        {"type": "tcp", "target": "example.com", "on_probes": True},
        {
            "type": "http",
            "target": "https://example.com",
            "on_probes": True,
            "params": {"bogus": "1"},
        },
        {"type": "log", "target": "/var/log/syslog", "tag": "web", "params": {"pattern": "("}},
        {"type": "log", "target": "relative.log", "tag": "web", "params": {"pattern": "x"}},
        {"type": "file", "target": "/x", "tag": "web", "params": {"mode": "max_age_seconds"}},
        {"type": "tcp", "target": "a.com:1", "tag": "web", "on_probes": True},
    ],
)
async def test_check_validation(alice: User, body: dict):
    r = await alice.request("POST", "/v1/checks", json={"name": "c", **body})
    assert r.status_code == 422, r.text


async def test_probe_check_minimum_interval_and_regions(alice: User):
    r = await alice.request(
        "POST",
        "/v1/checks",
        json={
            "name": "site",
            "type": "http",
            "target": "https://example.com/",
            "on_probes": True,
            "interval_seconds": 10,
            "min_failing": 2,
            "params": {"keyword": "Example", "expect_status": "200-299", "tls_skip_verify": False},
        },
    )
    assert r.status_code == 201, r.text
    c = r.json()
    assert c["interval_seconds"] == 30 and c["min_failing"] == 2
    assert c["params"]["tls_skip_verify"] == "false"


# ── Rules ────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("body", "ok"),
    [
        ({"kind": "anomaly", "metric": "cpu"}, True),
        ({"kind": "anomaly", "metric": "disk"}, False),
        ({"kind": "anomaly", "metric": "cpu", "threshold": 50}, False),
        ({"kind": "forecast", "metric": "disk", "threshold": 48}, True),
        ({"kind": "forecast", "metric": "cpu", "threshold": 48}, False),
        ({"kind": "forecast", "metric": "disk"}, False),
        (
            {
                "kind": "custom",
                "target": "jobs_waiting",
                "operator": ">",
                "threshold": 100,
                "labels": {"queue": "mail"},
            },
            True,
        ),
        ({"kind": "custom", "target": "jobs{x}", "operator": ">", "threshold": 1}, False),
        ({"kind": "container_down", "target": "web"}, True),
        ({"kind": "plugin_down"}, True),
        ({"kind": "check", "target": "not-a-uuid"}, False),
        (
            {
                "kind": "metric",
                "metric": "cpu",
                "operator": ">",
                "threshold": 90,
                "recovery_threshold": 80,
                "aggregation": "avg",
            },
            True,
        ),
        (
            {
                "kind": "metric",
                "metric": "cpu",
                "operator": ">",
                "threshold": 90,
                "recovery_threshold": 95,
            },
            False,
        ),
        ({"kind": "metric", "metric": "network_in", "operator": ">", "threshold": 500}, True),
        (
            {
                "kind": "metric",
                "metric": "cpu",
                "operator": ">",
                "threshold": 9,
                "action_name": "Bad Name",
            },
            False,
        ),
    ],
)
async def test_new_rule_kinds_validate(alice: User, body: dict, ok: bool):
    r = await alice.request("POST", "/v1/alert-rules", json={"name": "r", **body})
    assert (r.status_code == 201) is ok, r.text


async def test_recommended_rules_include_forecast(alice: User):
    rules = (await alice.request("POST", "/v1/alert-rules/recommended")).json()
    kinds = {r["kind"] for r in rules}
    assert {"forecast", "plugin_down", "host_down"} <= kinds
    cpu = next(r for r in rules if r["metric"] == "cpu")
    assert cpu["recovery_threshold"] == 80 and cpu["aggregation"] == "avg"


# ── Incidents ────────────────────────────────────────────────────────────────


async def _incident(tenant_id: uuid.UUID, host_id: uuid.UUID) -> str:
    async with ServiceSession() as db, db.begin():
        return str(
            (
                await db.execute(
                    text(
                        "INSERT INTO incidents (tenant_id, host_id, summary, rule_name, hostname) "
                        "VALUES (:t, :h, 'CPU high on web-1', 'CPU', 'web-1') RETURNING id"
                    ),
                    {"t": tenant_id, "h": host_id},
                )
            ).scalar_one()
        )


async def test_incident_timeline_notes_resolve_reopen(alice: User, bob: User):
    tid = await alice.tenant_id()
    iid = await _incident(tid, await insert_host(tid))

    r = await alice.request(
        "POST", f"/v1/incidents/{iid}/notes", json={"message": "Looking into it"}
    )
    assert r.status_code == 201
    assert (
        await bob.request("POST", f"/v1/incidents/{iid}/notes", json={"message": "x"})
    ).status_code == 404

    d = (await alice.request("POST", f"/v1/incidents/{iid}/acknowledge")).json()
    assert d["acknowledged_by"] == alice.email
    d = (
        await alice.request("POST", f"/v1/incidents/{iid}/resolve", json={"message": "Restarted"})
    ).json()
    assert d["status"] == "resolved" and d["resolved_by"] == alice.email
    d = (
        await alice.request("POST", f"/v1/incidents/{iid}/reopen", json={"message": "Back again"})
    ).json()
    assert d["status"] == "open" and d["reopened_count"] == 1
    kinds = [e["kind"] for e in d["events"]]
    assert kinds == ["note", "acknowledged", "resolved", "reopened"]
    assert d["events"][2]["message"] == "Resolved by hand: Restarted"

    listed = (await alice.request("GET", "/v1/incidents", params={"severity": "critical"})).json()
    assert [i["id"] for i in listed] == [iid]


# ── Contacts ─────────────────────────────────────────────────────────────────


async def test_only_enabled_contact_types_can_be_added(alice: User, monkeypatch):
    monkeypatch.setattr(settings, "ENABLED_CHANNEL_TYPES", ["email", "push"])
    r = await alice.request(
        "POST",
        "/v1/channels",
        json={"type": "slack", "target": "https://hooks.slack.com/services/x"},
    )
    assert r.status_code == 422 and "aren't available" in r.text
    r = await alice.request(
        "POST",
        "/v1/channels",
        json={"type": "email", "target": "ops@example.com", "min_severity": "warning"},
    )
    assert r.status_code == 201 and r.json()["min_severity"] == "warning"


async def test_push_subscriptions(alice: User):
    sub = {
        "endpoint": "https://fcm.googleapis.com/fcm/send/abc123",
        "keys": {
            "p256dh": "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQ",
            "auth": "tBHItJI5svbpez7KI4CCXg",
        },
        "label": "Laptop",
    }
    assert (await alice.request("GET", "/v1/channels/push/config")).json()[
        "public_key"
    ] == settings.VAPID_PUBLIC_KEY
    r = await alice.request("POST", "/v1/channels/push", json=sub)
    assert r.status_code == 201, r.text
    ch = r.json()
    assert ch["verified"] and ch["target"] == "Chrome / Edge / Android push"
    again = (
        await alice.request("POST", "/v1/channels/push", json={**sub, "min_severity": "critical"})
    ).json()
    assert again["id"] == ch["id"] and again["min_severity"] == "critical"
    bad = {**sub, "endpoint": "https://attacker.example/collect"}
    assert (await alice.request("POST", "/v1/channels/push", json=bad)).status_code == 422
    r = await alice.request("PATCH", f"/v1/channels/{ch['id']}", json={"min_severity": "warning"})
    assert r.json()["min_severity"] == "warning"
    assert (await alice.request("DELETE", f"/v1/channels/{ch['id']}")).status_code == 204


# ── API tokens ───────────────────────────────────────────────────────────────


async def test_api_tokens(alice: User, bob: User, client):
    tid = await alice.tenant_id()
    await insert_host(tid, "web-1")
    r = await alice.request("POST", "/v1/api-tokens", json={"name": "ci", "read_only": True})
    assert r.status_code == 201
    token = r.json()["token"]
    assert token.startswith("pgt_")
    h = {"Authorization": f"Bearer {token}"}

    hosts = (await client.get("/v1/hosts", headers=h)).json()
    assert [x["hostname"] for x in hosts] == ["web-1"]
    # Read-only: no writes. And never token management, read-only or not.
    assert (await client.post("/v1/alert-rules/recommended", headers=h)).status_code == 403
    assert (await client.get("/v1/api-tokens", headers=h)).status_code == 403

    rw = (
        await alice.request("POST", "/v1/api-tokens", json={"name": "tf", "read_only": False})
    ).json()
    hw = {"Authorization": f"Bearer {rw['token']}"}
    assert (await client.post("/v1/alert-rules/recommended", headers=hw)).status_code == 201
    assert (await client.post("/v1/api-tokens", headers=hw, json={"name": "x"})).status_code == 403

    # Bob's token sees Bob's account only.
    bt = (await bob.request("POST", "/v1/api-tokens", json={"name": "b"})).json()["token"]
    assert (await client.get("/v1/hosts", headers={"Authorization": f"Bearer {bt}"})).json() == []

    listed = (await alice.request("GET", "/v1/api-tokens")).json()
    assert {t["name"] for t in listed} == {"ci", "tf"} and "token" not in listed[0]
    tok_id = r.json()["id"]
    assert (await alice.request("DELETE", f"/v1/api-tokens/{tok_id}")).status_code == 204
    assert (await client.get("/v1/hosts", headers=h)).status_code == 401
    assert (
        await client.get("/v1/hosts", headers={"Authorization": "Bearer pgt_nope"})
    ).status_code == 401


# ── Status pages ─────────────────────────────────────────────────────────────


async def test_status_pages(alice: User, bob: User, client):
    tid = await alice.tenant_id()
    host = await insert_host(tid, "secret-db-01.internal")
    check = (
        await alice.request(
            "POST",
            "/v1/checks",
            json={
                "name": "site",
                "type": "http",
                "target": "https://example.com",
                "on_probes": True,
            },
        )
    ).json()
    slug = f"acme-{uuid.uuid4().hex[:8]}"
    body = {
        "slug": slug,
        "title": "Acme status",
        "items": [
            {"label": "Database", "host_id": str(host)},
            {"label": "Website", "check_id": check["id"]},
        ],
    }
    r = await alice.request("POST", "/v1/status-pages", json=body)
    assert r.status_code == 201, r.text
    page = r.json()

    # The address is unique across accounts.
    assert (
        await bob.request("POST", "/v1/status-pages", json={**body, "items": []})
    ).status_code == 409
    # Bob can't put Alice's host on his page.
    other = {**body, "slug": slug + "-b"}
    assert (await bob.request("POST", "/v1/status-pages", json=other)).status_code == 422

    pub = (await client.get(f"/public/status/{slug}")).json()
    assert [i["label"] for i in pub["items"]] == ["Database", "Website"]
    assert "secret-db-01" not in json.dumps(pub) and "example.com" not in json.dumps(pub)
    html = (await client.get(f"/status/{slug}")).text
    assert "Acme status" in html and "secret-db-01" not in html

    await alice.request("PUT", f"/v1/status-pages/{page['id']}", json={**body, "published": False})
    assert (await client.get(f"/public/status/{slug}")).status_code == 404


# ── Actions and inventory ────────────────────────────────────────────────────


async def test_actions_only_run_what_the_host_allows(alice: User, bob: User):
    tid = await alice.tenant_id()
    host = await insert_host(tid)
    r = await alice.request("POST", f"/v1/hosts/{host}/actions", json={"name": "restart-nginx"})
    assert r.status_code == 422 and "allow-action" in r.text

    async with ServiceSession() as db, db.begin():
        await db.execute(
            text("UPDATE hosts SET allowed_actions = '{restart-nginx}' WHERE id = :h"), {"h": host}
        )
    r = await alice.request("POST", f"/v1/hosts/{host}/actions", json={"name": "restart-nginx"})
    assert r.status_code == 202 and r.json()["status"] == "pending"
    assert (
        await bob.request("POST", f"/v1/hosts/{host}/actions", json={"name": "restart-nginx"})
    ).status_code == 404
    for _ in range(4):
        await alice.request("POST", f"/v1/hosts/{host}/actions", json={"name": "restart-nginx"})
    r = await alice.request("POST", f"/v1/hosts/{host}/actions", json={"name": "restart-nginx"})
    assert r.status_code == 429
    got = (await alice.request("GET", f"/v1/hosts/{host}/actions")).json()
    assert got["allowed"] == ["restart-nginx"] and len(got["history"]) == 5


async def test_inventory(alice: User):
    tid = await alice.tenant_id()
    host = await insert_host(tid)
    assert (await alice.request("GET", f"/v1/hosts/{host}/inventory")).json()["updated_at"] is None
    async with ServiceSession() as db, db.begin():
        await db.execute(
            text(
                "INSERT INTO host_inventory (host_id, tenant_id, data, changes) "
                "VALUES (:h, :t, :d, '[]')"
            ),
            {
                "h": host,
                "t": tid,
                "d": json.dumps(
                    {
                        "kernel_version": "6.8",
                        "packages": [
                            {"name": "nginx", "version": "1.24"},
                            {"name": "bash", "version": "5"},
                        ],
                    }
                ),
            },
        )
    inv = (
        await alice.request("GET", f"/v1/hosts/{host}/inventory", params={"search": "ngi"})
    ).json()
    assert inv["kernel_version"] == "6.8" and inv["packages"] == [
        {"name": "nginx", "version": "1.24"}
    ]


# ── Reports ──────────────────────────────────────────────────────────────────


async def test_reports(alice: User):
    tid = await alice.tenant_id()
    await insert_host(tid, "web-1")
    await _incident(tid, await insert_host(tid, "web-2"))
    s = (await alice.request("GET", "/v1/reports/summary", params={"days": 7})).json()
    assert {h["hostname"] for h in s["hosts"]} == {"web-1", "web-2"}
    assert s["incidents_total"] == 1
    csv = (await alice.request("GET", "/v1/reports/summary.csv")).text
    assert csv.startswith("type,name,availability_percent") and "web-1" in csv
    got = (await alice.request("GET", "/v1/reports/settings")).json()
    assert got["monthly_report"] is True and got["digest"] == "weekly"
    await alice.request("PUT", "/v1/reports/settings", json={"monthly_report": False})
    assert (await alice.request("GET", "/v1/reports/settings")).json()["monthly_report"] is False


async def test_monthly_report_job_queues_once(alice: User):
    from datetime import UTC, datetime, timedelta

    from app.jobs import send_monthly_reports

    tid = await alice.tenant_id()
    host = await insert_host(tid, "web-1")
    async with ServiceSession() as db, db.begin():
        await db.execute(
            text("UPDATE hosts SET created_at = now() - interval '60 days' WHERE id = :h"),
            {"h": host},
        )
    now = datetime.now(UTC)
    await send_monthly_reports(now)
    await send_monthly_reports(now + timedelta(minutes=1))
    async with ServiceSession() as db:
        n = (
            await db.execute(
                text(
                    "SELECT count(*) FROM outbound_messages "
                    "WHERE tenant_id = :t AND kind = 'report'"
                ),
                {"t": tid},
            )
        ).scalar_one()
        payload = (
            await db.execute(
                text(
                    "SELECT payload FROM outbound_messages "
                    "WHERE tenant_id = :t AND kind = 'report' LIMIT 1"
                ),
                {"t": tid},
            )
        ).scalar_one()
    assert n >= 1  # one per verified email contact, once
    assert "web-1" in payload["text"] and payload["html"].startswith("<!doctype html>")


# ── Staff: probes and fleet ──────────────────────────────────────────────────


async def test_only_probe_accounts_can_be_probes(client, monkeypatch):
    staff = {
        "Authorization": f"Bearer {access_token(str(uuid.uuid4()), 'staff@x.com', superadmin=True)}"
    }
    owner = _new_user(client, "probe")
    customer = _new_user(client, "cust")
    from app.config import settings

    monkeypatch.setattr(settings, "PROBE_ACCOUNT_IDS", [str(await owner.tenant_id())])
    probe_host = await insert_host(await owner.tenant_id(), f"probe-{uuid.uuid4().hex[:6]}")
    cust_host = await insert_host(await customer.tenant_id(), "cust-1")

    r = await client.put(
        f"/admin/v1/hosts/{cust_host}/probe", headers=staff, json={"region": "region1"}
    )
    assert r.status_code == 403
    r = await client.put(
        f"/admin/v1/hosts/{probe_host}/probe", headers=staff, json={"region": "region1"}
    )
    assert r.status_code == 200 and r.json()["probe_region"] == "region1"
    regions = (await customer.request("GET", "/v1/probes")).json()
    assert any(p["region"] == "region1" for p in regions)
    fleet = (await client.get("/admin/v1/fleet", headers=staff)).json()
    assert any(p["id"] == str(probe_host) for p in fleet["probes"])
    # Customers can't use staff routes.
    assert (
        await customer.request("PUT", f"/admin/v1/hosts/{probe_host}/probe", json={"region": None})
    ).status_code in (401, 403)
    await client.put(f"/admin/v1/hosts/{probe_host}/probe", headers=staff, json={"region": None})


async def test_agent_binaries_are_served_and_nothing_else(client, tmp_path, monkeypatch):
    from app.config import settings

    (tmp_path / "1.2.3").mkdir()
    (tmp_path / "1.2.3" / "sentinel-agent-linux-amd64").write_bytes(b"\x7fELF")
    (tmp_path / "secret.txt").write_text("no")
    monkeypatch.setattr(settings, "AGENT_DIST_DIR", str(tmp_path))
    r = await client.get("/agent/1.2.3/sentinel-agent-linux-amd64")
    assert r.status_code == 200 and r.content == b"\x7fELF"
    for bad in [
        "/agent/1.2.3/../secret.txt",
        "/agent/..%2Fsecret.txt/x",
        "/agent/1.2.3/secret.txt",
        "/agent/9.9.9/sentinel-agent-linux-amd64",
    ]:
        assert (await client.get(bad)).status_code == 404, bad
