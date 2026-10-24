"""Tags, dependencies, process/service checks, escalation, maintenance windows,
new channel types and one-click acknowledge."""

import time
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import text

from app.config import settings
from app.db import ServiceSession
from app.routes.ack import ack_token

from .conftest import User, insert_host

# ── Hosts: tags and dependencies ─────────────────────────────────────────────


async def test_tags_are_normalised_listed_and_filterable(alice: User):
    tid = await alice.tenant_id()
    web = await insert_host(tid, "web-1")
    await insert_host(tid, "db-1")

    r = await alice.request("PATCH", f"/v1/hosts/{web}", json={"tags": [" Web ", "prod", "web"]})
    assert r.status_code == 200, r.text
    assert r.json()["tags"] == ["prod", "web"]

    assert (await alice.request("GET", "/v1/tags")).json() == [
        {"tag": "prod", "hosts": 1},
        {"tag": "web", "hosts": 1},
    ]
    listed = (await alice.request("GET", "/v1/hosts", params={"tag": "web"})).json()
    assert [h["hostname"] for h in listed] == ["web-1"]

    for bad in (["-x"], ["has space"], ["x" * 41]):
        r = await alice.request("PATCH", f"/v1/hosts/{web}", json={"tags": bad})
        assert r.status_code == 422, bad


async def test_dependencies_must_be_own_hosts_without_loops(alice: User, bob: User):
    tid = await alice.tenant_id()
    gw, vm1, vm2 = [await insert_host(tid, n) for n in ("gw", "vm-1", "vm-2")]
    bob_host = await insert_host(await bob.tenant_id(), "bob-gw")

    async def depend(host, parent):
        return await alice.request(
            "PATCH", f"/v1/hosts/{host}", json={"depends_on_host_id": str(parent)}
        )

    assert (await depend(vm1, gw)).json()["depends_on_host_id"] == str(gw)
    assert (await depend(vm2, vm1)).status_code == 200
    assert (await depend(gw, vm2)).status_code == 422  # gw -> vm2 -> vm1 -> gw
    assert (await depend(gw, gw)).status_code == 422
    assert (await depend(vm1, bob_host)).status_code == 422

    r = await alice.request("PATCH", f"/v1/hosts/{vm1}", json={"clear_depends_on": True})
    assert r.json()["depends_on_host_id"] is None


async def test_install_commands_carry_tags(alice: User):
    r = await alice.request("POST", "/v1/agent-keys", json={"name": "acs", "tags": ["ACS", "web"]})
    assert r.status_code == 201
    body = r.json()
    assert body["install_command"].endswith("--tags acs,web")
    assert body["install_command_windows"].endswith("-Tags acs,web")
    assert body["cloud_init"].startswith("#!/bin/sh\n")
    assert f"--key {body['key']} --tags acs,web" in body["cloud_init"]


# ── Rules ────────────────────────────────────────────────────────────────────


async def test_process_and_service_rules(alice: User):
    ok = [
        {"name": "nginx", "kind": "service_down", "target": "nginx", "duration_seconds": 60},
        {"name": "fpm", "kind": "service_down", "target": "php8.2-fpm.service"},
        {"name": "sql", "kind": "service_down", "target": "MSSQL$SQLEXPRESS"},
        {"name": "worker", "kind": "process_down", "target": "celery worker"},
    ]
    for body in ok:
        r = await alice.request("POST", "/v1/alert-rules", json=body)
        assert r.status_code == 201, (body, r.text)
        assert r.json()["target"] == body["target"]
        assert r.json()["metric"] is None

    bad = [
        {"name": "x", "kind": "service_down"},
        {"name": "x", "kind": "service_down", "target": "-h"},
        {"name": "x", "kind": "service_down", "target": "a;rm -rf /"},
        {"name": "x", "kind": "process_down", "target": "/usr/sbin/nginx"},
    ]
    for body in bad:
        assert (await alice.request("POST", "/v1/alert-rules", json=body)).status_code == 422, body


async def test_new_metrics_and_tag_scope(alice: User):
    tid = await alice.tenant_id()
    host = await insert_host(tid)
    for metric in ("iowait", "steal", "inodes", "disk_busy"):
        body = {
            "name": metric,
            "kind": "metric",
            "metric": metric,
            "operator": ">",
            "threshold": 50,
        }
        r = await alice.request("POST", "/v1/alert-rules", json=body)
        assert r.status_code == 201, r.text

    body = {"name": "web cpu", "kind": "metric", "metric": "cpu", "operator": ">", "threshold": 80}
    r = await alice.request("POST", "/v1/alert-rules", json={**body, "tag": "Web"})
    assert r.json()["tag"] == "web"
    both = {**body, "tag": "web", "host_id": str(host)}
    assert (await alice.request("POST", "/v1/alert-rules", json=both)).status_code == 422


async def test_escalations(alice: User, bob: User):
    channel = (await alice.request("GET", "/v1/channels")).json()[0]["id"]
    body = {
        "name": "down",
        "kind": "host_down",
        "duration_seconds": 120,
        "escalations": [
            {"delay_minutes": 15, "channel_ids": [channel]},
            {"delay_minutes": 30, "channel_ids": [channel]},
        ],
    }
    r = await alice.request("POST", "/v1/alert-rules", json=body)
    assert r.status_code == 201, r.text
    rule = r.json()
    assert [e["delay_minutes"] for e in rule["escalations"]] == [15, 30]

    # Replaced on update.
    one = {**body, "escalations": [{"delay_minutes": 5, "channel_ids": [channel]}]}
    r = await alice.request("PUT", f"/v1/alert-rules/{rule['id']}", json=one)
    assert r.json()["escalations"] == [{"delay_minutes": 5, "channel_ids": [channel]}]

    descending = {
        **body,
        "escalations": [
            {"delay_minutes": 30, "channel_ids": [channel]},
            {"delay_minutes": 15, "channel_ids": [channel]},
        ],
    }
    assert (await alice.request("POST", "/v1/alert-rules", json=descending)).status_code == 422
    bob_channel = (await bob.request("GET", "/v1/channels")).json()[0]["id"]
    foreign = {**body, "escalations": [{"delay_minutes": 5, "channel_ids": [bob_channel]}]}
    assert (await alice.request("POST", "/v1/alert-rules", json=foreign)).status_code == 422


async def test_recommended_rules_are_added_once(alice: User):
    first = await alice.request("POST", "/v1/alert-rules/recommended")
    assert first.status_code == 201
    names = {r["name"] for r in first.json()}
    assert {"Server not reporting", "CPU above 90%", "Disk above 90%"} <= names
    assert all(r["host_id"] is None and r["tag"] is None for r in first.json())
    again = await alice.request("POST", "/v1/alert-rules/recommended")
    assert again.json() == []


# ── Channels ─────────────────────────────────────────────────────────────────


async def test_new_channel_types_validate_and_mask(alice: User):
    good = {
        "slack": "https://hooks.slack.com/services/T000/B000/XXXXsecretXXXX",
        "teams": "https://contoso.webhook.office.com/webhookb2/abc/IncomingWebhook/def/ghij",
        "discord": "https://discord.com/api/webhooks/123/tokentoken",
        "telegram": "123456789:AAEhBOweik6ad9r_QXMENQjcrGbqCr4K-bs/-1001234567890",
        "pagerduty": "a" * 31 + "Z",
        "voice": "+919876543210",
    }
    for type_, target in good.items():
        r = await alice.request("POST", "/v1/channels", json={"type": type_, "target": target})
        assert r.status_code == 201, (type_, r.text)
        shown = r.json()["target"]
        if type_ == "voice":
            assert shown == target
        else:
            assert shown != target and target not in shown, (type_, shown)
    listed = {c["type"]: c["target"] for c in (await alice.request("GET", "/v1/channels")).json()}
    assert listed["telegram"] == "chat -1001234567890"
    assert listed["slack"] == "https://hooks.slack.com/…XXXX"

    bad = {
        "slack": "https://evil.example/services/x",
        "teams": "http://contoso.webhook.office.com/x",
        "discord": "https://discord.com/not-a-webhook",
        "telegram": "123:short/1",
        "pagerduty": "too-short",
        "voice": "9876543210",
    }
    for type_, target in bad.items():
        r = await alice.request("POST", "/v1/channels", json={"type": type_, "target": target})
        assert r.status_code == 422, (type_, target)


# ── Maintenance ──────────────────────────────────────────────────────────────


async def test_maintenance_windows(alice: User, bob: User):
    tid = await alice.tenant_id()
    host = await insert_host(tid, "web-1")
    now = datetime.now(UTC)
    once = {
        "name": "upgrade",
        "host_id": str(host),
        "schedule": "once",
        "starts_at": (now - timedelta(minutes=5)).isoformat(),
        "ends_at": (now + timedelta(hours=1)).isoformat(),
    }
    r = await alice.request("POST", "/v1/maintenance", json=once)
    assert r.status_code == 201, r.text
    window = r.json()
    assert window["active"] is True
    h = (await alice.request("GET", f"/v1/hosts/{host}")).json()
    assert h["in_maintenance"] is True

    weekly = {
        "name": "backups",
        "tag": "db",
        "schedule": "weekly",
        "weekdays": [7, 6, 6],
        "start_time": "02:00",
        "duration_minutes": 60,
        "timezone": "Asia/Kolkata",
    }
    r = await alice.request("POST", "/v1/maintenance", json=weekly)
    assert r.status_code == 201, r.text
    assert r.json()["weekdays"] == [6, 7] and r.json()["start_time"] == "02:00"

    bad = [
        {**weekly, "timezone": "Mars/Base"},
        {**weekly, "weekdays": [0]},
        {**once, "ends_at": once["starts_at"]},
        {**once, "ends_at": (now + timedelta(days=40)).isoformat()},
        {**once, "tag": "db"},
    ]
    for body in bad:
        assert (await alice.request("POST", "/v1/maintenance", json=body)).status_code == 422, body

    # Private to the tenant.
    assert (await bob.request("GET", "/v1/maintenance")).json() == []
    put = await bob.request(
        "PUT", f"/v1/maintenance/{window['id']}", json={**once, "host_id": None}
    )
    assert put.status_code == 404
    bob_scoped = {**once, "host_id": str(host)}
    assert (await bob.request("POST", "/v1/maintenance", json=bob_scoped)).status_code == 422

    assert (await alice.request("DELETE", f"/v1/maintenance/{window['id']}")).status_code == 204
    h = (await alice.request("GET", f"/v1/hosts/{host}")).json()
    assert h["in_maintenance"] is False


# ── Acknowledge links ────────────────────────────────────────────────────────


def test_ack_token_matches_alerter():
    # Same fixture as alerter/chat_test.go (ackFixture).
    token = ack_token("00000000-0000-0000-0000-000000000001", "test-ack-secret")
    assert token == "00000000-0000-0000-0000-000000000001.GnitMVzz9iorKi3AI1lO4GU1"


async def _open_incident(tenant_id: uuid.UUID) -> str:
    async with ServiceSession() as db, db.begin():
        return str(
            (
                await db.execute(
                    text(
                        "INSERT INTO incidents (tenant_id, summary, rule_name, hostname) "
                        "VALUES (:t, 'web-1 is not reporting', 'down', 'web-1') RETURNING id"
                    ),
                    {"t": tenant_id},
                )
            ).scalar_one()
        )


async def test_ack_link(client, alice: User, monkeypatch):
    monkeypatch.setattr(settings, "ACK_SIGNING_SECRET", "s3cret")
    incident = await _open_incident(await alice.tenant_id())
    token = ack_token(incident, "s3cret")

    page = await client.get(f"/v1/ack/{token}")
    assert page.status_code == 200 and '<form method="post">' in page.text
    assert "web-1 is not reporting" in page.text
    # Viewing changes nothing.
    got = (await alice.request("GET", f"/v1/incidents/{incident}")).json()
    assert got["acknowledged_at"] is None

    assert (await client.post(f"/v1/ack/{token}")).status_code == 200
    got = (await alice.request("GET", f"/v1/incidents/{incident}")).json()
    assert got["acknowledged_at"] is not None and got["acknowledged_by"] == "alert link"

    forged = incident + "." + "A" * 24
    assert (await client.get(f"/v1/ack/{forged}")).status_code == 404
    assert (await client.post(f"/v1/ack/{ack_token(incident, 'wrong')}")).status_code == 404
    assert (await client.get("/v1/ack/not-a-uuid.x")).status_code == 404


async def test_ack_links_off_without_a_secret(client, alice: User, monkeypatch):
    monkeypatch.setattr(settings, "ACK_SIGNING_SECRET", "")
    incident = await _open_incident(await alice.tenant_id())
    assert (await client.get(f"/v1/ack/{ack_token(incident, '')}")).status_code == 404


async def test_dashboard_ack_records_who(alice: User):
    incident = await _open_incident(await alice.tenant_id())
    r = await alice.request("POST", f"/v1/incidents/{incident}/acknowledge")
    assert r.json()["acknowledged_by"] == alice.email


# ── Processes and checks (needs VictoriaMetrics) ─────────────────────────────


def _vm_up() -> bool:
    try:
        return httpx.get(f"{settings.VICTORIAMETRICS_URL}/health", timeout=2).status_code == 200
    except httpx.HTTPError:
        return False


needs_vm = pytest.mark.skipif(not _vm_up(), reason="VictoriaMetrics not running")


def _push(tenant_id: uuid.UUID, host_id: uuid.UUID, lines: list[str]) -> None:
    """Write samples the way ingest does (host_id in the body, tenant_id as
    extra_label), then make them queryable at once."""
    # 60s old: VictoriaMetrics hides the newest 30s from queries (latency offset).
    ts = int((time.time() - 60) * 1000)
    body = "\n".join(line.replace("{", f'{{host_id="{host_id}",', 1) + f" {ts}" for line in lines)
    base = settings.VICTORIAMETRICS_URL
    httpx.post(
        f"{base}/api/v1/import/prometheus",
        params={"extra_label": f"tenant_id={tenant_id}"},
        content=body,
    ).raise_for_status()
    httpx.get(f"{base}/internal/force_flush").raise_for_status()


@needs_vm
async def test_processes_endpoint(alice: User, bob: User):
    tid = await alice.tenant_id()
    host = await insert_host(tid)
    _push(
        tid,
        host,
        [
            'pulsegrid_process_cpu_percent{process="nginx"} 12.5',
            'pulsegrid_process_memory_bytes{process="nginx"} 1048576',
            'pulsegrid_process_count{process="nginx"} 4',
            'pulsegrid_process_cpu_percent{process="postgres"} 30',
            'pulsegrid_process_memory_bytes{process="postgres"} 2048',
            'pulsegrid_process_count{process="postgres"} 9',
            "pulsegrid_processes_total{} 211",
        ],
    )
    r = await alice.request("GET", f"/v1/hosts/{host}/processes")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 211
    assert [p["name"] for p in body["processes"]] == ["postgres", "nginx"]
    assert body["processes"][1] == {
        "name": "nginx",
        "cpu_percent": 12.5,
        "memory_bytes": 1048576,
        "count": 4,
    }
    assert (await bob.request("GET", f"/v1/hosts/{host}/processes")).status_code == 404


@needs_vm
async def test_checks_endpoint(alice: User):
    tid = await alice.tenant_id()
    host = await insert_host(tid)
    await alice.request("PATCH", f"/v1/hosts/{host}", json={"tags": ["web"]})
    rules = [
        {"name": "nginx", "kind": "service_down", "target": "nginx", "tag": "web"},
        {"name": "redis", "kind": "service_down", "target": "redis", "host_id": str(host)},
        {"name": "worker", "kind": "process_down", "target": "celery"},
        {"name": "db only", "kind": "service_down", "target": "postgresql", "tag": "db"},
    ]
    for body in rules:
        assert (await alice.request("POST", "/v1/alert-rules", json=body)).status_code == 201
    _push(
        tid,
        host,
        [
            'pulsegrid_service_up{service="nginx"} 1',
            'pulsegrid_service_up{service="redis"} 0',
            "pulsegrid_systemd_failed_units{} 2",
        ],
    )
    r = await alice.request("GET", f"/v1/hosts/{host}/checks")
    assert r.status_code == 200, r.text
    got = {(c["kind"], c["name"]): c["state"] for c in r.json()["checks"]}
    assert got == {
        ("process", "celery"): "waiting",  # not reported yet
        ("service", "nginx"): "running",
        ("service", "redis"): "stopped",
    }
    assert r.json()["failed_units"] == 2


@needs_vm
async def test_new_chart_metrics_are_queryable(alice: User):
    tid = await alice.tenant_id()
    host = await insert_host(tid)
    _push(
        tid,
        host,
        [
            'pulsegrid_cpu_mode_percent{mode="steal"} 7',
            'pulsegrid_cpu_mode_percent{mode="idle"} 80',
            'pulsegrid_cpu_core_usage_percent{core="0"} 50',
        ],
    )
    now = int(time.time())
    params = {"start": now - 600, "end": now + 60, "step": 60}
    modes = await alice.request(
        "GET", f"/v1/hosts/{host}/metrics", params={**params, "metric": "cpu_modes"}
    )
    assert modes.status_code == 200, modes.text
    assert [s["labels"] for s in modes.json()["series"]] == [{"mode": "steal"}]  # idle left out
    for metric in ("cpu_cores", "inodes", "disk_io", "disk_iops", "disk_busy", "processes"):
        r = await alice.request(
            "GET", f"/v1/hosts/{host}/metrics", params={**params, "metric": metric}
        )
        assert r.status_code == 200, (metric, r.text)


async def test_console_provisions_install_keys(client, alice: User):
    headers = {"X-Internal-Api-Key": settings.INTERNAL_API_KEY}
    uid = str(uuid.uuid4())
    body = {"email": "new@example.com", "name": "New", "key_name": "VM web-1", "tags": ["acs"]}
    r = await client.post(f"/internal/v1/tenants/{uid}/agent-keys", json=body, headers=headers)
    assert r.status_code == 201, r.text
    assert r.json()["cloud_init"].startswith("#!/bin/sh") and "--tags acs" in r.json()["cloud_init"]
    # The new tenant exists, with its key and its default email contact.
    async with ServiceSession() as db:
        keys = (
            await db.execute(
                text(
                    "SELECT k.name, (SELECT count(*) FROM notification_channels c "
                    "WHERE c.tenant_id = t.id) FROM agent_keys k "
                    "JOIN tenants t ON t.id = k.tenant_id "
                    "WHERE t.external_account_id = :e"
                ),
                {"e": uid},
            )
        ).all()
    assert keys == [("VM web-1", 1)]
    r = await client.post(f"/internal/v1/tenants/{uid}/agent-keys", json=body)
    assert r.status_code == 401
