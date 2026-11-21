"""Protocol checks: every type validates its target and params, network ones
run on the probes but only against public addresses, and passwords and
tokens are never answered back (an update that sends the mask keeps them)."""

import pytest

from app.routes.checks import MASK

from .conftest import User, insert_host

PG = "postgres://app:hunter2@db.example.com:5432/app"


async def make(user: User, **body):
    body.setdefault("name", body["type"])
    if "host_id" not in body and not body.get("on_probes"):
        body["host_id"] = str(await insert_host(await user.tenant_id(), "web-1"))
    return await user.request("POST", "/v1/checks", json=body)


GOOD = [
    ("websocket", "wss://ws.example.com/feed", {"subprotocol": "graphql-ws"}),
    ("smtp", "mail.example.com:587", {"security": "starttls"}),
    ("ntp", "pool.ntp.org", {"max_offset_ms": "500", "max_stratum": "3"}),
    ("redis", "redis://:pw@cache.example.com:6379/0", {}),
    ("postgres", PG, {"query": "SELECT 1", "expect": "1"}),
    ("mysql", "mysql://root:pw@db.example.com:3306/shop", {}),
    ("mongodb", "mongodb://db.example.com:27017", {}),
    ("kafka", "broker.example.com:9092", {}),
    ("mqtt", "mqtt.example.com:1883", {"topic": "a/b", "expect": "ok", "username": "u"}),
    ("grpc", "api.example.com:443", {"tls": "true", "service": "orders", "metadata": "{}"}),
    ("sip", "pbx.example.com", {}),
    ("radius", "aaa.example.com:1812", {"secret": "s", "username": "probe", "password": "p"}),
    ("game", "mc.example.com:25565", {"protocol": "minecraft"}),
    ("snmp", "10.0.0.1", {"oid": "1.3.6.1.2.1.1.3.0", "op": ">", "expect": "0"}),
    ("docker", "web", {}),
    ("service", "nginx.service", {}),
    ("tcp", "db.example.com:22", {"invert": "true"}),
]


@pytest.mark.parametrize(("type_", "target", "params"), GOOD)
async def test_each_type_is_accepted(alice: User, type_, target, params):
    r = await make(alice, type=type_, target=target, params=params)
    assert r.status_code == 201, r.text
    assert r.json()["type"] == type_


BAD = [
    ("websocket", "https://ws.example.com", {}, "ws://"),
    ("smtp", "mail.example.com", {"security": "ssl"}, "security"),
    ("postgres", "db.example.com:5432", {}, "postgres://"),
    ("mysql", "mysql://", {}, "mysql://"),
    ("snmp", "10.0.0.1", {}, "oid"),
    ("snmp", "10.0.0.1", {"oid": "1.3.6", "version": "3"}, "version"),
    ("radius", "aaa.example.com", {"username": "u"}, "secret"),
    ("game", "x.example.com", {"protocol": "quake"}, "protocol"),
    ("docker", "--privileged", {}, "container"),
    ("service", "a;reboot", {}, "service"),
    ("http", "https://x.example.com", {"headers": "[1]"}, "headers"),
    ("http", "https://x.example.com", {"json_path": "a", "json_op": "~="}, "json_op"),
    ("http", "https://x.example.com", {"basic_user": "a", "bearer_token": "b"}, "not both"),
    ("grpc", "api.example.com:50051", {"metadata": "x"}, "metadata"),
    ("tcp", "db.example.com:22", {"invert": "yes"}, "invert"),
    ("ntp", "pool.ntp.org:99999", {}, "port"),
    ("kafka", "bad host!", {}, "valid host"),
]


@pytest.mark.parametrize(("type_", "target", "params", "why"), BAD)
async def test_bad_definitions_are_refused(alice: User, type_, target, params, why):
    r = await make(alice, type=type_, target=target, params=params)
    assert r.status_code == 422, r.text
    assert why in r.text


async def test_probes_take_network_types_but_public_only(alice: User):
    r = await make(alice, type="redis", target="redis://cache.example.com:6379", on_probes=True)
    assert r.status_code == 201, r.text
    for target in ("redis://10.0.0.5:6379", "redis://localhost:6379"):
        r = await make(alice, type="redis", target=target, on_probes=True)
        assert r.status_code == 422 and "public" in r.text
    r = await make(alice, type="mqtt", target="mqtt://192.168.1.9:1883", on_probes=True)
    assert r.status_code == 422
    r = await make(alice, type="docker", target="web", on_probes=True)
    assert r.status_code == 422 and "on a server" in r.text


async def test_secrets_are_masked_and_kept(alice: User):
    host = str(await insert_host(await alice.tenant_id(), "db-1"))
    r = await make(
        alice,
        type="postgres",
        target=PG,
        host_id=host,
        params={"query": "SELECT 1"},
    )
    c = r.json()
    assert "hunter2" not in r.text and c["target"] == PG.replace("hunter2", MASK)
    r = await make(
        alice,
        type="http",
        target="https://api.example.com/health",
        host_id=host,
        params={"bearer_token": "tok-123", "headers": '{"Authorization": "x"}'},
    )
    h = r.json()
    assert "tok-123" not in r.text and h["params"]["bearer_token"] == MASK
    assert h["params"]["headers"] == MASK

    # Saving the form as it came back keeps the secrets.
    body = {k: c[k] for k in ("name", "type", "target", "params", "interval_seconds", "host_id")}
    body["params"] = {**c["params"], "query": "SELECT 2"}
    r = await alice.request("PUT", f"/v1/checks/{c['id']}", json=body)
    assert r.status_code == 200, r.text
    body = {k: h[k] for k in ("name", "type", "target", "params", "interval_seconds", "host_id")}
    assert (await alice.request("PUT", f"/v1/checks/{h['id']}", json=body)).status_code == 200

    from sqlalchemy import text

    from app.db import ServiceSession

    async with ServiceSession() as db:
        rows = {
            str(r.id): (r.target, r.params)
            for r in await db.execute(text("SELECT id, target, params FROM checks"))
        }
    assert rows[c["id"]][0] == PG and rows[c["id"]][1]["query"] == "SELECT 2"
    assert rows[h["id"]][1]["bearer_token"] == "tok-123"
    assert rows[h["id"]][1]["headers"] == '{"Authorization": "x"}'

    # A new check can't be created with the mask in place of a secret.
    r = await make(alice, type="postgres", target=PG.replace("hunter2", MASK), host_id=host)
    assert r.status_code == 422

    # Neither the export nor the audit log has them.
    export = (await alice.request("GET", "/v1/organisation/export")).text
    assert "hunter2" not in export and "tok-123" not in export
    log = (await alice.request("GET", "/v1/audit-log")).text
    assert "hunter2" not in log and "tok-123" not in log
