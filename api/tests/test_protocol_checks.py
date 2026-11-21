"""Protocol checks: every type validates its target and params, network ones
run on the probes but only against public addresses, and passwords and
tokens are never answered back (an update that sends the mask keeps them)."""

import uuid

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
    (
        "http",
        "https://x.example.com",
        {"basic_user": "a", "bearer_token": "b"},
        "one way to sign in",
    ),
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


async def test_push_checks(alice: User, bob: User):
    r = await alice.request(
        "POST",
        "/v1/checks",
        json={"name": "nightly backup", "type": "push", "target": "", "interval_seconds": 3600},
    )
    assert r.status_code == 201, r.text
    c = r.json()
    assert c["push_url"].startswith("http") and "/push/" in c["push_url"]
    assert c["status"] == "pending" and c["target"] == "push"
    rule = (await alice.request("GET", f"/v1/alert-rules/{c['rule_id']}")).json()
    assert rule["duration_seconds"] == 0

    # It runs nowhere.
    r = await alice.request(
        "POST", "/v1/checks", json={"name": "x", "type": "push", "target": "", "on_probes": True}
    )
    assert r.status_code == 422

    # A new URL replaces the old one; someone else can't rotate it.
    r = await alice.request("POST", f"/v1/checks/{c['id']}/push-token")
    assert r.status_code == 200 and r.json()["push_url"] != c["push_url"]
    assert (await bob.request("POST", f"/v1/checks/{c['id']}/push-token")).status_code == 404

    # An edit keeps the URL.
    body = {"name": "backup", "type": "push", "target": "push", "interval_seconds": 7200}
    body["params"] = {"grace_seconds": "600"}
    r2 = await alice.request("PUT", f"/v1/checks/{c['id']}", json=body)
    assert r2.status_code == 200, r2.text
    assert r2.json()["push_url"] == r.json()["push_url"]

    # The token isn't in the export.
    token = r.json()["push_url"].rsplit("/", 1)[1]
    assert token not in (await alice.request("GET", "/v1/organisation/export")).text


CERT = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
KEY = "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----"


async def test_http_proxy_mtls_oauth(alice: User):
    body = {"name": "api", "type": "http", "target": "https://api.example.com", "on_probes": True}
    params = {
        "proxy": "http://user:pr0xypass@proxy.example.com:3128",
        "client_cert": CERT,
        "client_key": KEY,
        "oauth_token_url": "https://idp.example.com/token",
        "oauth_client_id": "app",
        "oauth_client_secret": "0authsecret",
        "oauth_scopes": "read",
        "oauth_auth_method": "post",
    }
    r = await alice.request("POST", "/v1/checks", json={**body, "params": params})
    assert r.status_code == 201, r.text
    c = r.json()
    for secret in ("pr0xypass", "MIIE", "0authsecret"):
        assert secret not in r.text
    assert c["params"]["proxy"] == f"http://user:{MASK}@proxy.example.com:3128"
    assert c["params"]["client_cert"] == CERT
    # Sending the masks back keeps every secret.
    r = await alice.request("PUT", f"/v1/checks/{c['id']}", json={**body, "params": c["params"]})
    assert r.status_code == 200, r.text
    from app.db import ServiceSession
    from app.models import Check

    async with ServiceSession() as db:
        row = await db.get(Check, uuid.UUID(c["id"]))
    assert row is not None
    stored = row.params
    assert stored["proxy"] == params["proxy"] and stored["client_key"] == KEY
    assert stored["oauth_client_secret"] == "0authsecret"
    assert "pr0xypass" not in (await alice.request("GET", "/v1/organisation/export")).text
    assert "0authsecret" not in (await alice.request("GET", "/v1/audit-log")).text


@pytest.mark.parametrize(
    "params,why",
    [
        ({"proxy": "ftp://proxy.example.com"}, "URL"),
        ({"proxy": "http://10.0.0.5:3128"}, "proxy at a public address"),
        ({"client_cert": CERT}, "both client_cert and client_key"),
        ({"client_cert": "nope", "client_key": KEY}, "PEM certificate"),
        ({"oauth_token_url": "https://idp.example.com/t"}, "oauth_client_id"),
        (
            {
                "oauth_token_url": "https://127.0.0.1/t",
                "oauth_client_id": "a",
                "oauth_client_secret": "b",
            },
            "public token URL",
        ),
        (
            {
                "oauth_token_url": "https://i.example.com/t",
                "oauth_client_id": "a",
                "oauth_client_secret": "b",
                "oauth_auth_method": "jwt",
            },
            "basic or post",
        ),
        (
            {
                "oauth_token_url": "https://i.example.com/t",
                "bearer_token": "x",
                "oauth_client_id": "a",
                "oauth_client_secret": "b",
            },
            "one way to sign in",
        ),
    ],
)
async def test_http_auth_refused(alice: User, params, why):
    body = {"name": "x", "type": "http", "target": "https://a.example.com", "on_probes": True}
    r = await alice.request("POST", "/v1/checks", json={**body, "params": params})
    assert r.status_code == 422 and why in r.text, r.text


async def test_params_are_bounded(alice: User):
    body = {"name": "x", "type": "http", "target": "https://a.example.com", "on_probes": True}
    r = await alice.request("POST", "/v1/checks", json={**body, "params": {"body": "x" * 20000}})
    assert r.status_code == 422 and "too long" in r.text


async def test_every_http_method(alice: User):
    for m in ("put", "PATCH", "DELETE", "OPTIONS"):
        r = await make(
            alice, type="http", target="https://a.example.com", on_probes=True, params={"method": m}
        )
        assert r.status_code == 201 and r.json()["params"]["method"] == m.upper(), r.text


STEPS = (
    '[{"action":"type","selector":"#u","text":"{{username}}"},'
    '{"action":"type","selector":"#p","text":"{{password}}"},'
    '{"action":"click","selector":"button"},{"action":"expect_text","text":"Welcome"}]'
)


async def test_browser_checks(alice: User):
    import base64
    import json

    from app.services.heartbeats import redis

    r = await make(
        alice, type="browser", target="https://shop.example.com/login", on_probes=True,
        params={"steps": STEPS, "username": "ada", "password": "pa55word", "max_load_ms": "0"},
    )  # fmt: skip
    assert r.status_code == 201, r.text
    c = r.json()
    assert c["params"]["password"] == MASK and "pa55word" not in r.text
    assert c["interval_seconds"] >= 60
    # No screenshot yet; then one from ingest's key.
    shot = f"/v1/checks/{c['id']}/screenshot"
    assert (await alice.request("GET", shot)).status_code == 404
    jpeg = b"\xff\xd8\xff\xe0fake"
    for place, ts in (("probe:eu", 1), ("probe:us", 2)):
        await redis.hset(
            f"pg:checkshot:{c['id']}", place,
            json.dumps({"ts": ts, "jpeg": base64.b64encode(jpeg + place.encode()).decode()}),
        )  # fmt: skip
    r = await alice.request("GET", shot)
    assert r.status_code == 200 and r.headers["content-type"] == "image/jpeg"
    assert r.content == jpeg + b"probe:us" and r.headers["x-taken-at"] == "2"


@pytest.mark.parametrize(
    "params,on_probes,why",
    [
        ({"steps": "nope"}, True, "JSON list"),
        ({"steps": '[{"action":"eval"}]'}, True, "action is one of"),
        ({"steps": '[{"action":"click"}]'}, True, "needs a selector"),
        ({"steps": '[{"action":"goto","url":"http://10.0.0.1/"}]'}, True, "public addresses"),
        ({"steps": '[{"action":"sleep","ms":60000}]'}, True, "1-10000"),
        ({"browser_ws": "ws://chrome:9222"}, True, "not the public probes"),
        ({"timeout_seconds": "500"}, True, "5-90"),
        (
            {
                "steps": '[{"action":"type","selector":"#p","text":"hunter22"}]',
                "password": "hunter22",
            },
            True,
            "{{password}}",
        ),
    ],
)
async def test_browser_refused(alice: User, params, on_probes, why):
    r = await make(
        alice, type="browser", target="https://a.example.com", on_probes=on_probes, params=params
    )
    assert r.status_code == 422 and why in r.text, r.text
