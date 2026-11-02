"""APM: TraceQL built from validated parts; Tempo tenants keep accounts apart."""

import asyncio
import os
import time
import uuid

import httpx
import pytest

from app.config import settings
from app.services.apm import q, selector

from .conftest import User, insert_host

TEMPO = "http://localhost:3210"
OTLP = "http://localhost:4329"


def test_traceql_quoting():
    assert q('a"} || {') == r'"a\"} || {"'
    assert selector("resource.service.name=" + q("shop"), "status=error") == (
        '{resource.service.name="shop" && status=error}'
    )
    assert selector() == "{}"


async def test_disabled_without_tempo(alice: User, monkeypatch):
    monkeypatch.setattr(settings, "TEMPO_URL", "")
    assert (await alice.request("GET", "/v1/apm/services")).json() == {
        "enabled": False,
        "services": [],
    }


def tempo_up() -> bool:
    try:
        return httpx.get(f"{TEMPO}/ready", timeout=2).status_code == 200
    except httpx.HTTPError:
        return False


def span(tid, sid, name, start, dur_ms, parent=None, error=False, kind=2):
    s = {
        "traceId": tid,
        "spanId": sid,
        "name": name,
        "kind": kind,
        "startTimeUnixNano": str(start),
        "endTimeUnixNano": str(start + dur_ms * 1_000_000),
        "attributes": [{"key": "http.route", "value": {"stringValue": name}}],
    }
    if parent:
        s["parentSpanId"] = parent
    if error:
        s["status"] = {"code": 2, "message": "boom"}
    return s


async def send(tenant_id, host_id, service, spans):
    body = {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": service}},
                        {"key": "pulsegrid.host_id", "value": {"stringValue": str(host_id)}},
                    ]
                },
                "scopeSpans": [{"spans": spans}],
            }
        ]
    }
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{OTLP}/v1/traces", json=body, headers={"X-Scope-OrgID": str(tenant_id)}
        )
    assert r.status_code == 200, r.text


@pytest.mark.skipif(not tempo_up(), reason="needs Tempo on localhost:3210")
async def test_apm_is_per_account(alice: User, bob: User, monkeypatch):
    monkeypatch.setattr(settings, "TEMPO_URL", TEMPO)
    a_tid, b_tid = await alice.tenant_id(), await bob.tenant_id()
    a_host = await insert_host(a_tid, "alice-app")
    b_host = await insert_host(b_tid, "bob-app")
    svc = f"shop-{uuid.uuid4().hex[:6]}"
    now = time.time_ns() - 2_000_000_000
    tid = os.urandom(16).hex()
    await send(
        a_tid,
        a_host,
        svc,
        [
            span(tid, "a" * 16, "GET /checkout", now, 300, error=True),
            span(tid, "b" * 16, "SELECT orders", now + 50_000_000, 200, parent="a" * 16, kind=3),
        ],
    )
    for i in range(5):
        await send(a_tid, a_host, svc, [span(os.urandom(16).hex(), "c" * 16, "GET /", now, 20 + i)])
    await send(b_tid, b_host, f"bob-{svc}", [span(os.urandom(16).hex(), "d" * 16, "x", now, 5)])

    found = []
    for _ in range(40):  # Tempo indexes recent traces within seconds
        found = (await alice.request("GET", "/v1/apm/traces", params={"service": svc})).json()
        if len(found) >= 6:
            break
        await asyncio.sleep(1)
    assert len(found) == 6, found
    slow = (
        await alice.request("GET", "/v1/apm/traces", params={"service": svc, "min_ms": 250})
    ).json()
    assert [t["trace_id"] for t in slow] == [tid]
    failed = (
        await alice.request("GET", "/v1/apm/traces", params={"service": svc, "errors": "true"})
    ).json()
    assert [t["trace_id"] for t in failed] == [tid]
    named = (
        await alice.request("GET", "/v1/apm/traces", params={"name": "checkout", "service": svc})
    ).json()
    assert [t["trace_id"] for t in named] == [tid]

    spans = (await alice.request("GET", f"/v1/apm/traces/{tid}")).json()
    assert [s["name"] for s in spans] == ["GET /checkout", "SELECT orders"]
    assert spans[0]["error"] and spans[0]["status_message"] == "boom"
    assert spans[1]["parent_id"] == "a" * 16 and spans[1]["kind"] == "client"
    assert spans[0]["hostname"] == "alice-app"

    # Bob sees none of it, even by trace id.
    assert (await bob.request("GET", f"/v1/apm/traces/{tid}")).status_code == 404
    bob_traces = (await bob.request("GET", "/v1/apm/traces", params={"service": svc})).json()
    assert bob_traces == []
    assert (
        await bob.request("GET", "/v1/apm/traces", params={"host_id": str(a_host)})
    ).status_code == 404

    services = []
    for _ in range(40):
        body = (await alice.request("GET", "/v1/apm/services")).json()
        services = [s for s in body["services"] if s["name"] == svc]
        if services and services[0]["requests"] >= 6:
            break
        await asyncio.sleep(1)
    assert services and services[0]["requests_per_minute"] > 0, services
    assert services[0]["requests"] == 6
    assert abs(services[0]["error_rate"] - 1 / 6) < 0.01
    assert services[0]["p95_ms"] is not None
    bob_services = (await bob.request("GET", "/v1/apm/services")).json()["services"]
    assert svc not in [s["name"] for s in bob_services]

    series = (await alice.request("GET", f"/v1/apm/services/{svc}/series")).json()
    assert series["requests_per_minute"] and "p95" in series["latency_ms"]

    assert (await alice.request("GET", "/v1/apm/traces/not-hex")).status_code == 400
