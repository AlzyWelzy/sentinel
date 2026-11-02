"""APM over Tempo: services with their request rate, error rate and latency
(TraceQL metrics), trace search, and whole traces. Every request carries the
account's tenant id as X-Scope-OrgID, so Tempo keeps accounts apart; TraceQL
is built here from validated parts, never taken from the request."""

import base64
import json
import re
import uuid
from collections import defaultdict
from typing import Any

import httpx

from app.config import settings

TRACE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
KIND_NAMES = {
    "SPAN_KIND_INTERNAL": "internal",
    "SPAN_KIND_SERVER": "server",
    "SPAN_KIND_CLIENT": "client",
    "SPAN_KIND_PRODUCER": "producer",
    "SPAN_KIND_CONSUMER": "consumer",
}
# Spans that represent work arriving at a service: what "requests" means.
ENTRY = "(kind=server || kind=consumer)"


class ApmUnavailable(Exception):
    pass


class BadQuery(Exception):
    pass


def q(s: str) -> str:
    """A TraceQL string literal."""
    return json.dumps(s)


def _scope(service: str | None = None, host_id: uuid.UUID | None = None) -> list[str]:
    parts = []
    if service:
        parts.append(f"resource.service.name={q(service)}")
    if host_id:
        parts.append(f'resource.sentinel.host_id="{uuid.UUID(str(host_id))}"')
    return parts


def selector(*parts: str) -> str:
    return "{" + " && ".join(p for p in parts if p) + "}" if any(parts) else "{}"


async def _get(tenant_id: uuid.UUID, path: str, params: dict) -> dict:
    if not settings.TEMPO_URL:
        raise ApmUnavailable("APM isn't enabled")
    try:
        async with httpx.AsyncClient(base_url=settings.TEMPO_URL) as client:
            r = await client.get(
                path, params=params, headers={"X-Scope-OrgID": str(tenant_id)}, timeout=30
            )
    except httpx.HTTPError as exc:
        raise ApmUnavailable(str(exc)) from exc
    if r.status_code == 404:
        return {}
    if r.status_code == 400:
        raise BadQuery(r.text.strip()[:300])
    if r.status_code != 200:
        raise ApmUnavailable(f"HTTP {r.status_code}: {r.text.strip()[:200]}")
    return r.json()


async def service_names(tenant_id: uuid.UUID, start: int, end: int) -> list[str]:
    body = await _get(
        tenant_id,
        "/api/v2/search/tag/resource.service.name/values",
        {"start": start, "end": end},
    )
    return sorted({v["value"] for v in body.get("tagValues") or [] if v.get("value")})


def _series_by(body: dict, label: str) -> dict[str, list[tuple[int, float]]]:
    """TraceQL metrics response → {label value: [(unix s, value)]}."""
    out: dict[str, list[tuple[int, float]]] = {}
    for s in body.get("series") or []:
        labels = {
            lb["key"]: next(iter(lb.get("value", {}).values()), None) for lb in s.get("labels", [])
        }
        key = str(labels.get(label, ""))
        points = [
            (int(p["timestampMs"]) // 1000, float(p["value"]))
            for p in s.get("samples", [])
            if "value" in p
        ]
        out[key] = points
    return out


async def metrics(tenant_id: uuid.UUID, query: str, start: int, end: int, step: int) -> dict:
    return await _get(
        tenant_id,
        "/api/metrics/query_range",
        {"q": query, "start": start, "end": end, "step": f"{step}s"},
    )


def _count(points: list[tuple[int, float]], step: int) -> float:
    """Spans in the period: each sample is a per-second rate over one step."""
    return sum(v for _, v in points) * step


async def services(
    tenant_id: uuid.UUID, start: int, end: int, host_id: uuid.UUID | None
) -> list[dict]:
    """Each service: requests per minute, error share and latency percentiles
    (ms) over the period, from its entry spans."""
    step = max(60, (end - start) // 60)
    scope = _scope(host_id=host_id)
    by = "by (resource.service.name)"
    rate = await metrics(tenant_id, f"{selector(*scope, ENTRY)} | rate() {by}", start, end, step)
    errs = await metrics(
        tenant_id, f"{selector(*scope, ENTRY, 'status=error')} | rate() {by}", start, end, step
    )
    lat = await metrics(
        tenant_id,
        f"{selector(*scope, ENTRY)} | quantile_over_time(duration, .5, .95, .99) {by}",
        start,
        end,
        step,
    )
    names = set(await service_names(tenant_id, start, end))
    rates = _series_by(rate, "resource.service.name")
    errors = _series_by(errs, "resource.service.name")
    quantiles: dict[str, dict[str, float | None]] = defaultdict(dict)
    for s in lat.get("series") or []:
        labels = {
            lb["key"]: next(iter(lb.get("value", {}).values()), None) for lb in s.get("labels", [])
        }
        name = str(labels.get("resource.service.name", ""))
        p = labels.get("p")
        pts = [float(x["value"]) for x in s.get("samples", []) if "value" in x]
        if name and p is not None and pts:
            # quantile_over_time is in seconds; the period's typical value.
            quantiles[name][str(p)] = sorted(pts)[len(pts) // 2] * 1000
    names |= {n for n in rates if n} | {n for n in quantiles if n}
    minutes = max(1.0, (end - start) / 60)
    out = []
    for name in sorted(names):
        total = _count(rates.get(name, []), step)
        failed = _count(errors.get(name, []), step)
        qs = quantiles.get(name, {})
        out.append(
            {
                "name": name,
                "requests": round(total),
                "requests_per_minute": total / minutes if total else None,
                "error_rate": min(1.0, failed / total) if total else None,
                "p50_ms": qs.get("0.5"),
                "p95_ms": qs.get("0.95"),
                "p99_ms": qs.get("0.99"),
            }
        )
    return out


async def service_series(
    tenant_id: uuid.UUID, service: str, start: int, end: int, host_id: uuid.UUID | None
) -> dict:
    step = max(60, (end - start) // 120)
    sel = selector(*_scope(service, host_id), ENTRY)
    sel_err = selector(*_scope(service, host_id), ENTRY, "status=error")
    rate = _series_by(await metrics(tenant_id, f"{sel} | rate()", start, end, step), "")
    errs = _series_by(await metrics(tenant_id, f"{sel_err} | rate()", start, end, step), "")
    lat = await metrics(
        tenant_id, f"{sel} | quantile_over_time(duration, .5, .95, .99)", start, end, step
    )
    latency: dict[str, list[list[float]]] = {}
    for s in lat.get("series") or []:
        labels = {
            lb["key"]: next(iter(lb.get("value", {}).values()), None) for lb in s.get("labels", [])
        }
        p = str(labels.get("p", ""))
        latency[f"p{round(float(p) * 100)}" if p else "p"] = [
            [int(x["timestampMs"]) // 1000, float(x["value"]) * 1000]
            for x in s.get("samples", [])
            if "value" in x
        ]
    pick = lambda d: next(iter(d.values()), [])  # noqa: E731 (one unlabelled series)
    return {
        "requests_per_minute": [[t, v * 60] for t, v in pick(rate)],
        "errors_per_minute": [[t, v * 60] for t, v in pick(errs)],
        "latency_ms": latency,
        "step": step,
    }


async def search(
    tenant_id: uuid.UUID,
    start: int,
    end: int,
    limit: int,
    service: str | None = None,
    name: str | None = None,
    min_ms: int | None = None,
    errors: bool = False,
    host_id: uuid.UUID | None = None,
) -> list[dict]:
    parts = _scope(service, host_id)
    if name:
        if len(name) > 200:
            raise BadQuery("name is too long")
        parts.append(f"name=~{q('(?i).*' + re.escape(name) + '.*')}")
    if min_ms:
        parts.append(f"duration>{int(min_ms)}ms")
    if errors:
        parts.append("status=error")
    body = await _get(
        tenant_id,
        "/api/search",
        {"q": selector(*parts), "start": start, "end": end, "limit": limit, "spss": 3},
    )
    out: list[dict[str, Any]] = []
    for t in body.get("traces") or []:
        span_sets = t.get("spanSets") or ([t["spanSet"]] if t.get("spanSet") else [])
        out.append(
            {
                "trace_id": t["traceID"].rjust(32, "0"),
                "root_service": t.get("rootServiceName") or None,
                "root_name": t.get("rootTraceName") or None,
                "start_ms": int(t.get("startTimeUnixNano", "0")) // 1_000_000,
                "duration_ms": t.get("durationMs") or 0,
                "matched": sum(int(s.get("matched", 0)) for s in span_sets),
            }
        )
    out.sort(key=lambda x: int(x["start_ms"]), reverse=True)
    return out


def _hex(b64: str | None) -> str | None:
    if not b64:
        return None
    try:
        return base64.b64decode(b64).hex()
    except ValueError:
        return b64


def _value(v: dict):
    if not v:
        return None
    kind, val = next(iter(v.items()))
    if kind == "arrayValue":
        return [_value(x) for x in val.get("values", [])]
    if kind == "kvlistValue":
        return {x["key"]: _value(x.get("value", {})) for x in val.get("values", [])}
    if kind == "intValue":
        return int(val)
    return val


async def trace(tenant_id: uuid.UUID, trace_id: str) -> list[dict] | None:
    if not TRACE_ID_RE.match(trace_id):
        raise BadQuery("trace id must be 32 hex characters")
    body = await _get(tenant_id, f"/api/v2/traces/{trace_id}", {})
    data = body.get("trace") or {}
    batches = data.get("resourceSpans") or data.get("batches") or []
    if not batches:
        return None
    spans: list[dict[str, Any]] = []
    for rs in batches:
        res = {
            a["key"]: _value(a.get("value", {}))
            for a in rs.get("resource", {}).get("attributes", [])
        }
        for ss in rs.get("scopeSpans") or rs.get("instrumentationLibrarySpans") or []:
            for sp in ss.get("spans", []):
                start = int(sp.get("startTimeUnixNano", 0))
                end = int(sp.get("endTimeUnixNano", start))
                status = sp.get("status") or {}
                spans.append(
                    {
                        "span_id": _hex(sp.get("spanId")),
                        "parent_id": _hex(sp.get("parentSpanId")),
                        "name": sp.get("name", ""),
                        "service": res.get("service.name"),
                        "host_id": res.get("sentinel.host_id"),
                        "kind": KIND_NAMES.get(sp.get("kind", ""), "internal"),
                        "start_ns": start,
                        "duration_ns": max(0, end - start),
                        "error": status.get("code") in ("STATUS_CODE_ERROR", 2),
                        "status_message": status.get("message") or None,
                        "attributes": {
                            a["key"]: _value(a.get("value", {})) for a in sp.get("attributes", [])
                        },
                        "events": [
                            {
                                "name": ev.get("name"),
                                "time_ns": int(ev.get("timeUnixNano", 0)),
                                "attributes": {
                                    a["key"]: _value(a.get("value", {}))
                                    for a in ev.get("attributes", [])
                                },
                            }
                            for ev in sp.get("events", [])
                        ],
                    }
                )
    spans.sort(key=lambda s: int(s["start_ns"]))
    return spans
