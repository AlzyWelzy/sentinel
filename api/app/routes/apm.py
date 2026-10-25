"""APM: traces sent by applications through the agent's local OTLP receiver
(apm.conf on the server). Services with request rate, errors and latency;
trace search; one trace's spans for a waterfall."""

import time
import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select

from app.config import settings
from app.models import Host
from app.services import apm
from app.tenancy import Tenant, TenantContext

router = APIRouter(prefix="/v1/apm")

MAX_RANGE_S = 7 * 86400


class ServiceOut(BaseModel):
    name: str
    requests: int  # entry spans in the period
    requests_per_minute: float | None
    error_rate: float | None  # 0..1
    p50_ms: float | None
    p95_ms: float | None
    p99_ms: float | None


class ServicesOut(BaseModel):
    enabled: bool
    services: list[ServiceOut]


class TraceSummary(BaseModel):
    trace_id: str
    root_service: str | None
    root_name: str | None
    start_ms: int
    duration_ms: int
    matched: int


class Span(BaseModel):
    span_id: str | None
    parent_id: str | None
    name: str
    service: str | None
    host_id: str | None
    hostname: str | None = None
    kind: str
    start_ns: int
    duration_ns: int
    error: bool
    status_message: str | None
    attributes: dict
    events: list[dict]


def _window(start: int | None, end: int | None) -> tuple[int, int]:
    now = int(time.time())
    end = min(end or now, now + 60)
    start = start or end - 3600
    if start >= end:
        raise HTTPException(status_code=422, detail="start must be before end")
    if end - start > MAX_RANGE_S:
        raise HTTPException(status_code=422, detail="At most 7 days at a time")
    return start, end


async def _check_host(t: TenantContext, host_id: uuid.UUID | None) -> None:
    if host_id is None:
        return
    found = await t.db.scalar(
        select(Host.id).where(Host.id == host_id, Host.tenant_id == t.tenant_id)
    )
    if found is None:
        raise HTTPException(status_code=404, detail="Host not found")


def _errors(exc: Exception) -> HTTPException:
    if isinstance(exc, apm.BadQuery):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=503, detail="APM is unavailable right now")


@router.get("/services")
async def list_services(
    t: Tenant,
    host_id: uuid.UUID | None = None,
    start: int | None = None,
    end: int | None = None,
) -> ServicesOut:
    if not settings.TEMPO_URL:
        return ServicesOut(enabled=False, services=[])
    await _check_host(t, host_id)
    s, e = _window(start, end)
    try:
        found = await apm.services(t.tenant_id, s, e, host_id)
    except (apm.BadQuery, apm.ApmUnavailable) as exc:
        raise _errors(exc) from None
    return ServicesOut(enabled=True, services=[ServiceOut(**x) for x in found])


@router.get("/services/{name}/series")
async def service_series(
    name: str,
    t: Tenant,
    host_id: uuid.UUID | None = None,
    start: int | None = None,
    end: int | None = None,
) -> dict:
    if not settings.TEMPO_URL:
        raise HTTPException(status_code=404, detail="APM isn't enabled")
    await _check_host(t, host_id)
    s, e = _window(start, end)
    try:
        return await apm.service_series(t.tenant_id, name[:200], s, e, host_id)
    except (apm.BadQuery, apm.ApmUnavailable) as exc:
        raise _errors(exc) from None


@router.get("/traces")
async def search_traces(
    t: Tenant,
    service: Annotated[str | None, Query(max_length=200)] = None,
    name: Annotated[str | None, Query(max_length=200, description="span name contains")] = None,
    min_ms: Annotated[int | None, Query(ge=1, le=3_600_000)] = None,
    errors: bool = False,
    host_id: uuid.UUID | None = None,
    start: int | None = None,
    end: int | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[TraceSummary]:
    if not settings.TEMPO_URL:
        return []
    await _check_host(t, host_id)
    s, e = _window(start, end)
    try:
        found = await apm.search(t.tenant_id, s, e, limit, service, name, min_ms, errors, host_id)
    except (apm.BadQuery, apm.ApmUnavailable) as exc:
        raise _errors(exc) from None
    return [TraceSummary(**x) for x in found]


@router.get("/traces/{trace_id}")
async def get_trace(trace_id: str, t: Tenant) -> list[Span]:
    if not settings.TEMPO_URL:
        raise HTTPException(status_code=404, detail="APM isn't enabled")
    try:
        spans = await apm.trace(t.tenant_id, trace_id.lower())
    except (apm.BadQuery, apm.ApmUnavailable) as exc:
        raise _errors(exc) from None
    if spans is None:
        raise HTTPException(status_code=404, detail="Trace not found")
    host_ids = {s["host_id"] for s in spans if s["host_id"]}
    names: dict[str, str] = {}
    valid = []
    for h in host_ids:
        try:
            valid.append(uuid.UUID(h))
        except ValueError:
            continue
    if valid:
        rows = await t.db.execute(
            select(Host.id, Host.hostname).where(Host.id.in_(valid), Host.tenant_id == t.tenant_id)
        )
        names = {str(r.id): r.hostname for r in rows}
    return [Span(**s, hostname=names.get(s["host_id"] or "")) for s in spans]
