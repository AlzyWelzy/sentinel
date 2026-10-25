"""Log search: lines shipped by agents whose server lists them in logs.conf."""

import time
import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select

from app.config import settings
from app.models import Host
from app.services import logs as logstore
from app.tenancy import Tenant, TenantContext

router = APIRouter(prefix="/v1/logs")

MAX_RANGE_S = 14 * 86400


class LogLine(BaseModel):
    ts: int  # unix nanoseconds
    host_id: uuid.UUID | None
    hostname: str | None
    source: str | None
    level: str | None
    line: str


class LogSearch(BaseModel):
    enabled: bool
    lines: list[LogLine]
    limit: int


class VolumeSeries(BaseModel):
    level: str
    points: list[list[int]]


async def _hosts(t: TenantContext, host_id: uuid.UUID | None) -> dict[uuid.UUID, str]:
    q = select(Host.id, Host.hostname).where(
        Host.tenant_id == t.tenant_id, Host.revoked_at.is_(None)
    )
    if host_id is not None:
        q = q.where(Host.id == host_id)
    hosts = {row.id: row.hostname for row in await t.db.execute(q)}
    if host_id is not None and not hosts:
        raise HTTPException(status_code=404, detail="Host not found")
    return hosts


def _window(start: int | None, end: int | None) -> tuple[int, int]:
    now = int(time.time())
    end = min(end or now, now)
    start = start or end - 3600
    if start >= end:
        raise HTTPException(status_code=422, detail="start must be before end")
    if end - start > MAX_RANGE_S:
        raise HTTPException(status_code=422, detail="At most 14 days at a time")
    return start, end


def _filter(hosts, q, regex, source, level) -> logstore.LogFilter:
    return logstore.LogFilter(
        host_ids=list(hosts),
        text=q or None,
        regex=regex,
        source=source or None,
        levels=tuple(level or ()),
    )


def _errors(exc: Exception) -> HTTPException:
    if isinstance(exc, logstore.BadQuery):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=503, detail="Log search is unavailable right now")


@router.get("")
async def search_logs(
    t: Tenant,
    q: Annotated[str | None, Query(max_length=500, description="text to find (any case)")] = None,
    regex: bool = False,
    host_id: uuid.UUID | None = None,
    source: str | None = None,
    level: Annotated[list[str] | None, Query()] = None,
    start: Annotated[int | None, Query(description="unix seconds; default an hour ago")] = None,
    end: Annotated[int | None, Query(description="unix seconds; default now")] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> LogSearch:
    if not settings.LOKI_URL:
        return LogSearch(enabled=False, lines=[], limit=limit)
    hosts = await _hosts(t, host_id)
    if not hosts:
        return LogSearch(enabled=True, lines=[], limit=limit)
    s, e = _window(start, end)
    try:
        found = await logstore.search(
            t.tenant_id, _filter(hosts, q, regex, source, level), s * 10**9, e * 10**9, limit
        )
    except (logstore.BadQuery, logstore.LogsUnavailable) as exc:
        raise _errors(exc) from None
    lines = []
    for row in found:
        hid = uuid.UUID(row["host_id"]) if row["host_id"] else None
        lines.append(
            LogLine(
                ts=row["ts"],
                host_id=hid,
                hostname=hosts.get(hid) if hid else None,
                source=row["source"],
                level=row["level"],
                line=row["line"],
            )
        )
    return LogSearch(enabled=True, lines=lines, limit=limit)


@router.get("/volume")
async def log_volume(
    t: Tenant,
    q: Annotated[str | None, Query(max_length=500)] = None,
    regex: bool = False,
    host_id: uuid.UUID | None = None,
    source: str | None = None,
    level: Annotated[list[str] | None, Query()] = None,
    start: int | None = None,
    end: int | None = None,
) -> list[VolumeSeries]:
    if not settings.LOKI_URL:
        return []
    hosts = await _hosts(t, host_id)
    if not hosts:
        return []
    s, e = _window(start, end)
    step = max(60, (e - s) // 60)
    try:
        series = await logstore.volume(
            t.tenant_id, _filter(hosts, q, regex, source, level), s, e, step
        )
    except (logstore.BadQuery, logstore.LogsUnavailable) as exc:
        raise _errors(exc) from None
    return [VolumeSeries(**x) for x in series]


@router.get("/sources")
async def log_sources(
    t: Tenant, host_id: uuid.UUID | None = None, start: int | None = None, end: int | None = None
) -> list[str]:
    if not settings.LOKI_URL:
        return []
    hosts = await _hosts(t, host_id)
    if not hosts:
        return []
    s, e = _window(start or int(time.time()) - 86400, end)
    try:
        return await logstore.sources(t.tenant_id, list(hosts), s * 10**9, e * 10**9)
    except (logstore.BadQuery, logstore.LogsUnavailable) as exc:
        raise _errors(exc) from None
