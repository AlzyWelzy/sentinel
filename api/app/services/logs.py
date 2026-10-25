"""Log search over VictoriaLogs. Every request goes out with the tenant's own
VictoriaLogs account (the AccountID header, tenants.logs_account_id), so the
store itself keeps accounts apart; the LogsQL is built here from validated
parts, never taken from the request."""

import json
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import Tenant

LEVELS = ("error", "warning", "info", "debug", "unknown")
MAX_PATTERN = 500
# RE2's metacharacters. Python's re.escape also escapes spaces and other
# characters, which RE2 rejects as unknown escapes.
_RE2_META = re.compile(r"([\\.+*?()|\[\]{}^$])")


class LogsUnavailable(Exception):
    pass


class BadQuery(Exception):
    pass


@dataclass(frozen=True)
class LogFilter:
    host_ids: list[uuid.UUID]
    text: str | None = None
    regex: bool = False
    source: str | None = None
    levels: tuple[str, ...] = ()


def _quote(s: str) -> str:
    # LogsQL strings take Go escapes; JSON's are a compatible subset.
    return json.dumps(s)


def escape(text: str) -> str:
    return _RE2_META.sub(r"\\\1", text)


def text_filter(f: LogFilter) -> str:
    """The part of a query that doesn't depend on hosts: source, level and
    text. Log alert rules store this and the alerter adds the hosts."""
    parts = []
    if f.source:
        parts.append(f"source:={_quote(f.source)}")
    if f.levels:
        bad = set(f.levels) - set(LEVELS)
        if bad:
            raise BadQuery(f"unknown level {sorted(bad)[0]!r}")
        parts.append(f"level:in({', '.join(f.levels)})")
    if f.text:
        if len(f.text) > MAX_PATTERN:
            raise BadQuery("search text is too long")
        if f.regex:
            try:
                re.compile(f.text)
            except re.error as exc:
                raise BadQuery(f"invalid regular expression: {exc}") from None
            parts.append(f"_msg:~{_quote(f.text)}")
        else:
            parts.append(f"_msg:~{_quote('(?i)' + escape(f.text))}")
    return " ".join(parts)


def build_query(f: LogFilter) -> str:
    hosts = "|".join(str(uuid.UUID(str(h))) for h in f.host_ids)
    rest = text_filter(f)
    return f'{{host_id=~"{hosts}"}}' + (f" {rest}" if rest else "")


def _rfc3339(ns: int) -> str:
    whole, frac = divmod(ns, 10**9)
    return datetime.fromtimestamp(whole, UTC).strftime("%Y-%m-%dT%H:%M:%S") + f".{frac:09d}Z"


def _ns(value: str) -> int:
    """VictoriaLogs' RFC3339 timestamps (nanoseconds, Z) to unix ns."""
    head, _, frac = value.rstrip("Z").partition(".")
    base = datetime.strptime(head, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC)
    return int(base.timestamp()) * 10**9 + int((frac or "0").ljust(9, "0")[:9])


async def account_id(db: AsyncSession, tenant_id: uuid.UUID) -> int:
    value = await db.scalar(select(Tenant.logs_account_id).where(Tenant.id == tenant_id))
    if value is None:
        raise LogsUnavailable("no log account")
    return int(value)


async def _get(account: int, path: str, params: dict) -> httpx.Response:
    if not settings.VICTORIALOGS_URL:
        raise LogsUnavailable("log search isn't enabled")
    try:
        async with httpx.AsyncClient(base_url=settings.VICTORIALOGS_URL) as client:
            response = await client.get(
                path,
                params=params,
                headers={"AccountID": str(account), "ProjectID": "0"},
                timeout=20,
            )
    except httpx.HTTPError as exc:
        raise LogsUnavailable(str(exc)) from exc
    if response.status_code == 400:
        raise BadQuery(response.text.strip()[:300])
    if response.status_code != 200:
        raise LogsUnavailable(f"HTTP {response.status_code}")
    return response


async def search(account: int, f: LogFilter, start_ns: int, end_ns: int, limit: int) -> list[dict]:
    """Newest first: {ts (ns), host_id, source, level, line}."""
    response = await _get(
        account,
        "/select/logsql/query",
        {
            "query": f"{build_query(f)} | sort by (_time desc) | limit {int(limit)}",
            "start": _rfc3339(start_ns),
            "end": _rfc3339(end_ns),
        },
    )
    out = []
    for raw in response.text.splitlines():
        if not raw.strip():
            continue
        row = json.loads(raw)
        out.append(
            {
                "ts": _ns(row["_time"]),
                "host_id": row.get("host_id"),
                "source": row.get("source"),
                "level": row.get("level"),
                "line": row.get("_msg", ""),
            }
        )
    out.sort(key=lambda e: e["ts"], reverse=True)
    return out[:limit]


async def volume(account: int, f: LogFilter, start_s: int, end_s: int, step_s: int) -> list[dict]:
    """Lines per step by level: [{level, points: [[unix s, count]]}]."""
    response = await _get(
        account,
        "/select/logsql/hits",
        {
            "query": build_query(f),
            "start": start_s,
            "end": end_s,
            "step": f"{int(step_s)}s",
            "field": "level",
        },
    )
    out = []
    for h in response.json().get("hits") or []:
        points = [
            [_ns(ts) // 10**9, int(v)]
            for ts, v in zip(h.get("timestamps") or [], h.get("values") or [], strict=False)
        ]
        out.append({"level": (h.get("fields") or {}).get("level") or "unknown", "points": points})
    return out


async def hits_by_host(
    account: int, f: LogFilter, start_s: int, end_s: int, step_s: int
) -> dict[str, list[list[float]]]:
    """Matching lines per step, per host: {host_id: [[unix s, count]]}."""
    response = await _get(
        account,
        "/select/logsql/hits",
        {
            "query": build_query(f),
            "start": start_s,
            "end": end_s,
            "step": f"{int(step_s)}s",
            "field": "host_id",
        },
    )
    out: dict[str, list[list[float]]] = {}
    for h in response.json().get("hits") or []:
        host = (h.get("fields") or {}).get("host_id") or ""
        out[host] = [
            [_ns(ts) / 10**9, float(v)]
            for ts, v in zip(h.get("timestamps") or [], h.get("values") or [], strict=False)
        ]
    return out


async def sources(account: int, host_ids: list[uuid.UUID], start_ns: int, end_ns: int) -> list[str]:
    response = await _get(
        account,
        "/select/logsql/field_values",
        {
            "query": build_query(LogFilter(host_ids=host_ids)),
            "field": "source",
            "start": _rfc3339(start_ns),
            "end": _rfc3339(end_ns),
            "limit": 500,
        },
    )
    return sorted(v["value"] for v in response.json().get("values") or [] if v.get("value"))
