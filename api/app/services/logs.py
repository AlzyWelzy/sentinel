"""Log search over Loki. Every query goes out with the account's tenant id
as X-Scope-OrgID, so Loki itself keeps accounts apart; the LogQL is built
here from validated parts, never taken from the request."""

import json
import re
import uuid
from dataclasses import dataclass

import httpx

from app.config import settings

LEVELS = ("error", "warning", "info", "debug", "unknown")
MAX_PATTERN = 500


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
    # LogQL strings take Go escapes; JSON's are a compatible subset.
    return json.dumps(s)


def build_query(f: LogFilter) -> str:
    hosts = "|".join(str(uuid.UUID(str(h))) for h in f.host_ids)
    matchers = [f'host_id=~"{hosts}"']
    if f.source:
        matchers.append(f"source={_quote(f.source)}")
    if f.levels:
        bad = set(f.levels) - set(LEVELS)
        if bad:
            raise BadQuery(f"unknown level {sorted(bad)[0]!r}")
        matchers.append(f'level=~"{"|".join(f.levels)}"')
    query = "{" + ", ".join(matchers) + "}"
    if f.text:
        if len(f.text) > MAX_PATTERN:
            raise BadQuery("search text is too long")
        if f.regex:
            try:
                re.compile(f.text)
            except re.error as exc:
                raise BadQuery(f"invalid regular expression: {exc}") from None
            query += f" |~ {_quote(f.text)}"
        else:
            query += f" |~ {_quote('(?i)' + re.escape(f.text))}"
    return query


async def _get(tenant_id: uuid.UUID, path: str, params: dict) -> dict:
    if not settings.LOKI_URL:
        raise LogsUnavailable("log search isn't enabled")
    try:
        async with httpx.AsyncClient(base_url=settings.LOKI_URL) as client:
            response = await client.get(
                path, params=params, headers={"X-Scope-OrgID": str(tenant_id)}, timeout=20
            )
    except httpx.HTTPError as exc:
        raise LogsUnavailable(str(exc)) from exc
    if response.status_code == 400:
        raise BadQuery(response.text.strip()[:300])
    if response.status_code != 200:
        raise LogsUnavailable(f"HTTP {response.status_code}")
    return response.json()


async def search(
    tenant_id: uuid.UUID, f: LogFilter, start_ns: int, end_ns: int, limit: int
) -> list[dict]:
    """Newest first: {ts (ns), host_id, source, level, line}."""
    body = await _get(
        tenant_id,
        "/loki/api/v1/query_range",
        {
            "query": build_query(f),
            "start": start_ns,
            "end": end_ns,
            "limit": limit,
            "direction": "backward",
        },
    )
    out = []
    for stream in body["data"]["result"]:
        labels = stream["stream"]
        for ts, line in stream["values"]:
            out.append(
                {
                    "ts": int(ts),
                    "host_id": labels.get("host_id"),
                    "source": labels.get("source"),
                    "level": labels.get("level"),
                    "line": line,
                }
            )
    out.sort(key=lambda e: e["ts"], reverse=True)
    return out[:limit]


async def volume(
    tenant_id: uuid.UUID, f: LogFilter, start_s: int, end_s: int, step_s: int
) -> list[dict]:
    """Lines per step by level: [{level, points: [[unix s, count]]}]."""
    query = f"sum by (level) (count_over_time({build_query(f)} [{step_s}s]))"
    body = await _get(
        tenant_id,
        "/loki/api/v1/query_range",
        {"query": query, "start": start_s, "end": end_s, "step": step_s},
    )
    return [
        {
            "level": r["metric"].get("level", "unknown"),
            "points": [[int(float(ts)), int(float(v))] for ts, v in r["values"]],
        }
        for r in body["data"]["result"]
    ]


async def sources(
    tenant_id: uuid.UUID, host_ids: list[uuid.UUID], start_ns: int, end_ns: int
) -> list[str]:
    body = await _get(
        tenant_id,
        "/loki/api/v1/label/source/values",
        {"query": build_query(LogFilter(host_ids=host_ids)), "start": start_ns, "end": end_ns},
    )
    return sorted(body.get("data") or [])
