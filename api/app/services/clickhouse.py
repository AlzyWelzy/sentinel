"""ClickHouse over HTTP, for IPDR evidence. Queries are built in code with
every value passed as a typed query parameter ({name:Type}), never spliced
into the SQL."""

from collections.abc import Mapping
from typing import Any

import httpx

from app.config import settings


class EvidenceUnavailable(Exception):
    pass


def enabled() -> bool:
    return bool(settings.CLICKHOUSE_URL)


def _params(query: str, params: Mapping[str, Any], fmt: str) -> dict[str, str]:
    # WHERE src_ip means the column even when the SELECT renders it as text.
    out = {
        "query": f"{query} FORMAT {fmt}",
        "database": settings.CLICKHOUSE_DB,
        "prefer_column_name_to_alias": "1",
    }
    for k, v in params.items():
        out[f"param_{k}"] = str(v)
    return out


async def _post(query: str, params: Mapping[str, Any], fmt: str, seconds: float) -> httpx.Response:
    if not enabled():
        raise EvidenceUnavailable("IPDR isn't set up on this server")
    try:
        async with httpx.AsyncClient(timeout=seconds) as c:
            r = await c.post(
                settings.CLICKHOUSE_URL.rstrip("/") + "/",
                params=_params(query, params, fmt),
                auth=(settings.CLICKHOUSE_USER, settings.CLICKHOUSE_PASSWORD),
            )
    except httpx.HTTPError as exc:
        raise EvidenceUnavailable("the evidence store isn't answering") from exc
    if r.status_code != 200:
        raise EvidenceUnavailable(f"evidence query failed: {r.text[:300]}")
    return r


async def rows(query: str, params: Mapping[str, Any], seconds: float = 60) -> list[dict]:
    r = await _post(query, params, "JSON", seconds)
    return r.json().get("data", [])


async def csv(query: str, params: Mapping[str, Any], seconds: float = 600) -> bytes:
    return (await _post(query, params, "CSVWithNames", seconds)).content


async def command(query: str, params: Mapping[str, Any] | None = None) -> None:
    if not enabled():
        return
    async with httpx.AsyncClient(timeout=120) as c:
        r = await c.post(
            settings.CLICKHOUSE_URL.rstrip("/") + "/",
            params={"query": query, "database": settings.CLICKHOUSE_DB}
            | {f"param_{k}": str(v) for k, v in (params or {}).items()},
            auth=(settings.CLICKHOUSE_USER, settings.CLICKHOUSE_PASSWORD),
        )
    if r.status_code != 200:
        raise EvidenceUnavailable(r.text[:300])
