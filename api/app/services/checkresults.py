"""Latest check results, as ingest stores them in Redis (ingest/cache.go):
one hash per check, one field per place it runs (a host id, or
"probe:<region>"), plus "fail:<field>" holding that place's last failure."""

import json
import uuid

from app.services.heartbeats import redis

CHECK_RESULT_KEY = "pg:check:{check_id}"


FAILURE_PREFIX = "fail:"


async def _hashes(check_ids: list[uuid.UUID]) -> list[dict]:
    pipe = redis.pipeline()
    for cid in check_ids:
        pipe.hgetall(CHECK_RESULT_KEY.format(check_id=cid))
    return await pipe.execute()


def _parse(raw: str) -> dict | None:
    try:
        return json.loads(raw)
    except ValueError:
        return None


async def latest(check_ids: list[uuid.UUID]) -> dict[uuid.UUID, list[dict]]:
    """The current result per place each check runs."""
    if not check_ids:
        return {}
    out: dict[uuid.UUID, list[dict]] = {}
    for cid, fields in zip(check_ids, await _hashes(check_ids), strict=True):
        results = [
            r
            for field, raw in (fields or {}).items()
            if not field.startswith(FAILURE_PREFIX) and (r := _parse(raw)) is not None
        ]
        results.sort(key=lambda r: (r.get("region") or "", r.get("host_id") or ""))
        out[cid] = results
    return out


async def last_failures(check_ids: list[uuid.UUID]) -> dict[uuid.UUID, dict]:
    """The most recent failure of each check, anywhere it runs."""
    if not check_ids:
        return {}
    out: dict[uuid.UUID, dict] = {}
    for cid, fields in zip(check_ids, await _hashes(check_ids), strict=True):
        fails = [
            r
            for field, raw in (fields or {}).items()
            if field.startswith(FAILURE_PREFIX) and (r := _parse(raw)) is not None
        ]
        if fails:
            out[cid] = max(fails, key=lambda r: r.get("ts", 0))
    return out


async def forget(check_id: uuid.UUID) -> None:
    await redis.delete(CHECK_RESULT_KEY.format(check_id=check_id))
