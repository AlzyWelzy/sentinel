"""Latest check results, as ingest stores them in Redis (ingest/cache.go):
one hash per check, one field per place it runs (a host id, or
"probe:<region>")."""

import json
import uuid

from app.services.heartbeats import redis

CHECK_RESULT_KEY = "pg:check:{check_id}"


async def latest(check_ids: list[uuid.UUID]) -> dict[uuid.UUID, list[dict]]:
    if not check_ids:
        return {}
    pipe = redis.pipeline()
    for cid in check_ids:
        pipe.hgetall(CHECK_RESULT_KEY.format(check_id=cid))
    out: dict[uuid.UUID, list[dict]] = {}
    for cid, fields in zip(check_ids, await pipe.execute(), strict=True):
        results = []
        for raw in (fields or {}).values():
            try:
                results.append(json.loads(raw))
            except ValueError:
                continue
        results.sort(key=lambda r: (r.get("region") or "", r.get("host_id") or ""))
        out[cid] = results
    return out


async def forget(check_id: uuid.UUID) -> None:
    await redis.delete(CHECK_RESULT_KEY.format(check_id=check_id))
