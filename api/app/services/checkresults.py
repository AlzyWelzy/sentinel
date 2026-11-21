"""Latest check results, as ingest stores them in Redis (ingest/cache.go):
one hash per check, one field per place it runs (a host id, or
"probe:<region>"), plus "fail:<field>" holding that place's last failure."""

import base64
import json
import uuid

from app.services.heartbeats import redis

CHECK_RESULT_KEY = "pg:check:{check_id}"


FAILURE_PREFIX = "fail:"
DIAGNOSIS_PREFIX = "diag:"
# A diagnosis is shown with a failure for this long after the agent made it.
DIAGNOSIS_FRESH_MS = 30 * 60 * 1000


def _with_diagnosis(result: dict, fields: dict, field: str) -> dict:
    """Attach the place's latest diagnosis to a failing result, if fresh."""
    if result.get("ok") or result.get("diagnosis"):
        return result
    stored = _parse(fields.get(DIAGNOSIS_PREFIX + field) or "")
    if stored and result.get("ts", 0) - stored.get("ts", 0) < DIAGNOSIS_FRESH_MS:
        return {**result, "diagnosis": stored.get("diagnosis")}
    return result


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
        fields = fields or {}
        results = [
            _with_diagnosis(r, fields, field)
            for field, raw in fields.items()
            if not field.startswith((FAILURE_PREFIX, DIAGNOSIS_PREFIX))
            and (r := _parse(raw)) is not None
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
        fields = fields or {}
        fails = [
            _with_diagnosis(r, fields, field.removeprefix(FAILURE_PREFIX))
            for field, raw in fields.items()
            if field.startswith(FAILURE_PREFIX) and (r := _parse(raw)) is not None
        ]
        if fails:
            out[cid] = max(fails, key=lambda r: r.get("ts", 0))
    return out


CHECK_SHOT_KEY = "pg:checkshot:{check_id}"


async def screenshot(check_id: uuid.UUID) -> tuple[int, bytes, str] | None:
    """The newest failure screenshot of a browser check: (ts, jpeg, place)."""
    fields = await redis.hgetall(CHECK_SHOT_KEY.format(check_id=check_id)) or {}
    best: tuple[int, bytes, str] | None = None
    for place_raw, raw in fields.items():
        place = place_raw.decode() if isinstance(place_raw, bytes) else place_raw
        v = _parse(raw.decode() if isinstance(raw, bytes) else raw)
        if not v or not isinstance(v.get("jpeg"), str):
            continue
        try:
            jpeg = base64.b64decode(v["jpeg"], validate=True)
        except ValueError:
            continue
        if best is None or v.get("ts", 0) > best[0]:
            best = (int(v.get("ts", 0)), jpeg, place)
    return best


async def forget(check_id: uuid.UUID) -> None:
    await redis.delete(
        CHECK_RESULT_KEY.format(check_id=check_id), CHECK_SHOT_KEY.format(check_id=check_id)
    )
