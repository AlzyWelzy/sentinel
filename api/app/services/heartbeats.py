import time
import uuid

from redis.asyncio import Redis

from app.config import settings

# Key layout shared with ingest (ingest/cache.go). Change both together.
LAST_SEEN_KEY = "pg:last_seen:{host_id}"
HOST_TOKEN_CACHE_KEY = "pg:host_token:{token_hash}"

redis = Redis.from_url(settings.REDIS_URL, decode_responses=True)


async def last_seen(host_ids: list[uuid.UUID]) -> dict[uuid.UUID, int | None]:
    if not host_ids:
        return {}
    values = await redis.mget([LAST_SEEN_KEY.format(host_id=h) for h in host_ids])
    return {h: int(v) if v else None for h, v in zip(host_ids, values, strict=True)}


def is_online(last_seen_ts: int | None) -> bool:
    if last_seen_ts is None:
        return False
    return time.time() - last_seen_ts < settings.HOST_OFFLINE_AFTER_SECONDS


async def forget_host_tokens(token_hashes: list[str]) -> None:
    """Drop ingest's cached token lookups so a revoke or suspend takes effect now."""
    if token_hashes:
        await redis.delete(*[HOST_TOKEN_CACHE_KEY.format(token_hash=t) for t in token_hashes])


async def clock_ahead(host_id: uuid.UUID) -> int | None:
    """Seconds the host's clock runs fast, when over a minute (ingest/cache.go)."""
    v = await redis.get(f"pg:clock_ahead:{host_id}")
    return int(v) if v else None
