"""Fixed-window request limits in Redis, shared by every API replica.

Used where abuse costs something: sign-up, sign-in, password reset and
resending emails. A limit is per key (an address, an email), so one
attacker can't lock everyone out and one user can't be locked out by
others guessing at their address from many places (the per-email limits
are higher than the per-address ones).
"""

import time

from fastapi import HTTPException, Request, status

from app.services.heartbeats import redis


def client_ip(request: Request) -> str:
    # Caddy is the only thing in front of the API and sets X-Forwarded-For;
    # the last hop is the one Caddy saw.
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


async def hit(bucket: str, key: str, limit: int, window_seconds: int) -> None:
    """Count one attempt; refuse with 429 once over the limit for this window."""
    window = int(time.time()) // window_seconds
    k = f"pg:rl:{bucket}:{key}:{window}"
    pipe = redis.pipeline()
    pipe.incr(k)
    pipe.expire(k, window_seconds)
    count, _ = await pipe.execute()
    if int(count) > limit:
        retry = window_seconds - int(time.time()) % window_seconds
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many attempts. Try again later.",
            headers={"Retry-After": str(retry)},
        )


async def reset(bucket: str, key: str, window_seconds: int) -> None:
    window = int(time.time()) // window_seconds
    await redis.delete(f"pg:rl:{bucket}:{key}:{window}")
