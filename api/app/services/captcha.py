"""Cloudflare Turnstile, checked server-side on sign-up and password reset."""

import logging

import httpx
from fastapi import HTTPException, status

from app.config import settings

log = logging.getLogger(__name__)

SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


def enabled() -> bool:
    return bool(settings.TURNSTILE_SECRET_KEY) and not settings.CAPTCHA_DISABLED


async def require(token: str | None, remote_ip: str) -> None:
    if not enabled():
        return
    if not token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Complete the captcha")
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(
                SITEVERIFY_URL,
                data={
                    "secret": settings.TURNSTILE_SECRET_KEY,
                    "response": token,
                    "remoteip": remote_ip,
                },
            )
            r.raise_for_status()
            ok = bool(r.json().get("success"))
    except (httpx.HTTPError, ValueError):
        log.warning("Turnstile siteverify unavailable")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Couldn't check the captcha, try again",
        ) from None
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Captcha failed, try again"
        )
