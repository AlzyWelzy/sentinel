"""Cloudflare for SaaS custom hostnames: a customer's status page domain,
once verified, is added to Sentinel's zone so Cloudflare issues its
certificate and sends its traffic down the tunnel to Caddy."""

import logging

import httpx

from app.config import settings

log = logging.getLogger(__name__)
API = "https://api.cloudflare.com/client/v4"


def enabled() -> bool:
    return bool(settings.CF_API_TOKEN and settings.CF_ZONE_ID)


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=f"{API}/zones/{settings.CF_ZONE_ID}",
        headers={"Authorization": f"Bearer {settings.CF_API_TOKEN}"},
        timeout=20,
    )


async def _find(c: httpx.AsyncClient, hostname: str) -> str | None:
    r = await c.get("/custom_hostnames", params={"hostname": hostname})
    r.raise_for_status()
    found = [h for h in r.json().get("result", []) if h.get("hostname") == hostname]
    return found[0]["id"] if found else None


async def add(hostname: str) -> str | None:
    """Add (or keep) the custom hostname; returns None when done, else why
    not. Certificates are validated over HTTP through the CNAME."""
    if not enabled():
        return None
    try:
        async with _client() as c:
            if await _find(c, hostname):
                return None
            r = await c.post(
                "/custom_hostnames",
                json={"hostname": hostname, "ssl": {"method": "http", "type": "dv"}},
            )
            if r.status_code >= 300:
                errs = r.json().get("errors") or [{"message": r.text[:200]}]
                return "; ".join(str(e.get("message")) for e in errs)
    except httpx.HTTPError as exc:
        log.warning("custom hostname add failed for %s: %s", hostname, exc)
        return "Cloudflare didn't answer; try verifying again in a minute"
    return None


async def remove(hostname: str) -> None:
    if not enabled():
        return
    try:
        async with _client() as c:
            if hid := await _find(c, hostname):
                (await c.delete(f"/custom_hostnames/{hid}")).raise_for_status()
    except httpx.HTTPError as exc:
        log.warning("custom hostname removal failed for %s: %s", hostname, exc)


async def status(hostname: str) -> dict | None:
    """Cloudflare's view: hostname and certificate state."""
    if not enabled():
        return None
    try:
        async with _client() as c:
            r = await c.get("/custom_hostnames", params={"hostname": hostname})
            r.raise_for_status()
            for h in r.json().get("result", []):
                if h.get("hostname") == hostname:
                    return {"status": h.get("status"), "ssl": (h.get("ssl") or {}).get("status")}
    except httpx.HTTPError:
        return None
    return None
