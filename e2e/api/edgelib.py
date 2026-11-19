"""Helpers for edge-case probes against the dev stack. Each check prints OK or BUG."""

import os
import re
import secrets
import time

import httpx

API = os.environ.get("API", "http://localhost:8010/api")
INGEST = os.environ.get("INGEST", "http://localhost:8090")
MAIL = os.environ.get("MAILPIT", "http://localhost:8035") + "/api/v1"
H = {"X-Requested-With": "sentinel"}
bugs: list[str] = []


def check(name: str, ok: bool, detail: object = "") -> None:
    print(("OK   " if ok else "BUG  ") + name + ("" if ok else f"  -> {detail}"))
    if not ok:
        bugs.append(name)


def link_for(email: str, kind: str = "verify") -> str:
    """The newest link of this kind emailed to this address."""
    for _ in range(40):
        r = httpx.get(f"{MAIL}/search", params={"query": f"to:{email}"}).json()
        for m in r.get("messages", []):
            body = httpx.get(f"{MAIL}/message/{m['ID']}").json()["Text"]
            for u in re.findall(r"https?://\S+", body):
                if kind in u:
                    return u
        time.sleep(0.5)
    raise RuntimeError(f"no {kind} mail for {email}")


def account(email: str | None = None, pw: str = "edge password 123") -> tuple[httpx.Client, str]:
    """A confirmed, signed-in user with an organisation selected."""
    email = email or f"edge-{secrets.token_hex(4)}@example.com"
    c = httpx.Client(base_url=API, headers=H, timeout=30)
    r = c.post("/auth/signup", json={"email": email, "password": pw})
    assert r.status_code < 300, r.text
    token = link_for(email.lower()).split("token=")[1].split("&")[0]
    assert c.post("/auth/verify", json={"token": token}).status_code < 300
    r = c.post("/auth/login", json={"email": email, "password": pw})
    assert r.status_code == 200, r.text
    c.headers["Authorization"] = "Bearer " + r.json()["access_token"]
    orgs = c.get("/v1/me/accounts").json()
    if not orgs:
        orgs = [c.post("/v1/organisations", json={"name": "Edge org"}).json()]
    c.headers["X-Sentinel-Account"] = orgs[0]["tenant_id"]
    return c, email


def no500(name: str, r: httpx.Response) -> None:
    check(f"{name} (no 500)", r.status_code < 500, f"{r.status_code} {r.text[:200]}")
