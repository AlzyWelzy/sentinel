"""Push checks, against the running ingest and alerter.

A push check with a one-minute interval: pushes keep it up, a push saying
down opens an incident with the push's message, the next up resolves it,
and silence past interval plus grace opens one saying how long it's been.
Bad tokens, bad statuses and floods are refused.

    uv run --no-project --with httpx python push_live.py
"""

import sys
import time

import httpx

from edgelib import account, bugs, check

INGEST = "http://localhost:8090"

c, _ = account()


def wait(what: str, fn, timeout: float = 300):
    deadline = time.time() + timeout
    while time.time() < deadline:
        v = fn()
        if v:
            return v
        time.sleep(5)
    print(f"timed out waiting for {what}")
    return None


r = c.post("/v1/checks", json={"name": "cron backup", "type": "push", "interval_seconds": 60,
                               "params": {"grace_seconds": "30"}})
check("push check created", r.status_code == 201, r.text)
pc = r.json()
url = pc["push_url"].replace("http://localhost:8090", INGEST)
token = url.rsplit("/", 1)[1]


def incidents(state: str = "open") -> list[dict]:
    return [i for i in c.get("/v1/incidents", params={"status": state}).json() if i.get("check_id") == pc["id"]]


check("unknown token is 404", httpx.get(f"{INGEST}/push/{'x' * 30}").status_code == 404)
check("malformed token is 404", httpx.get(f"{INGEST}/push/a$b").status_code == 404)
check("bad status is 400", httpx.get(url, params={"status": "maybe"}).status_code == 400)
check("bad ping is 400", httpx.get(url, params={"ping": "-3"}).status_code == 400)
check("GET push accepted", httpx.get(url, params={"msg": "ok", "ping": "12.5"}).json() == {"ok": True})
check("POST form push accepted", httpx.post(url, data={"status": "up"}).status_code == 200)
st = wait("status up", lambda: c.get(f"/v1/checks/{pc['id']}").json()["status"] == "up", 30)
check("check shows up after pushes", st)

httpx.get(url, params={"status": "down", "msg": "pg_dump: connection refused"})
inc = wait("incident from a down push", lambda: incidents(), 120)
check("down push opens an incident", inc)
if inc:
    detail = c.get(f"/v1/incidents/{inc[0]['id']}").json()
    check("incident carries the push message", "connection refused" in str(detail), str(detail)[:300])

httpx.get(url, params={"status": "up", "msg": "backup done"})
check("up push resolves it", wait("resolve", lambda: not incidents(), 120))

# Silence: interval 60s + grace 30s.
print("waiting for the push to go stale (about 90s)…")
inc = wait("incident from silence", lambda: incidents(), 240)
check("silence opens an incident", inc)
if inc:
    detail = c.get(f"/v1/incidents/{inc[0]['id']}").json()
    check("it says how long it's been quiet", "no push for" in str(detail), str(detail)[:300])
check("status shows down while silent", c.get(f"/v1/checks/{pc['id']}").json()["status"] == "down")
httpx.get(url)
check("a push after silence resolves it", wait("resolve", lambda: not incidents(), 120))

# Rotating the token kills the old URL.
new = c.post(f"/v1/checks/{pc['id']}/push-token").json()["push_url"]
check("old URL stops working", httpx.get(url).status_code == 404)
check("new URL works", httpx.get(new.replace("http://localhost:8090", INGEST)).status_code == 200)

# A paused check doesn't take pushes.
body = {k: pc[k] for k in ("name", "type", "target", "interval_seconds", "params")} | {"enabled": False}
c.put(f"/v1/checks/{pc['id']}", json=body)
check("paused check refuses pushes", httpx.get(new.replace("http://localhost:8090", INGEST)).status_code == 404)

# Flood: 30 a minute per token.
c.put(f"/v1/checks/{pc['id']}", json=body | {"enabled": True})
codes = [httpx.get(new.replace("http://localhost:8090", INGEST)).status_code for _ in range(40)]
check("a flood is rate limited", 429 in codes, str(codes))

print(f"\n{len(bugs)} bugs")
for b in bugs:
    print(" -", b)
sys.exit(1 if bugs else 0)
