"""Catalog contacts, end to end, against the running API and alerter.

A local receiver stands in for self-hosted ntfy, Gotify, Mattermost, Matrix
and Signal servers (the dev alerter may reach private addresses). Each
contact gets its verification code through the provider, is verified with
it, and then receives a real incident's alert and recovery (a push check
reporting down, then up).

    uv run --no-project --with httpx python notifiers_live.py
"""

import json
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx

from edgelib import account, bugs, check

INGEST = "http://localhost:8090"
got: list[dict] = []


class Receiver(BaseHTTPRequestHandler):
    def _handle(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode(errors="replace")
        got.append({"method": self.command, "path": self.path, "headers": dict(self.headers), "body": body})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    do_POST = do_PUT = do_GET = _handle

    def log_message(self, *a):
        pass


srv = HTTPServer(("0.0.0.0", 0), Receiver)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
base = f"http://host.docker.internal:{port}"

c, _ = account()

CONTACTS = {
    "ntfy": {"server": base + "/ntfy", "topic": "sentinel-e2e", "token": "tk_live"},
    "gotify": {"server": base + "/gotify", "app_token": "AGOTIFYTOKEN"},
    "mattermost": {"webhook_url": base + "/mm/hooks/abc"},
    "matrix": {"server": base + "/matrix", "room_id": "!room:example.org", "access_token": "syt_live"},
    "signal": {"server": base + "/signal", "number": "+15550001111", "recipients": "+15550002222,+15550003333"},
}


def at(prefix: str) -> list[dict]:
    return [g for g in got if g["path"].startswith(prefix)]


def wait(fn, timeout=120):
    end = time.time() + timeout
    while time.time() < end:
        if v := fn():
            return v
        time.sleep(2)
    return None


ids = {}
for typ, fields in CONTACTS.items():
    r = c.post("/v1/channels", json={"type": typ, "fields": fields, "label": typ})
    check(f"{typ}: contact created", r.status_code == 201, r.text)
    if r.status_code == 201:
        ids[typ] = r.json()["id"]
        check(f"{typ}: secrets masked", all(v not in r.text for k, v in fields.items() if "token" in k))

prefixes = {"ntfy": "/ntfy/", "gotify": "/gotify/", "mattermost": "/mm/", "matrix": "/matrix/", "signal": "/signal/"}
for typ, cid in ids.items():
    req = wait(lambda: at(prefixes[typ]), 90)
    check(f"{typ}: verification delivered", req, f"nothing at {prefixes[typ]}")
    if not req:
        continue
    blob = json.dumps(req[0])
    code = re.search(r"\b(\d{6})\b", blob)
    check(f"{typ}: code in the message", code, blob[:300])
    if code:
        v = c.post(f"/v1/channels/{cid}/verify", json={"code": code.group(1)})
        check(f"{typ}: verified with the code", v.status_code == 200 and v.json()["verified"], v.text)

ntfy = at("/ntfy/")
if ntfy:
    h = {k.lower(): v for k, v in ntfy[0]["headers"].items()}
    check("ntfy: bearer token sent", h.get("authorization") == "Bearer tk_live", h)
    check("ntfy: path is the topic", ntfy[0]["path"] == "/ntfy/sentinel-e2e", ntfy[0]["path"])
mx = at("/matrix/")
if mx:
    check("matrix: PUT with a transaction id", mx[0]["method"] == "PUT" and "/send/m.room.message/" in mx[0]["path"], mx[0])
sg = at("/signal/")
if sg:
    check("signal: recipients split", json.loads(sg[0]["body"]).get("recipients") == ["+15550002222", "+15550003333"], sg[0]["body"])

# A real incident: a push check that reports down, then up.
before = len(got)
pc = c.post("/v1/checks", json={"name": "e2e notifier job", "type": "push", "interval_seconds": 3600}).json()
url = pc["push_url"]
rule = c.get(f"/v1/alert-rules/{pc['rule_id']}").json()
keep = ("name", "kind", "target", "duration_seconds", "severity", "enabled")
r = c.put(f"/v1/alert-rules/{pc['rule_id']}", json={k: rule[k] for k in keep} | {"channel_ids": list(ids.values())})
check("rule sends to the catalog contacts", r.status_code == 200, r.text)
httpx.get(url, params={"status": "down", "msg": "job exploded"})
fired = wait(lambda: len({g["path"].split("/")[1] for g in got[before:]}) >= len(ids), 180)
check("every verified contact got the alert", fired, sorted({g["path"].split("/")[1] for g in got[before:]}))
check("the alert names the failure", any("job exploded" in g["body"] for g in got[before:]))
mid = len(got)
httpx.get(url, params={"status": "up"})
resolved = wait(lambda: len({g["path"].split("/")[1] for g in got[mid:]}) >= len(ids), 180)
check("every contact got the recovery", resolved, sorted({g["path"].split("/")[1] for g in got[mid:]}))
gt = [g for g in got[mid:] if g["path"].startswith("/gotify/")]
if gt:
    check("gotify: priority is a number", isinstance(json.loads(gt[0]["body"]).get("priority"), int), gt[0]["body"])

# Deliveries carry no secrets.
for typ, cid in ids.items():
    d = c.get("/v1/incidents").json()
    check(f"{typ}: token not in incidents", "tk_live" not in json.dumps(d) and "syt_live" not in json.dumps(d))
    break

print(f"\n{len(bugs)} bugs")
for b in bugs:
    print(" -", b)
sys.exit(1 if bugs else 0)
