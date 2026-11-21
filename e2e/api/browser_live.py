"""Real-browser checks end to end: a real agent (with Chromium) signs in to
a local page through steps. Breaking the page opens an incident naming the
failing step, with a screenshot; fixing it resolves the incident.

    AGENT=/path/sentinel-agent SENTINEL_CHROME=/path/to/chromium \\
      uv run --no-project --with httpx python browser_live.py
"""

import os
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from edgelib import account, bugs, check

AGENT = os.environ.get("AGENT", "/tmp/sentinel-agent")
INGEST = "http://localhost:8090"
state = {"broken": False}

PAGE = """<!doctype html><html><body><input id="user"><input id="pw" type="password">
<button id="go">Sign in</button><div id="out"></div><script>
document.getElementById("go").onclick = () => {
  const ok = document.getElementById("user").value === "ada" && document.getElementById("pw").value === "s3cret";
  document.getElementById("out").textContent = ok && !BROKEN ? "Welcome, Ada" : "Something went wrong";
};</script></body></html>"""


class Site(BaseHTTPRequestHandler):
    def do_GET(self):
        body = PAGE.replace("BROKEN", "true" if state["broken"] else "false").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


srv = HTTPServer(("127.0.0.1", 0), Site)
threading.Thread(target=srv.serve_forever, daemon=True).start()
url = f"http://127.0.0.1:{srv.server_address[1]}/"


def wait(what, fn, timeout=480):
    end = time.time() + timeout
    while time.time() < end:
        if v := fn():
            return v
        time.sleep(3)
    print(f"timed out waiting for {what}")
    return None


c, _ = account()
key = c.post("/v1/agent-keys", json={"name": "browser box"}).json()["key"]
sd = tempfile.mkdtemp(prefix="browser-agent-")
subprocess.run([AGENT, "register", "--url", INGEST, "--key", key, "--state-dir", sd], check=True, capture_output=True)
agent = subprocess.Popen([AGENT, "run", "--state-dir", sd], stdout=open(f"{sd}/agent.log", "w"), stderr=subprocess.STDOUT)
try:
    host = wait("the agent", lambda: next(iter(c.get("/v1/hosts").json()), None))
    steps = (
        '[{"action":"type","selector":"#user","text":"{{username}}"},'
        '{"action":"type","selector":"#pw","text":"{{password}}"},'
        '{"action":"click","selector":"#go"},{"action":"expect_text","text":"Welcome, Ada"}]'
    )
    r = c.post("/v1/checks", json={
        "name": "sign-in journey", "type": "browser", "target": url, "host_id": host["id"],
        "interval_seconds": 60, "params": {"steps": steps, "username": "ada", "password": "s3cret"},
    })  # fmt: skip
    check("browser check created", r.status_code == 201, r.text)
    cid = r.json()["id"]
    get = lambda: c.get(f"/v1/checks/{cid}").json()  # noqa: E731
    up = wait("the first run", lambda: get()["status"] == "up" and get())
    check("journey passes", up, get())
    if up:
        check("detail counts the steps", "4 steps passed" in up["results"][0]["detail"], up["results"][0])

    state["broken"] = True
    inc = wait("an incident", lambda: print("  status:", get()["status"], (get()["results"] or [{}])[0].get("detail", "")[:80]) or next((i for i in c.get("/v1/incidents").json() if i.get("check_id") == cid and i["status"] == "open"), None))
    check("incident opened", inc)
    if inc:
        full = c.get(f"/v1/incidents/{inc['id']}").json()
        text = (full.get("detail") or "") + full.get("summary", "")
        check("names the failing step", "step 4" in text and "Welcome, Ada" in text, text)
        check("password not in the incident", "s3cret" not in str(full))
    shot = c.get(f"/v1/checks/{cid}/screenshot")
    check("screenshot kept", shot.status_code == 200 and shot.content[:2] == b"\xff\xd8", (shot.status_code, len(shot.content)))
    if shot.status_code == 200:
        open(os.path.join(sd, "failure.jpg"), "wb").write(shot.content)
        print("screenshot:", os.path.join(sd, "failure.jpg"))

    state["broken"] = False
    check("resolves when fixed", wait("recovery", lambda: next((i for i in c.get("/v1/incidents", params={"status": "resolved"}).json() if i.get("check_id") == cid), None)))
finally:
    agent.terminate()
    agent.wait(10)

print(f"\n{len(bugs)} bugs")
for b in bugs:
    print(" -", b)
sys.exit(1 if bugs else 0)
