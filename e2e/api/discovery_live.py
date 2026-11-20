"""Network discovery end to end: a real agent scans one address where the
SNMP simulator listens (this machine's LAN address, so nothing else on the
network is probed) and the device can be added from the results.

    SCAN_IP=$(ipconfig getifaddr en0) AGENT=/tmp/sentinel-agent \\
        uv run --no-project --with httpx python discovery_live.py
"""

import os
import subprocess
import sys
import tempfile
import time

from edgelib import INGEST, account, bugs, check

AGENT = os.environ.get("AGENT", "/tmp/sentinel-agent")
IP = os.environ["SCAN_IP"]

c, _ = account()
key = c.post("/v1/agent-keys", json={"name": "site"}).json()["key"]
sd = tempfile.mkdtemp(prefix="disc-")
subprocess.run([AGENT, "register", "--url", INGEST, "--key", key, "--state-dir", sd], check=True, capture_output=True)
agent = subprocess.Popen([AGENT, "run", "--state-dir", sd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    poller = next(h for h in c.get("/v1/hosts").json() if h["kind"] == "server")
    cred = c.post("/v1/network/credentials", json={"name": "a", "version": "2c", "community": "arista-eos"}).json()
    r = c.post("/v1/network/discoveries", json={"cidr": f"{IP}/32", "port": 1161, "credential_id": cred["id"],
                                                "poller_host_id": poller["id"]})
    check("scan started", r.status_code == 201, r.text)
    did = r.json()["id"]
    d = {}
    for _ in range(40):
        d = c.get(f"/v1/network/discoveries/{did}").json()
        if d["status"] == "done":
            break
        time.sleep(3)
    check("scan finished", d["status"] == "done", d)
    check("found the switch", [f["sys_name"] for f in d["found"]] == ["host-redacted"], d["found"])
    check("vendor detected", d["found"] and d["found"][0]["vendor"] == "Arista", d["found"])
    addr = d["found"][0]["address"]
    r = c.post("/v1/network/devices", json={"addresses": [addr], "credential_id": cred["id"],
                                            "poller_host_id": poller["id"]})
    check("added from the results", r.status_code == 201 and r.json()["created"], r.text)
    d = c.get(f"/v1/network/discoveries/{did}").json()
    check("marked as added", d["found"][0]["already_added"], d["found"])
finally:
    agent.terminate()

print("\nBUGS:", len(bugs))
for b in bugs:
    print(" -", b)
sys.exit(1 if bugs else 0)
