"""Sets up an organisation with a running poller and simulated devices for
the network UI check (network_ui.mjs), then keeps the agent running.
Prints EMAIL and PASSWORD for the browser."""

import os
import subprocess
import sys
import tempfile
import time

from edgelib import INGEST, account

AGENT = os.environ.get("AGENT", "/tmp/sentinel-agent")
PW = "network ui password 1"
c, email = account(pw=PW)
key = c.post("/v1/agent-keys", json={"name": "poller"}).json()["key"]
state = tempfile.mkdtemp(prefix="ui-poller-")
subprocess.run([AGENT, "register", "--url", INGEST, "--key", key, "--state-dir", state], check=True, capture_output=True)
agent = subprocess.Popen([AGENT, "run", "--state-dir", state], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
poller = next(h for h in c.get("/v1/hosts").json() if h["kind"] == "server")
for name, port, role in (("arista-eos", 1161, "core"), ("fortigate", 1162, "firewall")):
    cred = c.post("/v1/network/credentials", json={"name": name, "version": "2c", "community": name}).json()
    c.post("/v1/network/devices", json={"addresses": [f"127.0.0.1:{port}"], "credential_id": cred["id"],
                                        "poller_host_id": poller["id"], "network_role": role})
print(f"EMAIL={email}", flush=True)
print(f"PASSWORD={PW}", flush=True)
try:
    time.sleep(int(os.environ.get("KEEP", "900")))
finally:
    agent.terminate()
    sys.exit(0)
