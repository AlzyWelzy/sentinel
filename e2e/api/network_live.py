"""Network monitoring end to end: a real agent polls simulated devices.

Needs the dev stack (make up), snmpsim serving netmon/testdata/walks on
127.0.0.1:1161 (community = the recording's name), and the agent binary:

    python snmpsim_data.py /tmp/snmpsim   # the recordings, sorted, one record a line
    uvx --python 3.12 --from snmpsim-lextudio snmpsim-command-responder \\
        --data-dir=/tmp/snmpsim \\
        --agent-udpv4-endpoint=127.0.0.1:1161 --agent-udpv4-endpoint=127.0.0.1:1162
    go build -o /tmp/sentinel-agent ./agent
    AGENT=/tmp/sentinel-agent uv run --no-project --with httpx python network_live.py
"""

import os
import subprocess
import sys
import tempfile
import time

from edgelib import INGEST, account, bugs, check

AGENT = os.environ.get("AGENT", "/tmp/sentinel-agent")
SIM = os.environ.get("SNMPSIM", "127.0.0.1:1161")
SIM2 = os.environ.get("SNMPSIM2", "127.0.0.1:1162")  # the same simulator, a second port

c, email = account()
key = c.post("/v1/agent-keys", json={"name": "site poller"}).json()["key"]
state = tempfile.mkdtemp(prefix="poller-")
subprocess.run([AGENT, "register", "--url", INGEST, "--key", key, "--state-dir", state], check=True,
               capture_output=True)
agent = subprocess.Popen([AGENT, "run", "--state-dir", state], stdout=open(f"{state}/agent.log", "w"),
                         stderr=subprocess.STDOUT)
try:
    poller = next(h for h in c.get("/v1/hosts").json() if h["kind"] == "server")
    creds = {}
    for name in ("arista-eos", "fortigate"):
        r = c.post("/v1/network/credentials", json={"name": name, "version": "2c", "community": name})
        check(f"credential {name}", r.status_code == 201, r.text)
        creds[name] = r.json()["id"]
    devices = {}
    for name, role, addr in (("arista-eos", "core", SIM), ("fortigate", "firewall", SIM2)):
        r = c.post("/v1/network/devices", json={"addresses": [addr], "credential_id": creds[name],
                                                "poller_host_id": poller["id"], "network_role": role})
        check(f"add {name}", r.status_code == 201 and r.json()["created"], r.text)
        devices[name] = r.json()["created"][0]["id"]

    deadline = time.time() + 150
    details = {}
    while time.time() < deadline:
        details = {n: c.get(f"/v1/network/devices/{d}").json() for n, d in devices.items()}
        if all(d["system"].get("name") and d["interfaces"] for d in details.values()):
            break
        time.sleep(5)
    a, f = details["arista-eos"], details["fortigate"]
    check("arista detected", a["profile"] == "arista-eos", a["profile"])
    check("arista named from sysName", a["host"]["hostname"] == "host-754862", a["host"]["hostname"])
    check("arista interfaces stored", len(a["interfaces"]) > 20, len(a["interfaces"]))
    check("arista LLDP neighbours stored", len(a["links"]) > 0, a["links"][:2])
    check("arista inventory", bool(a["inventory"]), a["inventory"])
    check("fortigate detected", f["profile"] == "fortigate", f["profile"])
    check("fortigate vendor", f["host"]["vendor"] == "Fortinet", f["host"]["vendor"])
    check("no poll error", not a["host"]["device_error"] and not f["host"]["device_error"],
          (a["host"]["device_error"], f["host"]["device_error"]))
    hosts = {h["id"]: h for h in c.get("/v1/hosts").json()}
    check("devices online", all(hosts[d]["online"] for d in devices.values()),
          [hosts[d]["online"] for d in devices.values()])
    time.sleep(70)  # two fast polls: enough for rate()
    a = c.get(f"/v1/network/devices/{devices['arista-eos']}").json()
    rated = [i for i in a["interfaces"] if i["in_bps"] is not None]
    check("interface rates from metrics", len(rated) > 0, len(rated))
    m = c.get(f"/v1/hosts/{devices['arista-eos']}/metrics", params={"metric": "cpu"})
    print("info: generic metrics endpoint for a device:", m.status_code)
    # A wrong community: the device goes silent with a reason.
    r = c.post("/v1/network/credentials", json={"name": "wrong", "version": "2c", "community": "nope"})
    c.patch(f"/v1/network/devices/{devices['fortigate']}", json={"credential_id": r.json()["id"]})
    # The change reaches the agent with its next push, the poll times out,
    # and the result comes with the push after: up to about 70 s.
    time.sleep(100)
    f = c.get(f"/v1/network/devices/{devices['fortigate']}").json()
    check("wrong community explained", "No SNMP answer" in (f["host"]["device_error"] or ""), f["host"]["device_error"])
finally:
    agent.terminate()
    agent.wait(10)
    print("agent log tail:")
    print("".join(open(f"{state}/agent.log").readlines()[-8:]))

print("\nBUGS:", len(bugs))
for b in bugs:
    print(" -", b)
sys.exit(1 if bugs else 0)
