"""SNMP traps end to end: a real agent polls a simulated FortiGate and receives
traps sent with net-snmp's snmptrap; the alerter opens and closes the incident.

Needs the dev stack (make up), snmpsim as in network_live.py (the fortigate
recording on 127.0.0.1:1162), snmptrap (net-snmp), and the agent binary:

    AGENT=/tmp/sentinel-agent uv run --no-project --with httpx python traps_live.py
"""

import os
import subprocess
import sys
import tempfile
import time

from edgelib import INGEST, account, bugs, check

AGENT = os.environ.get("AGENT", "/tmp/sentinel-agent")
SIM = os.environ.get("SNMPSIM2", "127.0.0.1:1162")  # the fortigate recording
TRAP_PORT = os.environ.get("TRAP_PORT", "11162")
VPN_DOWN = "1.3.6.1.4.1.12356.101.2.0.302"
VPN_UP = "1.3.6.1.4.1.12356.101.2.0.301"
IPS = "1.3.6.1.4.1.12356.101.2.0.503"
TUNNEL = ["1.3.6.1.4.1.12356.101.12.3.4.0", "s", "to-branch", "1.3.6.1.4.1.12356.101.12.3.3.0", "a", "203.0.113.9"]


def trap(oid: str, varbinds: list[str], community: str = "fortigate") -> None:
    subprocess.run(["snmptrap", "-v", "2c", "-c", community, f"127.0.0.1:{TRAP_PORT}", "", oid, *varbinds],
                   check=True, capture_output=True)


def wait(what: str, fn, timeout: float = 150):
    deadline = time.time() + timeout
    while time.time() < deadline:
        v = fn()
        if v:
            return v
        time.sleep(3)
    print(f"timed out waiting for {what}")
    return None


c, email = account()
key = c.post("/v1/agent-keys", json={"name": "site poller"}).json()["key"]
state = tempfile.mkdtemp(prefix="trap-poller-")
subprocess.run([AGENT, "register", "--url", INGEST, "--key", key, "--state-dir", state], check=True, capture_output=True)
env = {**os.environ, "SENTINEL_TRAP_PORT": TRAP_PORT}
agent = subprocess.Popen([AGENT, "run", "--state-dir", state], stdout=open(f"{state}/agent.log", "w"),
                         stderr=subprocess.STDOUT, env=env)
try:
    poller = wait("the poller", lambda: next((h for h in c.get("/v1/hosts").json() if h["kind"] == "server"), None))
    cred = c.post("/v1/network/credentials", json={"name": "fg", "version": "2c", "community": "fortigate"}).json()
    dev = c.post("/v1/network/devices", json={"addresses": [SIM], "credential_id": cred["id"],
                                               "poller_host_id": poller["id"], "network_role": "firewall"}).json()
    device = dev["created"][0]["id"]
    named = wait("the device's first poll", lambda: c.get(f"/v1/network/devices/{device}").json()["system"].get("name"))
    check("device polled", bool(named), named)
    port = wait("the poller's trap port",
                lambda: next((p["trap_port"] for p in c.get("/v1/network/pollers").json() if p["trap_port"]), None))
    check("poller reports its trap port", port == int(TRAP_PORT), port)
    rules = [r for r in c.get("/v1/alert-rules").json() if r.get("target") == "trap_vpn_tunnel_down"]
    check("trap rule recommended with the first device", len(rules) == 1, [r.get("name") for r in rules])

    trap(VPN_DOWN, TUNNEL)
    trap(VPN_DOWN, TUNNEL, community="wrong")  # dropped by the agent
    for _ in range(20):  # a flood: one row
        trap(IPS, ["1.3.6.1.4.1.12356.101.9.3.1.0", "s", "SQL injection", "1.3.6.1.4.1.12356.101.9.3.2.0", "a", "198.51.100.7"])

    def device_traps():
        return c.get("/v1/network/traps", params={"device_id": device}).json()

    got = wait("the traps", lambda: (lambda t: t if len(t) >= 2 else None)(device_traps()))
    got = device_traps()
    vpn = [t for t in got if t["name"] == "fgTrapVpnTunDown"]
    ips = [t for t in got if t["name"] == "fgTrapIpsSignature"]
    check("VPN down stored once (the wrong community was dropped)", len(vpn) == 1, got)
    check("VPN down opens its alert", vpn and vpn[0]["action"] == "open" and vpn[0]["labels"].get("tunnel") == "to-branch",
          vpn)
    check("a flood is one row with a repeat count", len(ips) == 1 and ips[0]["repeats"] == 19, ips)

    def incident():
        for i in c.get("/v1/incidents", params={"status": "open"}).json():
            if "VPN tunnel down (trap)" in (i.get("rule_name") or i.get("summary") or ""):
                return i
        return None

    inc = wait("the incident", incident, 120)
    check("incident opened", inc is not None)
    if inc:
        check("incident names the tunnel", "to-branch" in (inc.get("detail") or ""), inc.get("detail"))

    trap(VPN_UP, TUNNEL)

    def resolved():
        return incident() is None

    check("VPN up resolves the incident", bool(wait("the recovery", resolved, 120)))
finally:
    agent.terminate()
    agent.wait(10)
    print("agent log tail:")
    print("".join(open(f"{state}/agent.log").readlines()[-6:]))

print("\nBUGS:", len(bugs))
for b in bugs:
    print(" -", b)
sys.exit(1 if bugs else 0)
