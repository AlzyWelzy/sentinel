"""IPDR end to end: a real agent is the organisation's evidence collector.
FortiGate-style syslog (UDP and TCP) and a NetFlow v5 packet sent to it land
in ClickHouse through ingest; a search finds them (and another
organisation's search doesn't), an export downloads with its manifest, and
the audit chain verifies.

    AGENT=/path/sentinel-agent uv run --no-project --with httpx python ipdr_live.py
"""

import io
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
from datetime import UTC, datetime, timedelta

from edgelib import account, bugs, check

AGENT = os.environ.get("AGENT", "/tmp/sentinel-agent")
INGEST = "http://localhost:8090"
UDP, TCP, NETFLOW = 1514, 1601, 2055


def wait(what, fn, timeout=120):
    end = time.time() + timeout
    while time.time() < end:
        if v := fn():
            return v
        time.sleep(2)
    print(f"timed out waiting for {what}")
    return None


def netflow_v5(src: str, dst: str, octets: int) -> bytes:
    hdr = struct.pack("!HHIIIIBBH", 5, 1, 0, int(time.time()), 0, 1, 0, 0, 0)
    rec = (
        socket.inet_aton(src) + socket.inet_aton(dst) + socket.inet_aton("0.0.0.0")
        + struct.pack("!HHIIII", 1, 2, 4, octets, 0, 0)
        + struct.pack("!HHBBBBHHBBH", 51000, 443, 0, 0x18, 6, 0, 0, 0, 0, 0, 0)
    )  # fmt: skip
    return hdr + rec


c, _ = account()
key = c.post("/v1/agent-keys", json={"name": "collector"}).json()["key"]
sd = tempfile.mkdtemp(prefix="ipdr-collector-")
subprocess.run([AGENT, "register", "--url", INGEST, "--key", key, "--state-dir", sd], check=True, capture_output=True)
env = {**os.environ, "SENTINEL_EVIDENCE_STANDARD_PORTS": "0", "SENTINEL_TRAP_PORT": "0"}
agent = subprocess.Popen([AGENT, "run", "--state-dir", sd], stdout=open(f"{sd}/agent.log", "w"), stderr=subprocess.STDOUT, env=env)
try:
    host = wait("the agent", lambda: next(iter(c.get("/v1/hosts").json()), None))
    r = c.put("/v1/ipdr/settings", json={"enabled": True, "retention_days": 90, "collector_host_id": host["id"], "allow": ["127.0.0.1/32"]})
    check("IPDR turned on", r.status_code == 200, r.text)
    listening = wait(
        "the receivers",
        lambda: (c.get("/v1/ipdr/settings").json().get("collector") or {}).get("stats", {}).get("listening"),
        150,
    )
    check("collector reports its listeners", listening and any("syslog/udp 1514" in x for x in listening), listening)

    stamp = int(time.time())
    forti = (
        f'<189>date=2026-11-21 time=10:00:00 devname="FG-E2E" logid="0000000013" type="traffic" subtype="forward" '
        f'srcip=10.44.0.{stamp % 200} srcport=50000 dstip=93.184.216.34 dstport=443 proto=6 action="accept" '
        f'policyid=7 transip=203.0.113.77 transport=40100 sentbyte=1000 rcvdbyte=9000 user="e2e-{stamp}"'
    )
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(forti.encode(), ("127.0.0.1", UDP))
    vpn = f'<189>logid="0101039947" type="event" subtype="vpn" devname="FG-E2E" action="tunnel-up" user="vpn-{stamp}" tunnelip=10.212.0.9 remip=198.51.100.9'
    t = socket.create_connection(("127.0.0.1", TCP))
    t.sendall(f"{len(vpn)} {vpn}".encode())
    t.sendall(b"<13>Nov 21 10:00:00 sw-e2e sshd[1]: Accepted publickey for root from 198.51.100.200\n")
    t.close()
    s.sendto(netflow_v5("10.44.1.1", "1.1.1.1", 4242), ("127.0.0.1", NETFLOW))

    win = {"start": (datetime.now(UTC) - timedelta(hours=1)).isoformat(), "end": (datetime.now(UTC) + timedelta(minutes=5)).isoformat()}
    q = {"kind": "sessions", "reason": "e2e: abuse report check", "ip": "203.0.113.77", **win}
    got = wait("the session in search", lambda: (r := c.post("/v1/ipdr/search", json=q)).status_code == 200 and r.json()["total"] >= 1 and r.json(), 90)
    check("firewall session found by its NAT address", got, got)
    if got:
        row = got["rows"][0]
        check("session fields parsed", row["nat_src_port"] == 40100 and row["rcvd_bytes"] == 9000 and row["user"] == f"e2e-{stamp}", row)
    idn = c.post("/v1/ipdr/search", json={**q, "kind": "identity", "ip": "10.212.0.9"}).json()
    check("VPN identity found (TCP, octet framing)", idn["total"] >= 1 and idn["rows"][0]["user"] == f"vpn-{stamp}", idn)
    sl = c.post("/v1/ipdr/search", json={**q, "kind": "syslog", "ip": "198.51.100.200"}).json()
    check("syslog line found by an IP inside it", sl["total"] >= 1, sl)
    fl = wait("the flow", lambda: (r := c.post("/v1/ipdr/search", json={**q, "kind": "flows", "ip": "10.44.1.1"}).json())["total"] >= 1 and r, 60)
    check("NetFlow record found", fl and fl["rows"][0]["bytes"] == 4242, fl)

    other, _ = account()
    other.put("/v1/ipdr/settings", json={"enabled": False, "retention_days": 90})
    r = other.post("/v1/ipdr/search", json=q)
    check("another organisation sees nothing", r.status_code in (200, 403) and (r.status_code == 403 or r.json()["total"] == 0), r.text)

    ex = c.post("/v1/ipdr/exports", json={k: v for k, v in q.items()}).json()
    check("export ready", ex.get("status") == "ready", ex)
    d = c.get(f"/v1/ipdr/exports/{ex.get('id')}/download")
    ok = d.status_code == 200 and "manifest.json" in zipfile.ZipFile(io.BytesIO(d.content)).namelist()
    check("export downloads with its manifest", ok, d.status_code)
    v = c.post("/v1/ipdr/audit/verify").json()
    check("audit chain intact", v["ok"] and v["checked"] >= 6, v)
    src = c.get("/v1/ipdr/sources").json()
    check("sources list the sender", any(x["source"] == "127.0.0.1" for x in src), src)
finally:
    agent.terminate()
    agent.wait(10)

print(f"\n{len(bugs)} bugs")
for b in bugs:
    print(" -", b)
sys.exit(1 if bugs else 0)
