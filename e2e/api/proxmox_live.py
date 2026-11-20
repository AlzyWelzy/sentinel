"""Proxmox VE end to end: a real agent polls a fake Proxmox API (HTTPS with a
self-signed certificate, like a fresh install) and the cluster shows up.

    AGENT=/tmp/sentinel-agent uv run --no-project --with httpx python proxmox_live.py
"""

import http.server
import json
import os
import ssl
import subprocess
import sys
import tempfile
import threading
import time

from edgelib import INGEST, account, bugs, check

AGENT = os.environ.get("AGENT", "/tmp/sentinel-agent")
TOKEN = "PVEAPIToken=monitoring@pve!sentinel=00000000-test-token"
state = {"node2": "online"}


class FakePVE(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.headers.get("Authorization") != TOKEN:
            self.send_response(401)
            self.end_headers()
            return
        if self.path == "/api2/json/cluster/resources":
            data = [
                {"type": "node", "node": "pve1", "status": "online", "cpu": 0.2, "maxcpu": 32,
                 "mem": 3.2e10, "maxmem": 6.4e10, "disk": 2e10, "maxdisk": 1e11, "uptime": 86400},
                {"type": "node", "node": "pve2", "status": state["node2"], "cpu": 0.1, "maxcpu": 32,
                 "mem": 1e10, "maxmem": 6.4e10, "disk": 1e10, "maxdisk": 1e11, "uptime": 3600},
                {"type": "qemu", "node": "pve1", "vmid": 100, "name": "web-1", "status": "running",
                 "cpu": 0.4, "maxcpu": 4, "mem": 2e9, "maxmem": 4e9, "maxdisk": 5e10, "uptime": 500},
                {"type": "lxc", "node": "pve2", "vmid": 200, "name": "dns", "status": "running",
                 "cpu": 0.01, "maxcpu": 1, "mem": 1e8, "maxmem": 5e8, "uptime": 500},
                {"type": "storage", "node": "pve1", "storage": "local-lvm", "status": "available",
                 "disk": 9.5e11, "maxdisk": 1e12},
            ]
        elif self.path == "/api2/json/cluster/status":
            data = [{"type": "cluster", "name": "lab", "quorate": 1, "nodes": 2}]
        else:
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps({"data": data}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


tmp = tempfile.mkdtemp(prefix="pve-")
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=pve",
                "-keyout", f"{tmp}/key.pem", "-out", f"{tmp}/cert.pem"], check=True, capture_output=True)
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakePVE)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(f"{tmp}/cert.pem", f"{tmp}/key.pem")
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

c, email = account()
key = c.post("/v1/agent-keys", json={"name": "site"}).json()["key"]
sd = tempfile.mkdtemp(prefix="pve-poller-")
subprocess.run([AGENT, "register", "--url", INGEST, "--key", key, "--state-dir", sd], check=True, capture_output=True)
agent = subprocess.Popen([AGENT, "run", "--state-dir", sd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    poller = next(h for h in c.get("/v1/hosts").json() if h["kind"] == "server")
    cred = c.post("/v1/network/credentials", json={
        "name": "lab", "version": "proxmox", "token_user": "monitoring@pve", "token_name": "sentinel",
        "token_value": "00000000-test-token", "insecure_tls": True}).json()
    dev = c.post("/v1/network/devices", json={"addresses": [f"127.0.0.1:{port}"], "credential_id": cred["id"],
                                              "poller_host_id": poller["id"]}).json()["created"][0]
    for _ in range(30):
        d = c.get(f"/v1/network/devices/{dev['id']}").json()
        if d["system"].get("name"):
            break
        time.sleep(3)
    check("cluster named from the API", d["host"]["hostname"] == "lab", d["host"]["hostname"])
    check("vendor Proxmox", d["host"]["vendor"] == "Proxmox", d["host"]["vendor"])
    check("profile proxmox", d["profile"] == "proxmox", d["profile"])
    check("no poll error", not d["host"]["device_error"], d["host"]["device_error"])
    time.sleep(5)
    r = c.get(f"/v1/network/devices/{dev['id']}/proxmox").json()
    types = sorted(x["type"] for x in r["resources"])
    check("nodes, guests and storage", types == ["lxc", "node", "node", "qemu", "storage"], types)
    check("quorum", r["quorate"] is True and r["cluster"] == "lab", r)
    lvm = next((x for x in r["resources"] if x["type"] == "storage"), {})
    check("storage usage", lvm.get("disk_used") == 9.5e11, lvm)
    # Without the self-signed allowance, the device says why it can't poll.
    c.patch(f"/v1/network/credentials/{cred['id']}", json={"insecure_tls": False})
    time.sleep(100)
    d = c.get(f"/v1/network/devices/{dev['id']}").json()
    check("self-signed certificate explained", "self-signed" in (d["host"]["device_error"] or ""),
          d["host"]["device_error"])
finally:
    agent.terminate()
    srv.shutdown()

print("\nBUGS:", len(bugs))
for b in bugs:
    print(" -", b)
sys.exit(1 if bugs else 0)
