"""Site incidents, affected hosts and reminders, against the running alerter.

Hosts are made the way ingest makes them, and their heartbeats are set in
Redis directly, so no agents are needed: six servers behind one public IP
go quiet (a site outage), a switch goes quiet with two servers behind it,
and an incident left unacknowledged gets a reminder.

    uv run --no-project --with httpx python alerting_live.py
"""

import subprocess
import sys
import time
import uuid

import httpx

from edgelib import MAIL, account, bugs, check

SITE_IP = "203.0.113.50"


def psql(sql: str) -> str:
    out = subprocess.run(["docker", "exec", "beyond-dev-postgres-1", "psql", "-U", "sentinel", "-d", "sentinel",
                          "-tAc", sql], check=True, capture_output=True, text=True).stdout
    return out.strip()


def redis(*args: str) -> None:
    subprocess.run(["docker", "exec", "beyond-dev-redis-1", "redis-cli", *args], check=True, capture_output=True)


def host(tenant: str, name: str, public_ip: str | None = None, depends_on: str | None = None) -> str:
    return psql(
        "INSERT INTO hosts (tenant_id, machine_id, hostname, token_hash, public_ip, depends_on_host_id, created_at) "
        f"VALUES ('{tenant}', '{uuid.uuid4().hex}', '{name}', '{uuid.uuid4().hex}', "
        f"{repr(public_ip) if public_ip else 'NULL'}, {repr(depends_on) if depends_on else 'NULL'}, now() - interval '1 hour') "
        "RETURNING id").splitlines()[0]


def seen(host_id: str, ago: int) -> None:
    redis("SET", f"pg:last_seen:{host_id}", str(int(time.time()) - ago))


def keep_platform_alive() -> None:
    # The alerter holds "not reporting" alerts when the whole fleet goes
    # quiet at once; one fresh heartbeat says the platform is fine.
    redis("ZADD", "pg:fleet:seen", str(int(time.time())), f"{uuid.uuid4()}:{uuid.uuid4()}")


def wait(what: str, fn, timeout: float = 240):
    deadline = time.time() + timeout
    while time.time() < deadline:
        keep_platform_alive()
        v = fn()
        if v:
            return v
        time.sleep(5)
    print(f"timed out waiting for {what}")
    return None


def mails(to: str, subject_has: str) -> list[dict]:
    r = httpx.get(f"{MAIL}/search", params={"query": f"to:{to}"}).json()
    return [m for m in r.get("messages", []) if subject_has in m.get("Subject", "")]


c, email = account()
tenant = c.headers["X-Sentinel-Account"]
wait("the recommended rules", lambda: [r for r in c.get("/v1/alert-rules").json() if r["kind"] == "host_down"])

# ── a site outage: six servers behind one public IP ─────────────────────────
site = [host(tenant, f"nat-{i}", public_ip=SITE_IP) for i in range(6)]
# ── a switch with two servers behind it, elsewhere ──────────────────────────
switch = host(tenant, "tor-9", public_ip="198.51.100.9")
behind = [host(tenant, f"rack9-{i}", public_ip="198.51.100.10", depends_on=switch) for i in range(2)]
for h in site + [switch] + behind:
    seen(h, 3600)


def open_incidents():
    return c.get("/v1/incidents", params={"status": "open"}).json()


def site_incident():
    return next((i for i in open_incidents() if "stopped reporting" in i["summary"] and SITE_IP in i["hostname"]), None)


s = wait("the site incident", site_incident)
check("six silent servers behind one IP become one site incident", s is not None, [i["summary"] for i in open_incidents()])
if s:
    check("it counts them", s["summary"].startswith("6 hosts"), s["summary"])
    merged = [i for i in c.get("/v1/incidents", params={"limit": 500}).json() if i.get("merged_into") == s["id"]]
    check("their own incidents are merged into it", len(merged) == 6, len(merged))

tor = wait("the switch's incident", lambda: next((i for i in open_incidents() if i["hostname"] == "tor-9"), None))
check("the switch alerts", tor is not None)
if tor:
    d = c.get(f"/v1/incidents/{tor['id']}").json()
    check("its incident lists the hosts behind it", [a["hostname"] for a in d["affected"]] == ["rack9-0", "rack9-1"],
          d["affected"])
    check("its detail line names them", "rack9-0" in (d.get("detail") or ""), d.get("detail"))
    check("the hosts behind it don't alert on their own",
          not [i for i in open_incidents() if i["hostname"].startswith("rack9-")])

    # ── a reminder ───────────────────────────────────────────────────────────
    c.put("/v1/organisation/alerting", json={"reminder_minutes": 30})
    psql(f"UPDATE incidents SET opened_at = now() - interval '31 minutes' WHERE id = '{tor['id']}'")
    got = wait("the reminder", lambda: mails(email, "STILL OPEN"), 120)
    check("an unacknowledged incident is reminded by email", bool(got))
    events = [e["kind"] for e in c.get(f"/v1/incidents/{tor['id']}").json()["events"]]
    check("the reminder is on its timeline", "reminded" in events, events)
    c.post(f"/v1/incidents/{tor['id']}/acknowledge")
    psql(f"UPDATE incidents SET reminded_at = now() - interval '31 minutes' WHERE id = '{tor['id']}'")
    time.sleep(40)
    check("acknowledging stops reminders", len(mails(email, "STILL OPEN")) == 1, len(mails(email, "STILL OPEN")))

# ── a contact limited to one customer's tag ─────────────────────────────────
acme_inbox = f"noc-{uuid.uuid4().hex[:6]}@acme.example"
acme = c.post("/v1/channels", json={"type": "email", "target": acme_inbox, "only_tag": "customer-acme"}).json()
psql(f"UPDATE notification_channels SET verified_at = now() WHERE id = '{acme['id']}'")
default = next(ch for ch in c.get("/v1/channels").json() if ch["is_default"])
rule = c.post("/v1/alert-rules", json={"name": "Customer servers silent", "kind": "host_down", "duration_seconds": 60,
                                        "tag": "customer-acme", "channel_ids": [default["id"], acme["id"]]})
check("a rule can notify a tag-limited contact", rule.status_code == 201, rule.text)
acme_web = host(tenant, "acme-web", public_ip="192.0.2.77")
psql(f"UPDATE hosts SET tags = '{{customer-acme}}' WHERE id = '{acme_web}'")
seen(acme_web, 3600)
got = wait("acme's alert", lambda: mails(acme_inbox, "acme-web"), 180)
check("the customer's contact gets its own server's alert", bool(got))
others = [m["Subject"] for m in httpx.get(f"{MAIL}/search", params={"query": f"to:{acme_inbox}"}).json()["messages"]
          if "acme-web" not in m["Subject"] and "verification code" not in m["Subject"]]
check("and nothing about anyone else's", others == [], others)
seen(acme_web, 0)

# ── the site comes back ──────────────────────────────────────────────────────
for h in site:
    seen(h, 0)


def site_resolved():
    for h in site:
        seen(h, 0)
    return site_incident() is None


check("the site incident resolves when every server reports", bool(wait("the site recovery", site_resolved)))
check("one recovery email for the site", bool(wait("the recovery email", lambda: mails(email, "are reporting again"), 90)))

print("\nBUGS:", len(bugs))
for b in bugs:
    print(" -", b)
sys.exit(1 if bugs else 0)
