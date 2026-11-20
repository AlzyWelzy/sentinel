"""Access matrix over every API operation: cross-organisation, read-only, no sign-in."""
import json, re, secrets, httpx, gzip, time
from pathlib import Path
from edgelib import account, link_for, API, INGEST, H, check, bugs

spec = json.load(open(Path(__file__).parents[2] / "web" / "openapi.json"))
ops = [(m.upper(), p, o) for p, v in spec["paths"].items() for m, o in v.items()]

def seed(c):
    """Create one of everything; return ids by param name."""
    ids = {}
    k = c.post("/v1/agent-keys", json={"name": "k"}).json()
    ids["key_id"] = k["id"]
    r = httpx.post(INGEST + "/v1/register", json={"install_key": k["key"], "machine_id": secrets.token_hex(8),
                   "hostname": "h-" + secrets.token_hex(3), "os": "linux", "arch": "amd64", "agent_version": "0.9.1"})
    ids["host_id"] = r.json()["host_id"]
    def mk(path, body, name):
        r = c.post(path, json=body)
        if r.status_code < 300 and isinstance(r.json(), dict) and "id" in r.json():
            ids[name] = r.json()["id"]
        else:
            print("seed fail", path, r.status_code, r.text[:200])
    mk("/v1/alert-rules", {"name": "r", "kind": "host_down"}, "rule_id")
    mk("/v1/channels", {"name": "c", "type": "webhook", "target": "https://hooks.slack.com/services/T000/B000/secretsecret"}, "channel_id")
    mk("/v1/checks", {"name": "ck", "type": "http", "target": "https://example.com"}, "check_id")
    mk("/v1/maintenance", {"name": "m", "schedule": "once", "starts_at": "2030-01-01T00:00:00Z", "ends_at": "2030-01-02T00:00:00Z"}, "window_id")
    mk("/v1/dashboards", {"name": "d"}, "dashboard_id")
    mk("/v1/status-pages", {"title": "sp", "slug": "s" + secrets.token_hex(4)}, "page_id")
    mk("/v1/api-tokens", {"name": "t"}, "token_id")
    mk("/v1/saved-views", {"name": "v", "kind": "servers"}, "view_id")
    if "channel_id" in ids:
        mk("/v1/oncall/schedules", {"name": "o", "start_at": "2026-01-01T09:00:00Z", "shift_hours": 24, "responders": [{"name": "x", "channel_ids": [ids["channel_id"]]}]}, "schedule_id")
    if "schedule_id" in ids:
        mk(f"/v1/oncall/schedules/{ids['schedule_id']}/overrides", {"name": "ov", "channel_ids": [ids["channel_id"]], "starts_at": "2030-01-01T00:00:00Z", "ends_at": "2030-01-02T00:00:00Z"}, "override_id")
    if "page_id" in ids:
        mk(f"/v1/status-pages/{ids['page_id']}/updates", {"title": "u", "body": "b", "status": "investigating"}, "update_id")
    r = c.post("/v1/network/credentials", json={"name": "c" + secrets.token_hex(3), "version": "2c", "community": "public"})
    if r.status_code == 201:
        ids["credential_id"] = r.json()["id"]
        r = c.post("/v1/network/devices", json={"addresses": ["10.77.0.1"], "credential_id": ids["credential_id"],
                                                "poller_host_id": ids["host_id"]})
        if r.status_code == 201:
            ids["device_id"] = r.json()["created"][0]["id"]
        r = c.post("/v1/network/discoveries", json={"cidr": "10.77.0.0/30", "credential_id": ids["credential_id"],
                                                    "poller_host_id": ids["host_id"]})
        if r.status_code == 201:
            ids["discovery_id"] = r.json()["id"]
    ids["ifindex"] = 1
    tid = c.headers["X-Sentinel-Account"]
    import subprocess
    out = subprocess.run(["docker", "exec", "beyond-dev-postgres-1", "sh", "-c",
        f"psql -U \"$POSTGRES_USER\" -d \"$POSTGRES_DB\" -tAc \"insert into incidents (tenant_id, host_id, summary, rule_name, hostname) values ('{tid}', '{ids['host_id']}', 'x', 'x', 'x') returning id\""],
        capture_output=True, text=True).stdout.split()[0]
    ids["incident_id"] = out
    # lists, to pick up anything we didn't create
    for path in ["/v1/incidents", "/v1/members", "/v1/channels", "/v1/escalation-policies"]:
        r = c.get(path)
        if r.status_code == 200:
            j = r.json(); j = j if isinstance(j, list) else j.get("items", [])
            if j and isinstance(j[0], dict) and "id" in j[0]:
                ids.setdefault(path.rsplit("/", 1)[-1].rstrip("s").replace("-", "_") + "_id", j[0]["id"])
    return ids

def fill(path, ids):
    def rep(m):
        n = m.group(1)
        if n in ids: return str(ids[n])
        if n == "member_id": return str(ids.get("member_id", ids.get("host_id")))
        if n in ("slug", "token"): return "nope"
        return str(ids.get(n, "00000000-0000-0000-0000-000000000001"))
    return re.sub(r"\{(\w+)\}", rep, path)

a, ea = account(); b, eb = account()
ia, ib = seed(a), seed(b)
print("seeded A:", sorted(ia)); print("seeded B:", sorted(ib))
missing = sorted({n for _, p, _ in ops for n in re.findall(r"\{(\w+)\}", p)} - set(ib))
print("param names without a seeded id:", missing)

# 1. cross-organisation: A's credentials, B's ids
for m, p, o in ops:
    if not p.startswith("/v1/") or "{" not in p: continue
    if any(n not in ib for n in re.findall(r"\{(\w+)\}", p)): continue
    r = a.request(m, fill(p, ib), json={} if m not in ("GET", "DELETE") else None)
    check(f"cross-org {m} {p}", r.status_code not in range(200, 300) and r.status_code < 500, f"{r.status_code} {r.text[:150]}")

# 2. no sign-in
anon = httpx.Client(base_url=API, headers=H, timeout=30)
for m, p, o in ops:
    if not (p.startswith("/v1/") or p.startswith("/admin")): continue
    if p.startswith("/v1/agent/") or p.startswith("/v1/public"): continue
    r = anon.request(m, fill(p, ia), json={} if m not in ("GET", "DELETE") else None)
    check(f"anon {m} {p}", r.status_code in (401, 403, 404), f"{r.status_code} {r.text[:120]}")

# 3. non-superadmin on /admin
for m, p, o in ops:
    if not p.startswith("/admin"): continue
    r = a.request(m, fill(p, ia), json={} if m not in ("GET", "DELETE") else None)
    check(f"user->admin {m} {p}", r.status_code in (403, 404), f"{r.status_code} {r.text[:120]}")

# 4. read-only member of A
vemail = f"viewer-{secrets.token_hex(3)}@example.com"
r = a.post("/v1/members", json={"email": vemail, "role": "viewer"}); assert r.status_code < 300, r.text
v = httpx.Client(base_url=API, headers=H, timeout=30)
v.post("/auth/signup", json={"email": vemail, "password": "edge password 123"})
tok = link_for(vemail).split("token=")[1].split("&")[0]
v.post("/auth/verify", json={"token": tok})
r = v.post("/auth/login", json={"email": vemail, "password": "edge password 123"})
v.headers["Authorization"] = "Bearer " + r.json()["access_token"]
pend = v.get("/auth/invitations/pending").json()
print("pending invites:", len(pend))
for i in pend: v.post(f"/auth/invitations/pending/{i['id'] if 'id' in i else i['member_id']}/accept")
v.headers["X-Sentinel-Account"] = a.headers["X-Sentinel-Account"]
print("viewer me:", v.get("/v1/me").json().get("role"))
r = a.post("/v1/members", json={"email": f"third-{secrets.token_hex(3)}@example.com", "role": "viewer"})
ia["member_id"] = r.json()["id"]
allowed = {"/v1/channels/push", "/v1/saved-views", "/v1/saved-views/{view_id}", "/v1/organisations"}
for m, p, o in ops:
    if not p.startswith("/v1/") or m == "GET" or p in allowed: continue
    if p.startswith("/v1/agent/"): continue
    r = v.request(m, fill(p, ia), json={"role": "admin"} if "members" in p else ({} if m != "DELETE" else None))
    check(f"viewer {m} {p}", r.status_code in (403, 404), f"{r.status_code} {r.text[:150]}")

me_mid = next(x["id"] for x in a.get("/v1/members").json() if x["email"] == vemail)
r = v.patch(f"/v1/members/{me_mid}", json={"role": "admin"})
check("viewer promotes self", r.status_code in (403, 404, 400), f"{r.status_code} {r.text[:150]}")
# 5. secrets visible to a read-only member
for m, p, o in ops:
    if m != "GET" or not p.startswith("/v1/") or p.startswith("/v1/agent/"): continue
    r = v.get(fill(p, ia))
    if r.status_code == 200:
        t = r.text
        hit = re.findall(r'"(?:key|token|secret|password|webhook_url|url)"\s*:\s*"([^"]{6,})"', t)
        hit = [h for h in hit if re.match(r"(pg[ht]?_|https://hooks|xox)", h)]
        check(f"viewer secrets {p}", not hit, hit[:2])
print("\nBUGS:", len(bugs)); [print(" -", x) for x in bugs]
