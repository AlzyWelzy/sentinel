"""Check groups, end to end: two push checks in a group (one through a
nested group). One reporting down opens its own incident, then the group's,
naming it; recovery resolves both.

    uv run --no-project --with httpx python groups_live.py
"""

import sys
import time

import httpx

from edgelib import account, bugs, check

c, _ = account()


def mk(**body):
    r = c.post("/v1/checks", json=body)
    check(f"{body['name']}: created", r.status_code == 201, r.text)
    return r.json()


def wait(fn, timeout=150):
    end = time.time() + timeout
    while time.time() < end:
        if v := fn():
            return v
        time.sleep(3)
    return None


def incident_for(cid, status="open"):
    for i in c.get("/v1/incidents", params={"status": status}).json():
        if i.get("check_id") == cid:
            return i
    return None


g = mk(name="Shop", type="group")
inner = mk(name="Billing", type="group", parent_id=g["id"])
a = mk(name="nightly backup", type="push", interval_seconds=3600, parent_id=g["id"])
b = mk(name="invoice run", type="push", interval_seconds=3600, parent_id=inner["id"])
httpx.get(a["push_url"], params={"status": "up"})
httpx.get(b["push_url"], params={"status": "up"})
time.sleep(5)
check("group up", c.get(f"/v1/checks/{g['id']}").json()["status"] == "up")

httpx.get(b["push_url"], params={"status": "down", "msg": "invoice job crashed"})
check("group down at once in the API", c.get(f"/v1/checks/{g['id']}").json()["status"] == "down")
gi = wait(lambda: incident_for(g["id"]))
check("group incident opened", gi)
if gi:
    full = c.get(f"/v1/incidents/{gi['id']}").json()
    text = (full.get("detail") or "") + full.get("summary", "")
    check("names the failing member", "invoice run" in text and "1 of 2 down" in text, text)
check("nested group has its incident too", wait(lambda: incident_for(inner["id"]), 60))

httpx.get(b["push_url"], params={"status": "up"})
check("group resolves", wait(lambda: incident_for(g["id"], "resolved")))
check("member resolves", wait(lambda: incident_for(b["id"], "resolved"), 60))

print(f"\n{len(bugs)} bugs")
for x in bugs:
    print(" -", x)
sys.exit(1 if bugs else 0)
