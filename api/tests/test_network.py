"""Network devices: credentials, adding devices, pollers, topology."""

import json
import re
import uuid
from pathlib import Path

import pytest
from sqlalchemy import text

from app.db import ServiceSession
from app.routes.network import compute_parents, normalize_address

from .conftest import User, insert_host

V2 = {"name": "Office switches", "version": "2c", "community": "s3cret-community"}


@pytest.fixture(autouse=True)
def credentials_key(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "CREDENTIALS_KEY", "test-credentials-key-0123456789abcdef")


def test_addresses_are_ips_or_hostnames_never_urls():
    assert normalize_address(" 10.0.0.1 ") == "10.0.0.1"
    assert normalize_address("10.0.0.1:161") == "10.0.0.1"
    assert normalize_address("10.0.0.1:1161") == "10.0.0.1:1161"
    assert normalize_address("Core1.Example.NET") == "core1.example.net"
    assert normalize_address("[2001:db8::1]:1161") == "[2001:db8::1]:1161"
    assert normalize_address("2001:db8::1") == "2001:db8::1"
    for bad in [
        "http://10.0.0.1",
        "10.0.0.1:0",
        "10.0.0.1:99999",
        "a b",
        "",
        "-bad.example",
        "x" * 300,
    ]:
        with pytest.raises(ValueError):
            normalize_address(bad)


def test_upstream_is_one_hop_closer_to_a_core_device():
    core, dist, tor1, tor2, lone = (uuid.UUID(int=i) for i in range(1, 6))
    roles = {core: "core", dist: "distribution", tor1: "access", tor2: "access", lone: None}
    # tor2 is cabled to both tor1 and dist: dist is the closer one.
    links = [(dist, core), (tor1, dist), (tor2, tor1), (tor2, dist)]
    parents = compute_parents(roles, links)
    assert parents == {dist: core, tor1: dist, tor2: dist}
    assert core not in parents and lone not in parents
    # No core marked: no automatic upstreams.
    assert compute_parents({k: "access" for k in roles}, links) == {}


async def test_credentials_never_come_back(alice: User):
    r = await alice.request("POST", "/v1/network/credentials", json=V2)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["community_set"] and "s3cret" not in r.text
    listed = await alice.request("GET", "/v1/network/credentials")
    assert "s3cret" not in listed.text
    async with ServiceSession() as db:
        stored = await db.scalar(
            text("SELECT secret FROM snmp_credentials WHERE id = :i"), {"i": body["id"]}
        )
    assert stored.startswith("v1:") and "s3cret" not in stored
    # v3 needs a user, known protocols and real passwords.
    bad = [
        {"name": "x", "version": "3"},
        {
            "name": "x",
            "version": "3",
            "username": "u",
            "auth_protocol": "rot13",
            "auth_password": "12345678",
        },
        {
            "name": "x",
            "version": "3",
            "username": "u",
            "auth_protocol": "sha",
            "auth_password": "short",
        },
        {
            "name": "x",
            "version": "3",
            "username": "u",
            "priv_protocol": "aes",
            "priv_password": "12345678",
        },
        {"name": "x", "version": "2c"},
    ]
    for b in bad:
        assert (
            await alice.request("POST", "/v1/network/credentials", json=b)
        ).status_code == 422, b
    v3 = {
        "name": "v3",
        "version": "3",
        "username": "monitor",
        "auth_protocol": "SHA256",
        "auth_password": "auth-pass-1",
        "priv_protocol": "aes",
        "priv_password": "priv-pass-1",
    }
    r = await alice.request("POST", "/v1/network/credentials", json=v3)
    assert r.status_code == 201 and r.json()["auth_protocol"] == "sha256" and r.json()["priv_set"]
    # A patch without secrets keeps them.
    r = await alice.request(
        "PATCH", f"/v1/network/credentials/{r.json()['id']}", json={"name": "v3b"}
    )
    assert r.status_code == 200 and r.json()["auth_set"] and r.json()["priv_set"]
    dup = await alice.request("POST", "/v1/network/credentials", json=V2)
    assert dup.status_code == 409


async def test_devices_are_polled_by_your_own_servers(alice: User, bob: User):
    cred = (await alice.request("POST", "/v1/network/credentials", json=V2)).json()
    poller = await insert_host(await alice.tenant_id(), "site-poller")
    bobs = await insert_host(await bob.tenant_id(), "bobs-server")
    add = {"credential_id": cred["id"], "poller_host_id": str(poller)}
    # Bob's server can't poll for Alice, and Bob can't use Alice's credential.
    r = await alice.request(
        "POST",
        "/v1/network/devices",
        json={**add, "addresses": ["10.0.0.1"], "poller_host_id": str(bobs)},
    )
    assert r.status_code == 422
    bob_cred = await bob.request(
        "POST",
        "/v1/network/devices",
        json={**add, "addresses": ["10.0.0.1"], "poller_host_id": str(bobs)},
    )
    assert bob_cred.status_code == 404
    r = await alice.request(
        "POST",
        "/v1/network/devices",
        json={**add, "addresses": ["10.0.0.1", "10.0.0.2:161", "10.0.0.1"], "network_role": "core"},
    )
    assert r.status_code == 201, r.text
    created = r.json()["created"]
    assert [d["address"] for d in created] == ["10.0.0.1", "10.0.0.2"]
    assert all(d["kind"] == "network" and d["poller_host_id"] == str(poller) for d in created)
    again = await alice.request(
        "POST", "/v1/network/devices", json={**add, "addresses": ["10.0.0.2", "10.0.0.3"]}
    )
    assert again.json()["skipped"] == ["10.0.0.2"] and len(again.json()["created"]) == 1
    # A name only goes with one address; URLs aren't addresses.
    assert (
        await alice.request(
            "POST",
            "/v1/network/devices",
            json={**add, "addresses": ["a.example", "b.example"], "name": "x"},
        )
    ).status_code == 422
    assert (
        await alice.request(
            "POST", "/v1/network/devices", json={**add, "addresses": ["http://10.0.0.9"]}
        )
    ).status_code == 422
    # Devices show among the servers, with their kind.
    hosts = (await alice.request("GET", "/v1/hosts")).json()
    assert {h["hostname"] for h in hosts if h["kind"] == "network"} == {
        "10.0.0.1",
        "10.0.0.2",
        "10.0.0.3",
    }
    # Bob sees none of it.
    assert (await bob.request("GET", f"/v1/network/devices/{created[0]['id']}")).status_code == 404
    assert all(h["kind"] == "server" for h in (await bob.request("GET", "/v1/hosts")).json())
    # The detail page works before the first poll.
    detail = await alice.request("GET", f"/v1/network/devices/{created[0]['id']}")
    assert detail.status_code == 200 and detail.json()["poller_hostname"] == "site-poller"
    # The credential can't go while devices use it.
    assert (
        await alice.request("DELETE", f"/v1/network/credentials/{cred['id']}")
    ).status_code == 409
    # Nor the poller: its devices would stop being polled.
    r = await alice.request("DELETE", f"/v1/hosts/{poller}")
    assert r.status_code == 409 and "3 network devices" in r.json()["detail"]
    # Removing the poller and its devices together is fine.
    ids = [str(poller)] + [d["id"] for d in created] + [again.json()["created"][0]["id"]]
    r = await alice.request("POST", "/v1/hosts/bulk", json={"host_ids": ids, "action": "delete"})
    assert r.status_code == 200 and r.json()["changed"] == 4
    assert (
        await alice.request("DELETE", f"/v1/network/credentials/{cred['id']}")
    ).status_code == 204


async def test_vendor_profiles_are_listed(alice: User):
    r = await alice.request("GET", "/v1/network/profiles")
    names = {p["name"] for p in r.json()}
    assert {"arista-eos", "fortigate", "generic"} <= names
    assert not any(n.startswith("_") for n in names)


# The alerter evaluates the same keys (alerter/network_test.go).
SHARED_CONDITION_KEYS = [
    "bgp_peer_flapped",
    "bgp_peer_not_established",
    "device_rebooted",
    "fortigate_cpu_high",
    "fortigate_memory_high",
    "ha_out_of_sync",
    "hardware_sensor_alarm",
    "interface_down",
    "interface_errors",
    "interface_utilisation",
    "lag_member_down",
    "optic_receive_power_low",
    "ospf_neighbour_not_full",
    "proxmox_guest_stopped",
    "proxmox_node_cpu",
    "proxmox_node_memory",
    "proxmox_node_offline",
    "proxmox_quorum_lost",
    "proxmox_storage_full",
    "sd_wan_latency_high",
    "sd_wan_link_dead",
    "sd_wan_packet_loss",
    "sensor_above_critical_threshold",
    "sensor_above_warning_threshold",
    "sophos_disk_almost_full",
    "sophos_memory_high",
    "trap_ap_down",
    "trap_auth_failure",
    "trap_bgp_down",
    "trap_bypass_mode",
    "trap_conserve_mode",
    "trap_cpu_high",
    "trap_dhcp",
    "trap_fan_failure",
    "trap_faz_disconnected",
    "trap_fortiswitch_down",
    "trap_ha_failover",
    "trap_ha_heartbeat",
    "trap_ha_member_down",
    "trap_inspection_bypassed",
    "trap_ip_conflict",
    "trap_ip_pool",
    "trap_ips_attack",
    "trap_lb_real_server_down",
    "trap_link_down",
    "trap_log_disk_low",
    "trap_memory_low",
    "trap_ospf_down",
    "trap_power_supply",
    "trap_restart",
    "trap_security_level",
    "trap_temperature_high",
    "trap_virus",
    "trap_voltage",
    "trap_vpn_tunnel_down",
    "vpn_tunnel_down",
]


def test_condition_catalog_matches_the_alerter():
    from app.services.netconditions import CONDITIONS

    assert sorted(CONDITIONS) == SHARED_CONDITION_KEYS


def test_trap_conditions_match_the_go_catalog():
    """Names, severities and which are recommended, as in netmon/traps."""
    from app.services.netconditions import TRAPS

    go = (Path(__file__).resolve().parents[2] / "netmon" / "traps" / "catalog.go").read_text()
    rules = {}
    for m in re.finditer(
        r'\{Key: "(trap_\w+)", Name: "([^"]+)", Severity: "(\w+)"(.*?)Help:', go, re.S
    ):
        rules[m.group(1)] = (m.group(2), m.group(3), "Off: true" not in m.group(4))
    assert {c.key: (c.name, c.severity, c.recommended) for c in TRAPS} == rules


async def test_network_rules_arrive_with_the_first_device(alice: User):
    cred = (await alice.request("POST", "/v1/network/credentials", json=V2)).json()
    poller = await insert_host(await alice.tenant_id(), "poller")
    add = {"credential_id": cred["id"], "poller_host_id": str(poller)}

    def network_rules(rules: list[dict]) -> list[str]:
        return sorted(r["name"] for r in rules if r["kind"] == "network")

    assert network_rules((await alice.request("GET", "/v1/alert-rules")).json()) == []
    await alice.request("POST", "/v1/network/devices", json={**add, "addresses": ["10.1.0.1"]})
    rules = (await alice.request("GET", "/v1/alert-rules")).json()
    names = network_rules(rules)
    assert "Interface down" in names and "Interface utilisation above 90%" in names
    assert "VPN tunnel down" in names and "Proxmox storage above 90%" in names and len(names) == 50
    assert "VPN tunnel down (trap)" in names and "IPS attack detected" not in names
    # Deleting one sticks: the next device doesn't bring it back.
    down = next(r for r in rules if r["name"] == "Interface down")
    assert (await alice.request("DELETE", f"/v1/alert-rules/{down['id']}")).status_code == 204
    await alice.request("POST", "/v1/network/devices", json={**add, "addresses": ["10.1.0.2"]})
    assert "Interface down" not in network_rules(
        (await alice.request("GET", "/v1/alert-rules")).json()
    )


async def test_network_rules_need_a_known_condition(alice: User):
    base = {"name": "Uplink busy", "kind": "network"}
    assert (
        await alice.request("POST", "/v1/alert-rules", json={**base, "target": "nope"})
    ).status_code == 422
    r = await alice.request(
        "POST",
        "/v1/alert-rules",
        json={**base, "target": "interface_utilisation", "threshold": 150},
    )
    assert r.status_code == 422
    r = await alice.request(
        "POST", "/v1/alert-rules", json={**base, "target": "interface_utilisation"}
    )
    assert r.status_code == 201 and r.json()["threshold"] == 90 and r.json()["operator"] == ">"
    r = await alice.request(
        "POST",
        "/v1/alert-rules",
        json={**base, "name": "VPN", "target": "vpn_tunnel_down", "threshold": 5},
    )
    assert r.status_code == 201 and r.json()["threshold"] is None
    conds = (await alice.request("GET", "/v1/network/conditions")).json()
    assert {c["key"] for c in conds} == set(SHARED_CONDITION_KEYS)


def test_percentile_is_nearest_rank():
    from app.routes.network import percentile95

    assert percentile95([]) == 0
    assert percentile95([5.0]) == 5
    # 100 samples 1..100: the top 5 (96-100) go, 95 is billed.
    assert percentile95([float(v) for v in range(100, 0, -1)]) == 95
    # 20 samples: ceil(0.95*20) = 19th smallest.
    assert percentile95([float(v) for v in range(1, 21)]) == 19


async def test_bandwidth_needs_tagged_ports(alice: User):
    r = await alice.request(
        "GET", "/v1/network/bandwidth", params={"tag": "acme", "month": "2026-11"}
    )
    assert r.status_code == 404
    for bad in (
        {"tag": "acme", "month": "2026-13"},
        {"tag": "acme", "month": "26-1"},
        {"tag": "acme"},
    ):
        assert (
            await alice.request("GET", "/v1/network/bandwidth", params=bad)
        ).status_code == 422, bad
    cred = (await alice.request("POST", "/v1/network/credentials", json=V2)).json()
    poller = await insert_host(await alice.tenant_id(), "poller")
    dev = (
        await alice.request(
            "POST",
            "/v1/network/devices",
            json={
                "addresses": ["10.9.0.1"],
                "credential_id": cred["id"],
                "poller_host_id": str(poller),
            },
        )
    ).json()["created"][0]
    async with ServiceSession() as db, db.begin():
        await db.execute(
            text(
                "INSERT INTO network_interfaces (tenant_id, host_id, ifindex, name) "
                "VALUES (:t, :h, 7, 'Ethernet7')"
            ),
            {"t": await alice.tenant_id(), "h": dev["id"]},
        )
    r = await alice.request(
        "PATCH", f"/v1/network/devices/{dev['id']}/interfaces/7", json={"billing_tag": "Acme Ltd"}
    )
    assert r.status_code == 200 and r.json()["billing_tag"] == "Acme Ltd"
    tags = (await alice.request("GET", "/v1/network/bandwidth/tags")).json()
    assert tags == [{"tag": "Acme Ltd", "ports": 1, "devices": 1}]
    r = await alice.request(
        "GET", "/v1/network/bandwidth", params={"tag": "Acme Ltd", "month": "2026-11"}
    )
    assert r.status_code in (200, 503), r.text
    if r.status_code == 200:
        body = r.json()
        assert body["ports"][0]["ifname"] == "Ethernet7"
        assert body["samples"] == 0 and body["coverage_pct"] == 0 and body["billable_p95_bps"] == 0
    # A tag is cleared with an empty string, and control characters aren't tags.
    bad = await alice.request(
        "PATCH", f"/v1/network/devices/{dev['id']}/interfaces/7", json={"billing_tag": "a\x01b"}
    )
    assert bad.status_code == 422
    r = await alice.request(
        "PATCH", f"/v1/network/devices/{dev['id']}/interfaces/7", json={"billing_tag": ""}
    )
    assert r.json()["billing_tag"] is None


async def test_proxmox_tokens_are_credentials_too(alice: User):
    body = {
        "name": "pve",
        "version": "proxmox",
        "token_user": "monitoring@pve",
        "token_name": "sentinel",
        "token_value": "aaaa-bbbb-secret",
        "insecure_tls": True,
    }
    r = await alice.request("POST", "/v1/network/credentials", json=body)
    assert r.status_code == 201, r.text
    c = r.json()
    assert c["token_set"] and c["insecure_tls"] and c["token_user"] == "monitoring@pve"
    assert "aaaa-bbbb" not in r.text
    for bad in ({"token_user": "monitoring"}, {"token_name": "a!b"}, {"token_value": ""}):
        r = await alice.request(
            "POST", "/v1/network/credentials", json={**body, "name": "x", **bad}
        )
        assert r.status_code == 422, bad
    # Turning the self-signed allowance off keeps the token.
    r = await alice.request(
        "PATCH", f"/v1/network/credentials/{c['id']}", json={"insecure_tls": False}
    )
    assert r.status_code == 200 and not r.json()["insecure_tls"] and r.json()["token_set"]
    poller = await insert_host(await alice.tenant_id(), "site")
    r = await alice.request(
        "POST",
        "/v1/network/devices",
        json={
            "addresses": ["10.0.11.100:8006"],
            "credential_id": c["id"],
            "poller_host_id": str(poller),
        },
    )
    dev = r.json()["created"][0]
    assert dev["address"] == "10.0.11.100:8006"
    r = await alice.request("GET", f"/v1/network/devices/{dev['id']}/proxmox")
    assert r.status_code in (200, 503)
    if r.status_code == 200:
        assert r.json()["resources"] == []


async def test_discovery_scans_your_own_private_ranges(alice: User, bob: User):
    from app.services import heartbeats

    cred = (await alice.request("POST", "/v1/network/credentials", json=V2)).json()
    poller = await insert_host(await alice.tenant_id(), "site")
    base = {"credential_id": cred["id"], "poller_host_id": str(poller)}
    for cidr in (
        "8.8.8.0/24",
        "10.0.0.0/21",
        "fd00::/120",
        "127.0.0.0/24",
        "240.0.0.0/24",
        "0.0.0.0/24",
        "198.18.0.0/24",
        "nonsense",
    ):
        r = await alice.request("POST", "/v1/network/discoveries", json={**base, "cidr": cidr})
        assert r.status_code == 422, cidr
    r = await alice.request(
        "POST", "/v1/network/discoveries", json={**base, "cidr": "10.20.30.7/24"}
    )
    assert r.status_code == 201, r.text
    d = r.json()
    assert d["cidr"] == "10.20.30.0/24" and d["status"] == "pending"
    # Bob can't read it, or start one with Alice's credential.
    assert (await bob.request("GET", f"/v1/network/discoveries/{d['id']}")).status_code == 404
    assert (await alice.request("GET", "/v1/network/discoveries/not-an-id")).status_code == 404
    # Results as ingest stores them: addresses already added are marked.
    await alice.request("POST", "/v1/network/devices", json={**base, "addresses": ["10.20.30.2"]})
    await heartbeats.redis.hset(
        f"pg:netdisc:{d['id']}",
        mapping={
            "status": "done",
            "scanned": 254,
            "total": 254,
            "found": json.dumps(
                [
                    {"address": "10.20.30.10", "sys_name": "sw10"},
                    {"address": "10.20.30.2", "sys_name": "sw2"},
                ]
            ),
        },
    )
    r = (await alice.request("GET", f"/v1/network/discoveries/{d['id']}")).json()
    assert [(f["address"], f["already_added"]) for f in r["found"]] == [
        ("10.20.30.2", True),
        ("10.20.30.10", False),
    ]
    # A Proxmox token isn't an SNMP credential.
    pve = await alice.request(
        "POST",
        "/v1/network/credentials",
        json={
            "name": "pve",
            "version": "proxmox",
            "token_user": "m@pve",
            "token_name": "t",
            "token_value": "v",
        },
    )
    r = await alice.request(
        "POST",
        "/v1/network/discoveries",
        json={**base, "credential_id": pve.json()["id"], "cidr": "10.1.1.0/24"},
    )
    assert r.status_code == 422
    # At most three scans at once.
    for i in range(3):
        await alice.request(
            "POST", "/v1/network/discoveries", json={**base, "cidr": f"10.5.{i}.0/24"}
        )
    r = await alice.request("POST", "/v1/network/discoveries", json={**base, "cidr": "10.6.0.0/24"})
    assert r.status_code == 429


async def test_a_stopped_scan_frees_its_slot_and_says_why(alice: User, bob: User):
    """A scan sent to a server that's offline, or whose server stops
    reporting midway, ends with the reason instead of holding one of the
    three slots for a day; scans can be listed and cancelled."""
    import time

    from app.services import heartbeats

    cred = (await alice.request("POST", "/v1/network/credentials", json=V2)).json()
    poller = await insert_host(await alice.tenant_id(), "site")
    base = {"credential_id": cred["id"], "poller_host_id": str(poller)}
    ids = []
    for i in range(3):
        r = await alice.request(
            "POST", "/v1/network/discoveries", json={**base, "cidr": f"10.7.{i}.0/24"}
        )
        ids.append(r.json()["id"])
    now = int(time.time())
    # Never picked up: created 11 minutes ago.
    await heartbeats.redis.hset(f"pg:netdisc:{ids[0]}", "created", now - 660)
    # Started, then silent for 3 minutes.
    await heartbeats.redis.hset(
        f"pg:netdisc:{ids[1]}",
        mapping={"status": "running", "scanned": 40, "total": 254, "updated": now - 180},
    )
    listed = (await alice.request("GET", "/v1/network/discoveries")).json()
    by_id = {d["id"]: d for d in listed}
    assert set(by_id) >= set(ids)
    assert by_id[ids[0]]["status"] == "done" and "didn't start" in by_id[ids[0]]["error"]
    assert by_id[ids[1]]["status"] == "done" and "stopped reporting" in by_id[ids[1]]["error"]
    assert by_id[ids[1]]["scanned"] == 40
    assert by_id[ids[2]]["status"] == "pending"
    # Ingest no longer hands the ended ones to the agent.
    members = await heartbeats.redis.smembers(f"pg:netdisc:poller:{poller}")
    assert set(members) == {ids[2]}
    # Their slots are free again.
    r = await alice.request("POST", "/v1/network/discoveries", json={**base, "cidr": "10.8.0.0/24"})
    assert r.status_code == 201, r.text
    # Cancel: only Alice's own, and it stays listed as cancelled.
    assert (await bob.request("DELETE", f"/v1/network/discoveries/{ids[2]}")).status_code == 404
    assert (await bob.request("GET", "/v1/network/discoveries")).json() == []
    r = await alice.request("DELETE", f"/v1/network/discoveries/{ids[2]}")
    assert r.status_code == 204
    d = (await alice.request("GET", f"/v1/network/discoveries/{ids[2]}")).json()
    assert d["status"] == "done" and d["error"] == "Cancelled."
    # Cancelling a finished scan changes nothing.
    r = await alice.request("DELETE", f"/v1/network/discoveries/{ids[0]}")
    assert r.status_code == 204
    d = (await alice.request("GET", f"/v1/network/discoveries/{ids[0]}")).json()
    assert "didn't start" in d["error"]


async def test_an_organisation_with_devices_exports_and_deletes(alice: User):
    cred = (await alice.request("POST", "/v1/network/credentials", json=V2)).json()
    poller = await insert_host(await alice.tenant_id(), "site")
    dev = (
        await alice.request(
            "POST",
            "/v1/network/devices",
            json={
                "addresses": ["10.3.0.1"],
                "credential_id": cred["id"],
                "poller_host_id": str(poller),
            },
        )
    ).json()["created"][0]
    r = await alice.request("GET", "/v1/organisation/export")
    assert r.status_code == 200
    body = r.text
    assert "s3cret-community" not in body and '"secret"' not in body
    exported = r.json()
    assert exported["network_credentials"][0]["name"] == V2["name"]
    assert any(s["id"] == dev["id"] for s in exported["servers"])
    # Deleting the organisation takes the devices and credentials with it.
    me = (await alice.request("GET", "/v1/me")).json()
    name = me["display_name"] or me["email"] or ""
    r = await alice.request("POST", "/v1/organisation/delete", json={"confirm_name": name})
    assert r.status_code in (204, 503), r.text
    if r.status_code == 204:
        async with ServiceSession() as db:
            left = await db.scalar(
                text("SELECT count(*) FROM snmp_credentials WHERE id = :c"), {"c": cred["id"]}
            )
        assert left == 0


async def test_a_server_depends_on_the_one_switch_it_is_cabled_to(alice: User):
    """LLDP from a server's NIC on a switch port makes the server depend on
    that switch (so the switch failing is one alert, not one per server);
    not when it's cabled to two switches, or when the switch's own upstream
    is the server (its poller); a hand-set dependency stays."""
    from app.routes.network import topology_everywhere

    tid = await alice.tenant_id()
    cred = (await alice.request("POST", "/v1/network/credentials", json=V2)).json()
    poller = await insert_host(tid, "poller")
    web, db, man = [await insert_host(tid, n) for n in ("web-1", "db-1", "app-1")]
    created = (
        await alice.request(
            "POST",
            "/v1/network/devices",
            json={
                "addresses": ["10.4.0.1", "10.4.0.2"],
                "credential_id": cred["id"],
                "poller_host_id": str(poller),
            },
        )
    ).json()["created"]
    sw_a, sw_b = (uuid.UUID(d["id"]) for d in created)
    r = await alice.request("PATCH", f"/v1/hosts/{man}", json={"depends_on_host_id": str(sw_b)})
    assert r.status_code == 200, r.text

    async def cable(switch, port, server):
        async with ServiceSession() as s, s.begin():
            await s.execute(
                text(
                    "INSERT INTO network_links (tenant_id, host_id, local_port, remote_sys_name,"
                    " remote_port_id, remote_chassis_id, remote_host_id, seen_at)"
                    " VALUES (:t, :h, :p, 'NIC', :m, :m, :r, now())"
                ),
                {"t": tid, "h": switch, "p": port, "m": f"d4:04:e6:00:00:{port[-1]}0", "r": server},
            )

    await cable(sw_a, "Ethernet1", web)
    await cable(sw_a, "Ethernet2", db)
    await cable(sw_b, "Ethernet2", db)  # dual-homed
    await cable(sw_a, "Ethernet3", poller)  # A's upstream is this poller
    await cable(sw_a, "Ethernet4", man)
    await topology_everywhere()

    async def upstream(h):
        b = (await alice.request("GET", f"/v1/hosts/{h}")).json()
        return b["depends_on_host_id"], b["depends_on_auto"]

    assert await upstream(web) == (str(sw_a), True)
    cabled = (await alice.request("GET", f"/v1/hosts/{db}")).json()["cabled_to"]
    assert [(c["device_id"], c["port"]) for c in cabled] == sorted(
        [(str(sw_a), "Ethernet2"), (str(sw_b), "Ethernet2")],
        key=lambda c: next(d["hostname"] for d in created if d["id"] == c[0]),
    )
    assert await upstream(db) == (None, False)
    assert await upstream(poller) == (None, False)
    assert await upstream(man) == (str(sw_b), False)
    # Saving the server's settings sends its upstream back: it stays automatic.
    r = await alice.request(
        "PATCH", f"/v1/hosts/{web}", json={"tags": ["web"], "depends_on_host_id": str(sw_a)}
    )
    assert (r.json()["depends_on_host_id"], r.json()["depends_on_auto"]) == (str(sw_a), True)
    # Recabled: the old link ages out and the dependency follows.
    async with ServiceSession() as s, s.begin():
        await s.execute(
            text(
                "UPDATE network_links SET seen_at = now() - interval '2 days'"
                " WHERE remote_host_id = :w"
            ),
            {"w": web},
        )
    await topology_everywhere()
    assert await upstream(web) == (None, False)


async def test_traps_are_listed_per_device_and_stay_in_the_organisation(alice: User, bob: User):
    cred = (await alice.request("POST", "/v1/network/credentials", json=V2)).json()
    tenant = await alice.tenant_id()
    poller = await insert_host(tenant, "poller")
    dev = (
        await alice.request(
            "POST",
            "/v1/network/devices",
            json={
                "credential_id": cred["id"],
                "poller_host_id": str(poller),
                "addresses": ["10.9.0.1"],
            },
        )
    ).json()["created"][0]["id"]
    async with ServiceSession() as db, db.begin():
        for host, action, rule, title in (
            (dev, "open", "trap_vpn_tunnel_down", "VPN tunnel is down"),
            (dev, "event", None, "IPS package updated"),
            (None, "event", None, "Trap 1.2.3"),  # a sender that isn't a device
        ):
            await db.execute(
                text(
                    "INSERT INTO network_traps (tenant_id, host_id, poller_host_id, source, oid,"
                    " name, title, action, rule, labels, received_at, last_at)"
                    " VALUES (:t, :h, :p, '10.9.0.1', '1.2', 'x', :title, :a, :r,"
                    ' \'{"tunnel": "to-branch"}\', now(), now())'
                ),
                {"t": tenant, "h": host, "p": poller, "title": title, "a": action, "r": rule},
            )
        await db.execute(text("UPDATE hosts SET trap_port = 1162 WHERE id = :p"), {"p": poller})

    everything = (await alice.request("GET", "/v1/network/traps")).json()
    assert len(everything) == 3 and {t["hostname"] for t in everything} == {None, "10.9.0.1"}
    mine = (await alice.request("GET", f"/v1/network/traps?device_id={dev}")).json()
    assert len(mine) == 2
    alerting = (await alice.request("GET", "/v1/network/traps?alerting=true")).json()
    assert [t["rule_name"] for t in alerting] == ["VPN tunnel down (trap)"]
    assert alerting[0]["labels"] == {"tunnel": "to-branch"}
    assert (await bob.request("GET", "/v1/network/traps")).json() == []

    device = (await alice.request("GET", f"/v1/network/devices/{dev}")).json()
    assert device["poller_trap_port"] == 1162
    pollers = (await alice.request("GET", "/v1/network/pollers")).json()
    assert [p["trap_port"] for p in pollers if p["hostname"] == "poller"] == [1162]
