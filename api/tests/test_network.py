"""Network devices: credentials, adding devices, pollers, topology."""

import uuid

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
    "sd_wan_latency_high",
    "sd_wan_link_dead",
    "sd_wan_packet_loss",
    "sensor_above_critical_threshold",
    "sensor_above_warning_threshold",
    "sophos_disk_almost_full",
    "sophos_memory_high",
    "vpn_tunnel_down",
]


def test_condition_catalog_matches_the_alerter():
    from app.services.netconditions import CONDITIONS

    assert sorted(CONDITIONS) == SHARED_CONDITION_KEYS


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
    assert "VPN tunnel down" in names and len(names) == 20
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
