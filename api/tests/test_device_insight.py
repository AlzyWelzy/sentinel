"""Device insight: availability, busiest and troubled ports, and the weekly
heatmap, from the poller's metrics; other accounts see nothing."""

import time
import uuid

import httpx

from app.config import settings

from .conftest import User, insert_host
from .test_monitoring_depth import needs_vm
from .test_network import V2, credentials_key  # noqa: F401 (autouse fixture)


def _push_at(tenant_id: uuid.UUID, host_id: uuid.UUID, ts: int, lines: list[str]) -> None:
    body = "\n".join(
        line.replace("{", f'{{host_id="{host_id}",', 1) + f" {ts * 1000}" for line in lines
    )
    base = settings.VICTORIAMETRICS_URL
    httpx.post(
        f"{base}/api/v1/import/prometheus",
        params={"extra_label": f"tenant_id={tenant_id}"},
        content=body,
    ).raise_for_status()
    httpx.get(f"{base}/internal/force_flush").raise_for_status()


@needs_vm
async def test_device_insight(alice: User, bob: User):
    tid = await alice.tenant_id()
    cred = (await alice.request("POST", "/v1/network/credentials", json=V2)).json()
    poller = await insert_host(tid, "site-poller")
    add = {"credential_id": cred["id"], "poller_host_id": str(poller), "addresses": ["10.9.0.1"]}
    r = await alice.request("POST", "/v1/network/devices", json=add)
    dev = uuid.UUID(r.json()["created"][0]["id"])
    now = int(time.time()) - 60
    for i, ts in enumerate(range(now - 600, now + 1, 60)):
        _push_at(tid, dev, ts, [
            'sentinel_net_snmp_up{} 1',
            f'sentinel_net_if_in_octets_total{{ifname="Ethernet1"}} {i * 75_000_000}',
            f'sentinel_net_if_out_octets_total{{ifname="Ethernet1"}} {i * 25_000_000}',
            f'sentinel_net_if_in_octets_total{{ifname="Ethernet2"}} {i * 1_000_000}',
            'sentinel_net_if_out_octets_total{ifname="Ethernet2"} 0',
            f'sentinel_net_if_in_errors_total{{ifname="Ethernet2"}} {i * 3}',
            f'sentinel_net_if_oper_status{{ifname="Ethernet3"}} {1 + i % 2}',
        ])  # fmt: skip
    r = await alice.request("GET", f"/v1/network/devices/{dev}/insight", params={"days": 1})
    assert r.status_code == 200, r.text
    ins = r.json()
    assert ins["availability"] == 100
    assert [p["ifname"] for p in ins["busiest"]][:2] == ["Ethernet1", "Ethernet2"]
    # Ethernet1 moves 100 MB a minute: about 13.3 Mbit/s at its peak.
    peak = next(p["value"] for p in ins["peaks"] if p["ifname"] == "Ethernet1")
    assert 10e6 < peak < 16e6, peak
    assert ins["errors"][0]["ifname"] == "Ethernet2" and ins["errors"][0]["value"] >= 20
    assert ins["flaps"][0]["ifname"] == "Ethernet3" and ins["flaps"][0]["value"] >= 9
    assert len(ins["heatmap"]) == 7 and all(len(row) == 24 for row in ins["heatmap"])
    assert any(v for v in ins["heatmap"][-1] if v)
    assert (await bob.request("GET", f"/v1/network/devices/{dev}/insight")).status_code == 404
    bad = await alice.request("GET", f"/v1/network/devices/{dev}/insight", params={"days": 365})
    assert bad.status_code == 422
