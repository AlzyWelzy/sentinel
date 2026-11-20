"""Network devices: switches, firewalls and other gear polled over SNMP.

A device is a hosts row (kind 'network') polled by one of the organisation's
servers that can reach it (its poller). Everything for servers applies to
it: tags, maintenance, dependencies, pausing, "not reporting" alerts. This
module adds what's particular to devices: SNMP credentials, adding devices,
their interfaces and neighbours, and the topology built from LLDP.
"""

import ipaddress
import math
import re
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.models import Host, NetworkInterface, NetworkLink, SNMPCredential
from app.routes.v1 import HostOut, _get_host, _hosts_out
from app.services import devicesecrets, heartbeats, metrics
from app.tenancy import Tenant, TenantContext
from app.validation import Trimmed, normalize_tags

router = APIRouter(prefix="/v1/network", tags=["network"])

ROLES = ("core", "distribution", "access", "firewall", "router", "wireless", "other")
Role = Literal["core", "distribution", "access", "firewall", "router", "wireless", "other"]
AUTH_PROTOCOLS = ("md5", "sha", "sha224", "sha256", "sha384", "sha512")
PRIV_PROTOCOLS = ("des", "aes", "aes192", "aes256", "aes192c", "aes256c")
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
MAX_DEVICES_PER_REQUEST = 256


def normalize_address(value: str) -> str:
    """An IP address or hostname, with an optional port: 10.0.0.1,
    10.0.0.1:1161, [2001:db8::1]:161, core1.example.net. Never a URL."""
    v = value.strip()
    host, port = v, None
    if v.startswith("["):
        m = re.fullmatch(r"\[([0-9A-Fa-f:.]+)\](?::(\d{1,5}))?", v)
        if not m:
            raise ValueError(f"{value!r} isn't an address")
        host, port = m.group(1), m.group(2)
    elif v.count(":") == 1:
        host, port = v.split(":")
    try:
        ip = ipaddress.ip_address(host)
        host = str(ip)
    except ValueError:
        if not HOSTNAME_RE.match(host):
            raise ValueError(f"{value!r} isn't an IP address or hostname") from None
        host = host.lower()
    if port is not None:
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError(f"{value!r} has an invalid port")
        if int(port) == 161:
            port = None
    if port is None:
        return host
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


# ── Credentials ──────────────────────────────────────────────────────────────


class _CredentialSecrets(BaseModel):
    community: str | None = Field(default=None, max_length=255)
    username: str | None = Field(default=None, max_length=255)
    auth_protocol: str | None = None
    auth_password: str | None = Field(default=None, max_length=255)
    priv_protocol: str | None = None
    priv_password: str | None = Field(default=None, max_length=255)
    context: str | None = Field(default=None, max_length=255)

    @field_validator("auth_protocol", "priv_protocol")
    @classmethod
    def _lower(cls, v: str | None) -> str | None:
        return v.strip().lower() or None if v else None


class CredentialIn(_CredentialSecrets):
    name: Annotated[str, Trimmed, Field(min_length=1, max_length=100)]
    version: Literal["1", "2c", "3"] = "2c"


class CredentialPatch(_CredentialSecrets):
    name: Annotated[str, Trimmed, Field(min_length=1, max_length=100)] | None = None
    version: Literal["1", "2c", "3"] | None = None


class CredentialOut(BaseModel):
    id: uuid.UUID
    name: str
    version: str
    community_set: bool
    username: str | None
    auth_protocol: str | None
    auth_set: bool
    priv_protocol: str | None
    priv_set: bool
    context: str | None
    devices: int
    created_at: datetime


def _check_secret(version: str, s: dict) -> dict:
    """Keep what the version uses and check it's complete."""
    if version in ("1", "2c"):
        if not s.get("community"):
            raise HTTPException(422, "SNMP v1 and v2c need a community")
        return {"community": s["community"]}
    if not s.get("username"):
        raise HTTPException(422, "SNMP v3 needs a username")
    auth, priv = s.get("auth_protocol"), s.get("priv_protocol")
    if auth and auth not in AUTH_PROTOCOLS:
        raise HTTPException(422, f"auth_protocol is one of {', '.join(AUTH_PROTOCOLS)}")
    if priv and priv not in PRIV_PROTOCOLS:
        raise HTTPException(422, f"priv_protocol is one of {', '.join(PRIV_PROTOCOLS)}")
    if auth and len(s.get("auth_password") or "") < 8:
        raise HTTPException(422, "SNMP v3 passwords are at least 8 characters")
    if priv and not auth:
        raise HTTPException(422, "Privacy (encryption) needs authentication too")
    if priv and len(s.get("priv_password") or "") < 8:
        raise HTTPException(422, "SNMP v3 passwords are at least 8 characters")
    out = {"username": s["username"]}
    for k in ("auth_protocol", "auth_password", "priv_protocol", "priv_password", "context"):
        if (auth or not k.startswith("auth")) and (priv or not k.startswith("priv")) and s.get(k):
            out[k] = s[k]
    return out


def _credential_out(c: SNMPCredential, devices: int) -> CredentialOut:
    try:
        s = devicesecrets.open_sealed(c.secret)
    except Exception:
        s = {}
    return CredentialOut(
        id=c.id,
        name=c.name,
        version=c.version,
        community_set=bool(s.get("community")),
        username=s.get("username"),
        auth_protocol=s.get("auth_protocol"),
        auth_set=bool(s.get("auth_password")),
        priv_protocol=s.get("priv_protocol"),
        priv_set=bool(s.get("priv_password")),
        context=s.get("context"),
        devices=devices,
        created_at=c.created_at,
    )


def _seal(values: dict) -> str:
    try:
        return devicesecrets.seal(values)
    except devicesecrets.CredentialsKeyMissing:
        raise HTTPException(
            503, "Network monitoring isn't set up on this server (CREDENTIALS_KEY)"
        ) from None


async def _usage(t: TenantContext) -> dict[uuid.UUID, int]:
    rows = await t.db.execute(
        select(Host.snmp_credential_id, func.count())
        .where(Host.tenant_id == t.tenant_id, Host.snmp_credential_id.is_not(None))
        .group_by(Host.snmp_credential_id)
    )
    return {cid: n for cid, n in rows if cid}


@router.get("/credentials")
async def list_credentials(t: Tenant) -> list[CredentialOut]:
    rows = await t.db.scalars(
        select(SNMPCredential)
        .where(SNMPCredential.tenant_id == t.tenant_id)
        .order_by(SNMPCredential.name)
    )
    used = await _usage(t)
    return [_credential_out(c, used.get(c.id, 0)) for c in rows]


async def _get_credential(t: TenantContext, cid: uuid.UUID) -> SNMPCredential:
    c = await t.db.scalar(
        select(SNMPCredential).where(
            SNMPCredential.id == cid, SNMPCredential.tenant_id == t.tenant_id
        )
    )
    if c is None:
        raise HTTPException(404, "Credential not found")
    return c


@router.post("/credentials", status_code=status.HTTP_201_CREATED)
async def create_credential(body: CredentialIn, t: Tenant) -> CredentialOut:
    secret = _check_secret(body.version, body.model_dump())
    c = SNMPCredential(
        tenant_id=t.tenant_id, name=body.name, version=body.version, secret=_seal(secret)
    )
    t.db.add(c)
    try:
        await t.db.flush()
    except IntegrityError:
        raise HTTPException(409, "A credential with that name exists") from None
    await t.db.refresh(c)
    return _credential_out(c, 0)


@router.patch("/credentials/{credential_id}")
async def update_credential(
    credential_id: uuid.UUID, body: CredentialPatch, t: Tenant
) -> CredentialOut:
    """Secrets left out (or empty) keep their current value."""
    c = await _get_credential(t, credential_id)
    try:
        current = devicesecrets.open_sealed(c.secret)
    except devicesecrets.CredentialsKeyMissing:
        raise HTTPException(
            503, "Network monitoring isn't set up on this server (CREDENTIALS_KEY)"
        ) from None
    except Exception:
        current = {}
    version = body.version or c.version
    merged = {
        **current,
        **{k: v for k, v in body.model_dump(exclude={"name", "version"}).items() if v},
    }
    c.secret = _seal(_check_secret(version, merged))
    c.version = version
    if body.name:
        c.name = body.name
    try:
        await t.db.flush()
    except IntegrityError:
        raise HTTPException(409, "A credential with that name exists") from None
    return _credential_out(c, (await _usage(t)).get(c.id, 0))


@router.delete("/credentials/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_credential(credential_id: uuid.UUID, t: Tenant) -> None:
    c = await _get_credential(t, credential_id)
    if n := (await _usage(t)).get(c.id, 0):
        raise HTTPException(
            409, f"{n} device{'s use' if n != 1 else ' uses'} it: change them first"
        )
    await t.db.delete(c)


# ── Pollers and profiles ─────────────────────────────────────────────────────


class PollerOut(BaseModel):
    id: uuid.UUID
    hostname: str
    online: bool
    os: str | None
    agent_version: str | None
    devices: int


@router.get("/pollers")
async def list_pollers(t: Tenant) -> list[PollerOut]:
    """Servers that can poll devices: any of the organisation's agents."""
    hosts = list(
        await t.db.scalars(
            select(Host)
            .where(Host.tenant_id == t.tenant_id, Host.kind == "server", Host.revoked_at.is_(None))
            .order_by(Host.hostname)
        )
    )
    counts = dict(
        (
            await t.db.execute(
                select(Host.poller_host_id, func.count())
                .where(Host.tenant_id == t.tenant_id, Host.poller_host_id.is_not(None))
                .group_by(Host.poller_host_id)
            )
        ).all()
    )
    seen = await heartbeats.last_seen([h.id for h in hosts])
    return [
        PollerOut(
            id=h.id,
            hostname=h.hostname,
            online=heartbeats.is_online(seen[h.id]),
            os=h.os,
            agent_version=h.agent_version,
            devices=counts.get(h.id, 0),
        )
        for h in hosts
    ]


class ProfileOut(BaseModel):
    name: str
    vendor: str
    description: str


def _profiles_dir() -> Path:
    for p in (
        Path("/app/netmon-profiles"),
        Path(__file__).resolve().parents[3] / "netmon" / "profiles",
    ):
        if p.is_dir():
            return p
    return Path("/nonexistent")


def load_profiles() -> list[ProfileOut]:
    out = []
    for f in sorted(_profiles_dir().glob("*.yaml")):
        text = f.read_text()
        top = dict(re.findall(r"^(name|vendor|description):\s*(.+?)\s*$", text, re.M))
        name = top.get("name", "").strip("'\"")
        if not name or name.startswith("_"):
            continue  # mixins aren't chosen directly
        out.append(
            ProfileOut(
                name=name,
                vendor=top.get("vendor", "").strip("'\""),
                description=top.get("description", "").strip("'\""),
            )
        )
    return out


PROFILES = load_profiles()


@router.get("/profiles")
async def list_profiles(t: Tenant) -> list[ProfileOut]:
    """Vendor profiles; a device's is detected from its sysObjectID unless pinned."""
    return PROFILES


# ── Devices ──────────────────────────────────────────────────────────────────


class DevicesIn(BaseModel):
    addresses: list[str] = Field(min_length=1, max_length=MAX_DEVICES_PER_REQUEST)
    name: Annotated[str, Trimmed, Field(min_length=1, max_length=255)] | None = Field(
        default=None, description="only with one address; else named from sysName"
    )
    credential_id: uuid.UUID
    poller_host_id: uuid.UUID
    profile: str | None = Field(default=None, description="pin a profile; empty detects it")
    network_role: Role | None = None
    tags: list[str] = Field(default_factory=list)

    @field_validator("addresses")
    @classmethod
    def _addresses(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        for a in v:
            n = normalize_address(a)
            if n not in out:
                out.append(n)
        return out

    @field_validator("tags")
    @classmethod
    def _tags(cls, v: list[str]) -> list[str]:
        return normalize_tags(v)

    @model_validator(mode="after")
    def _one_name(self) -> "DevicesIn":
        if self.name and len(self.addresses) > 1:
            raise ValueError("name only applies to a single address")
        return self


class DevicesOut(BaseModel):
    created: list[HostOut]
    skipped: list[str] = Field(description="addresses this poller already polls")


async def _check_poller(t: TenantContext, poller_id: uuid.UUID) -> Host:
    p = await t.db.scalar(
        select(Host).where(
            Host.id == poller_id,
            Host.tenant_id == t.tenant_id,
            Host.kind == "server",
            Host.revoked_at.is_(None),
        )
    )
    if p is None:
        raise HTTPException(422, "The poller must be one of your servers")
    return p


def _check_profile(name: str | None) -> str | None:
    if not name:
        return None
    if name not in {p.name for p in PROFILES}:
        raise HTTPException(422, f"Unknown profile {name!r}")
    return name


@router.post("/devices", status_code=status.HTTP_201_CREATED)
async def add_devices(body: DevicesIn, t: Tenant) -> DevicesOut:
    """Adds devices to be polled by one of your servers. Each is named from
    its sysName at the first poll, unless named here."""
    await _get_credential(t, body.credential_id)
    await _check_poller(t, body.poller_host_id)
    profile = _check_profile(body.profile)
    existing = set(
        await t.db.scalars(
            select(Host.address).where(
                Host.tenant_id == t.tenant_id,
                Host.kind == "network",
                Host.poller_host_id == body.poller_host_id,
            )
        )
    )
    created, skipped = [], []
    for addr in body.addresses:
        if addr in existing:
            skipped.append(addr)
            continue
        h = Host(
            tenant_id=t.tenant_id,
            kind="network",
            machine_id=f"network:{uuid.uuid4()}",
            hostname=body.name or addr,
            address=addr,
            os="network",
            poller_host_id=body.poller_host_id,
            snmp_credential_id=body.credential_id,
            profile=profile,
            network_role=body.network_role,
            tags=body.tags,
        )
        t.db.add(h)
        created.append(h)
    await t.db.flush()
    for h in created:
        await t.db.refresh(h)
    if created:
        await _add_network_rules(t)
    return DevicesOut(created=await _hosts_out(t, created), skipped=skipped)


async def _add_network_rules(t: TenantContext) -> None:
    """The network alert rules, once per organisation (with its first
    device): later deletes stick. Names already in use are skipped."""
    from sqlalchemy import text

    from app.db import ServiceSession
    from app.models import AlertRule
    from app.routes.alerts import RuleIn
    from app.services.netconditions import starter_rules

    async with ServiceSession() as sdb, sdb.begin():
        claimed = await sdb.scalar(
            text(
                "UPDATE tenants SET network_rules_at = now() "
                "WHERE id = :t AND network_rules_at IS NULL RETURNING id"
            ),
            {"t": t.tenant_id},
        )
    if claimed is None:
        return
    existing = set(
        await t.db.scalars(select(AlertRule.name).where(AlertRule.tenant_id == t.tenant_id))
    )
    for spec in starter_rules():
        if spec["name"] in existing:
            continue
        body = RuleIn(**spec)
        t.db.add(
            AlertRule(
                tenant_id=t.tenant_id, **body.model_dump(exclude={"channel_ids", "escalations"})
            )
        )
    await t.db.flush()


class DevicePatch(BaseModel):
    name: Annotated[str, Trimmed, Field(min_length=1, max_length=255)] | None = None
    address: str | None = None
    credential_id: uuid.UUID | None = None
    poller_host_id: uuid.UUID | None = None
    profile: str | None = Field(default=None, description="'' detects it again")
    network_role: Role | None = None
    clear_role: bool = False

    @field_validator("address")
    @classmethod
    def _address(cls, v: str | None) -> str | None:
        return None if v is None else normalize_address(v)


async def _get_device(t: TenantContext, device_id: uuid.UUID) -> Host:
    h = await _get_host(t, device_id)
    if h.kind != "network":
        raise HTTPException(404, "Device not found")
    return h


@router.patch("/devices/{device_id}")
async def update_device(device_id: uuid.UUID, body: DevicePatch, t: Tenant) -> HostOut:
    h = await _get_device(t, device_id)
    if body.name:
        h.hostname = body.name
    if body.address and body.address != h.address:
        if h.hostname == h.address:
            h.hostname = body.address
        h.address = body.address
        h.device, h.device_error = {}, None
    if body.credential_id:
        await _get_credential(t, body.credential_id)
        h.snmp_credential_id = body.credential_id
    if body.poller_host_id:
        await _check_poller(t, body.poller_host_id)
        h.poller_host_id = body.poller_host_id
    if body.profile is not None:
        h.profile = _check_profile(body.profile)
    if body.clear_role:
        h.network_role = None
    elif body.network_role:
        h.network_role = body.network_role
    await t.db.flush()
    return (await _hosts_out(t, [h]))[0]


class InterfaceOut(BaseModel):
    ifindex: int
    name: str
    descr: str | None
    alias: str | None
    speed_bps: int | None
    mac: str | None
    admin_up: bool | None
    oper_up: bool | None
    in_bps: float | None = None
    out_bps: float | None = None
    utilisation: float | None = Field(default=None, description="the busier direction, % of speed")
    errors_per_sec: float | None = None
    billing_tag: str | None
    neighbor: str | None = None
    neighbor_host_id: uuid.UUID | None = None


class LinkOut(BaseModel):
    local_port: str
    remote_sys_name: str
    remote_port_id: str
    remote_port_desc: str | None
    remote_mgmt_addr: str | None
    remote_host_id: uuid.UUID | None
    remote_hostname: str | None


class DeviceOut(BaseModel):
    host: HostOut
    profile: str | None
    profile_pinned: bool
    system: dict
    inventory: dict
    last_ok_at: str | None
    polled_at: datetime | None
    poll_duration_ms: int | None
    credential_id: uuid.UUID | None
    credential_name: str | None
    poller_hostname: str | None
    interfaces: list[InterfaceOut]
    links: list[LinkOut]


async def _interface_rates(t: TenantContext, device_id: uuid.UUID) -> dict[str, dict[str, float]]:
    sel = f'host_id="{device_id}"'
    queries = {
        "in": f"rate(sentinel_net_if_in_octets_total{{{sel}}}[5m]) * 8",
        "out": f"rate(sentinel_net_if_out_octets_total{{{sel}}}[5m]) * 8",
        "err": (
            'sum by (ifname) (rate({__name__=~"sentinel_net_if_(in|out)_errors_total",'
            f"{sel}}}[5m]))"
        ),
    }
    out: dict[str, dict[str, float]] = {}
    for key, q in queries.items():
        try:
            rows = await metrics.query_instant(t.tenant_id, q)
        except metrics.MetricsUnavailable:
            return {}
        for labels, v in rows:
            if name := labels.get("ifname"):
                out.setdefault(name, {})[key] = v
    return out


@router.get("/devices/{device_id}")
async def get_device(device_id: uuid.UUID, t: Tenant) -> DeviceOut:
    h = await _get_device(t, device_id)
    host = (await _hosts_out(t, [h]))[0]
    ifs = list(
        await t.db.scalars(
            select(NetworkInterface)
            .where(NetworkInterface.tenant_id == t.tenant_id, NetworkInterface.host_id == h.id)
            .order_by(NetworkInterface.ifindex)
        )
    )
    links = list(
        await t.db.scalars(
            select(NetworkLink)
            .where(NetworkLink.tenant_id == t.tenant_id, NetworkLink.host_id == h.id)
            .order_by(NetworkLink.local_port)
        )
    )
    names = dict(
        (
            await t.db.execute(
                select(Host.id, Host.hostname).where(
                    Host.tenant_id == t.tenant_id,
                    Host.id.in_(
                        [x for x in [h.poller_host_id, *[ln.remote_host_id for ln in links]] if x]
                    ),
                )
            )
        ).all()
    )
    cred = (
        await t.db.scalar(
            select(SNMPCredential.name).where(
                SNMPCredential.id == h.snmp_credential_id, SNMPCredential.tenant_id == t.tenant_id
            )
        )
        if h.snmp_credential_id
        else None
    )
    rates = await _interface_rates(t, h.id)
    by_port = {ln.local_port: ln for ln in links}
    interfaces = []
    for i in ifs:
        r = rates.get(i.name, {})
        speed = i.speed_bps or 0
        busiest = max(r.get("in", 0), r.get("out", 0)) if r else None
        ln = by_port.get(i.name)
        interfaces.append(
            InterfaceOut(
                ifindex=i.ifindex,
                name=i.name,
                descr=i.descr,
                alias=i.alias,
                speed_bps=i.speed_bps,
                mac=i.mac,
                admin_up=i.admin_up,
                oper_up=None if i.oper_status is None else i.oper_status == 1,
                in_bps=r.get("in"),
                out_bps=r.get("out"),
                utilisation=round(100 * busiest / speed, 1)
                if busiest is not None and speed > 0
                else None,
                errors_per_sec=r.get("err"),
                billing_tag=i.billing_tag,
                neighbor=(ln.remote_sys_name or ln.remote_mgmt_addr or ln.remote_chassis_id)
                if ln
                else None,
                neighbor_host_id=ln.remote_host_id if ln else None,
            )
        )
    d = h.device or {}
    return DeviceOut(
        host=host,
        profile=d.get("profile") or h.profile,
        profile_pinned=bool(h.profile),
        system=d.get("system") or {},
        inventory=d.get("inventory") or {},
        last_ok_at=d.get("last_ok_at"),
        polled_at=h.device_polled_at,
        poll_duration_ms=d.get("duration_ms"),
        credential_id=h.snmp_credential_id,
        credential_name=cred,
        poller_hostname=names.get(h.poller_host_id) if h.poller_host_id else None,
        interfaces=interfaces,
        links=[
            LinkOut(
                local_port=ln.local_port,
                remote_sys_name=ln.remote_sys_name,
                remote_port_id=ln.remote_port_id,
                remote_port_desc=ln.remote_port_desc,
                remote_mgmt_addr=ln.remote_mgmt_addr,
                remote_host_id=ln.remote_host_id,
                remote_hostname=names.get(ln.remote_host_id) if ln.remote_host_id else None,
            )
            for ln in links
        ],
    )


def promql_string(value: str) -> str:
    """A label value inside double quotes in PromQL."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


class TrafficOut(BaseModel):
    series: list[dict] = Field(description="direction in/out, in bits per second")


@router.get("/devices/{device_id}/traffic")
async def device_traffic(
    device_id: uuid.UUID,
    t: Tenant,
    start: int,
    end: int,
    ifname: Annotated[
        str | None,
        Query(max_length=255, description="one interface; all of them summed if left out"),
    ] = None,
) -> TrafficOut:
    h = await _get_device(t, device_id)
    if not 0 < end - start <= 400 * 86400:
        raise HTTPException(422, "Pick a range of up to 400 days")
    sel = f'host_id="{h.id}"'
    if ifname is not None:
        known = await t.db.scalar(
            select(NetworkInterface.ifindex).where(
                NetworkInterface.tenant_id == t.tenant_id,
                NetworkInterface.host_id == h.id,
                NetworkInterface.name == ifname,
            )
        )
        if known is None:
            raise HTTPException(404, "No interface by that name")
        sel += f",ifname={promql_string(ifname)}"
    step = max(30, (end - start) // 300)
    window = f"{max(step, 120)}s"
    out = []
    try:
        for direction in ("in", "out"):
            q = f"sum(rate(sentinel_net_if_{direction}_octets_total{{{sel}}}[{window}])) * 8"
            for s in await metrics.query_series(t.tenant_id, q, start, end, step, []):
                out.append({"labels": {"direction": direction}, "points": s["points"]})
    except metrics.MetricsUnavailable:
        raise HTTPException(503, "Metrics are unavailable right now") from None
    return TrafficOut(series=out)


class InterfacePatch(BaseModel):
    billing_tag: str | None = Field(
        default=None,
        max_length=100,
        description="groups ports for 95th-percentile bandwidth; '' clears",
    )


@router.patch("/devices/{device_id}/interfaces/{ifindex}")
async def update_interface(
    device_id: uuid.UUID, ifindex: int, body: InterfacePatch, t: Tenant
) -> dict:
    await _get_device(t, device_id)
    i = await t.db.scalar(
        select(NetworkInterface).where(
            NetworkInterface.tenant_id == t.tenant_id,
            NetworkInterface.host_id == device_id,
            NetworkInterface.ifindex == ifindex,
        )
    )
    if i is None:
        raise HTTPException(404, "Interface not found")
    if body.billing_tag is not None:
        tag = body.billing_tag.strip()
        if tag and not re.fullmatch(r"[^\x00-\x1f\x7f]{1,100}", tag):
            raise HTTPException(422, "Billing tags are printable text")
        i.billing_tag = tag or None
    await t.db.flush()
    return {"ifindex": i.ifindex, "billing_tag": i.billing_tag}


# ── Topology ─────────────────────────────────────────────────────────────────


class TopologyNode(BaseModel):
    id: uuid.UUID
    hostname: str
    kind: str
    network_role: str | None
    online: bool
    parent_id: uuid.UUID | None
    parent_auto: bool
    parent_via: Literal["lldp", "manual", "poller"] | None = Field(
        default=None, description="how the upstream was chosen; poller when it has none of its own"
    )


class TopologyEdge(BaseModel):
    source: uuid.UUID
    target: uuid.UUID
    source_port: str
    target_port: str


class TopologyOut(BaseModel):
    nodes: list[TopologyNode]
    edges: list[TopologyEdge]
    has_core: bool = Field(description="a device is marked core: automatic upstreams need one")


@router.get("/topology")
async def topology(t: Tenant) -> TopologyOut:
    devices = list(
        await t.db.scalars(
            select(Host).where(Host.tenant_id == t.tenant_id, Host.revoked_at.is_(None))
        )
    )
    links = list(
        await t.db.scalars(
            select(NetworkLink).where(
                NetworkLink.tenant_id == t.tenant_id, NetworkLink.remote_host_id.is_not(None)
            )
        )
    )
    linked = {ln.host_id for ln in links} | {ln.remote_host_id for ln in links}
    shown = [
        h
        for h in devices
        if h.kind == "network" or h.id in linked or h.id in {d.poller_host_id for d in devices}
    ]
    seen = await heartbeats.last_seen([h.id for h in shown])
    edges, pairs = [], set()
    for ln in links:
        key = tuple(sorted((str(ln.host_id), str(ln.remote_host_id))))
        if key in pairs or ln.remote_host_id is None:
            continue
        pairs.add(key)
        edges.append(
            TopologyEdge(
                source=ln.host_id,
                target=ln.remote_host_id,
                source_port=ln.local_port,
                target_port=ln.remote_port_desc or ln.remote_port_id,
            )
        )
    return TopologyOut(
        nodes=[
            TopologyNode(
                id=h.id,
                hostname=h.hostname,
                kind=h.kind,
                network_role=h.network_role,
                online=heartbeats.is_online(seen[h.id]),
                parent_id=h.depends_on_host_id or h.poller_host_id,
                parent_auto=h.depends_on_auto,
                parent_via=(
                    ("lldp" if h.depends_on_auto else "manual")
                    if h.depends_on_host_id
                    else ("poller" if h.poller_host_id else None)
                ),
            )
            for h in shown
        ],
        edges=edges,
        has_core=any(h.network_role == "core" for h in devices),
    )


def compute_parents(
    devices: dict[uuid.UUID, str | None], links: list[tuple[uuid.UUID, uuid.UUID]]
) -> dict[uuid.UUID, uuid.UUID]:
    """Each device's upstream: the neighbour one hop closer to a core device
    (breadth-first over the LLDP graph). Ties go to the lower role rank
    (core before distribution before access...), then the lower id, so the
    answer doesn't change from one run to the next."""
    rank = {r: i for i, r in enumerate(ROLES)}
    graph: dict[uuid.UUID, set[uuid.UUID]] = {d: set() for d in devices}
    for a, b in links:
        if a in graph and b in graph and a != b:
            graph[a].add(b)
            graph[b].add(a)
    dist = {d: 0 for d, role in devices.items() if role == "core"}
    frontier = sorted(dist, key=str)
    while frontier:
        nxt = []
        for d in frontier:
            for n in sorted(graph[d], key=str):
                if n not in dist:
                    dist[n] = dist[d] + 1
                    nxt.append(n)
        frontier = nxt
    parents = {}
    for d in devices:
        if d not in dist or dist[d] == 0:
            continue
        closer = [n for n in graph[d] if dist.get(n) == dist[d] - 1]
        closer.sort(key=lambda n: (rank.get(devices[n] or "other", len(ROLES)), str(n)))
        parents[d] = closer[0]
    return parents


async def apply_topology(db, tenant_id: uuid.UUID) -> int:
    """Sets automatic upstreams from LLDP for one organisation (a session
    scoped to it). Hand-set dependencies are left alone. Returns changes."""
    hosts = list(
        await db.scalars(select(Host).where(Host.tenant_id == tenant_id, Host.revoked_at.is_(None)))
    )
    devices = {h.id: h.network_role for h in hosts if h.kind == "network"}
    if not any(r == "core" for r in devices.values()):
        return 0
    stale = datetime.now(UTC) - timedelta(days=1)
    links = [
        (ln.host_id, ln.remote_host_id)
        for ln in await db.scalars(
            select(NetworkLink).where(
                NetworkLink.tenant_id == tenant_id,
                NetworkLink.remote_host_id.is_not(None),
                NetworkLink.seen_at > stale,
            )
        )
        if ln.remote_host_id
    ]
    parents = compute_parents(devices, links)
    changed = 0
    for h in hosts:
        if h.kind != "network" or (h.depends_on_host_id and not h.depends_on_auto):
            continue
        want = parents.get(h.id)
        if want != h.depends_on_host_id:
            h.depends_on_host_id, h.depends_on_auto = want, want is not None
            changed += 1
    await db.flush()
    return changed


async def topology_everywhere() -> int:
    """apply_topology for every organisation with a core device (jobs)."""
    from sqlalchemy import text

    from app.db import AppSession, ServiceSession

    async with ServiceSession() as sdb:
        tenants = list(
            await sdb.scalars(
                text(
                    "SELECT DISTINCT h.tenant_id FROM hosts h JOIN tenants t ON t.id = h.tenant_id "
                    "WHERE h.kind = 'network' AND h.network_role = 'core' AND t.status = 'active'"
                )
            )
        )
    changed = 0
    for tid in tenants:
        async with AppSession() as db, db.begin():
            await db.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tid)})
            changed += await apply_topology(db, tid)
    return changed


class ConditionOut(BaseModel):
    key: str
    name: str
    unit: str
    default: float | None
    about: str
    vendor: str


@router.get("/conditions")
async def list_conditions(t: Tenant) -> list[ConditionOut]:
    """What a network alert rule can watch (kind network, target = key)."""
    from app.services.netconditions import CONDITIONS

    return [
        ConditionOut(
            key=c.key, name=c.name, unit=c.unit, default=c.default, about=c.about, vendor=c.vendor
        )
        for c in CONDITIONS.values()
    ]


# ── 95th-percentile bandwidth ────────────────────────────────────────────────

BILLING_STEP = 300  # 5-minute average rates, the industry standard
MAX_BILLING_PORTS = 200


class BillingTagOut(BaseModel):
    tag: str
    ports: int
    devices: int


@router.get("/bandwidth/tags")
async def bandwidth_tags(t: Tenant) -> list[BillingTagOut]:
    rows = await t.db.execute(
        select(
            NetworkInterface.billing_tag,
            func.count(),
            func.count(func.distinct(NetworkInterface.host_id)),
        )
        .where(NetworkInterface.tenant_id == t.tenant_id, NetworkInterface.billing_tag.is_not(None))
        .group_by(NetworkInterface.billing_tag)
        .order_by(NetworkInterface.billing_tag)
    )
    return [BillingTagOut(tag=tag, ports=n, devices=d) for tag, n, d in rows if tag]


class BillingPort(BaseModel):
    device_id: uuid.UUID
    device: str
    ifname: str
    alias: str | None
    speed_bps: int | None


class BillingDirection(BaseModel):
    p95_bps: float
    max_bps: float
    avg_bps: float
    total_bytes: float


class BandwidthOut(BaseModel):
    tag: str
    start: int
    end: int
    timezone: str
    ports: list[BillingPort]
    inbound: BillingDirection
    outbound: BillingDirection
    billable_p95_bps: float = Field(description="the higher of inbound and outbound")
    samples: int
    expected_samples: int
    coverage_pct: float
    method: str
    series_in: list[list[float]]
    series_out: list[list[float]]


def percentile95(values: list[float]) -> float:
    """Nearest rank: sort, drop the top 5%, take the highest left."""
    if not values:
        return 0.0
    s = sorted(values)
    return s[max(math.ceil(0.95 * len(s)) - 1, 0)]


def _summarise(points: list[list[float]]) -> BillingDirection:
    vals = [p[1] for p in points]
    total = sum(v / 8 * BILLING_STEP for v in vals)
    return BillingDirection(
        p95_bps=percentile95(vals),
        max_bps=max(vals, default=0.0),
        avg_bps=total * 8 / (len(vals) * BILLING_STEP) if vals else 0.0,
        total_bytes=total,
    )


async def _org_timezone(t: TenantContext) -> str:
    from app.models import Tenant as TenantRow

    return (
        await t.db.scalar(select(TenantRow.digest_timezone).where(TenantRow.id == t.tenant_id))
    ) or "UTC"


@router.get("/bandwidth")
async def bandwidth(
    t: Tenant,
    tag: Annotated[str, Query(min_length=1, max_length=100)],
    month: Annotated[
        str | None,
        Query(pattern=r"^\d{4}-\d{2}$", description="YYYY-MM, in the organisation's timezone"),
    ] = None,
    start: int | None = None,
    end: int | None = None,
) -> BandwidthOut:
    """95th-percentile bandwidth for the ports tagged `tag`: 5-minute
    average rates, the ports summed per sample, the top 5% of samples
    dropped. Missing samples are skipped, not counted as zero; coverage
    says how complete the period is."""
    from zoneinfo import ZoneInfo

    tzname = await _org_timezone(t)
    try:
        tz = ZoneInfo(tzname)
    except Exception:
        tz, tzname = ZoneInfo("UTC"), "UTC"
    now = int(datetime.now(UTC).timestamp()) // BILLING_STEP * BILLING_STEP
    if month:
        y, m = (int(x) for x in month.split("-"))
        if not 1 <= m <= 12:
            raise HTTPException(422, "month must be YYYY-MM")
        first = datetime(y, m, 1, tzinfo=tz)
        nxt = datetime(y + (m == 12), m % 12 + 1, 1, tzinfo=tz)
        start, end = int(first.timestamp()), min(int(nxt.timestamp()), now)
    elif start is None or end is None:
        raise HTTPException(422, "Give month=YYYY-MM, or start and end (unix seconds)")
    if not 0 < end - start <= 93 * 86400:
        raise HTTPException(422, "The period is up to 93 days, and not in the future")
    rows = (
        await t.db.execute(
            select(NetworkInterface, Host.hostname)
            .join(Host, Host.id == NetworkInterface.host_id)
            .where(
                NetworkInterface.tenant_id == t.tenant_id,
                NetworkInterface.billing_tag == tag,
                Host.tenant_id == t.tenant_id,
            )
            .order_by(Host.hostname, NetworkInterface.name)
        )
    ).all()
    if not rows:
        raise HTTPException(404, "No ports carry that billing tag")
    if len(rows) > MAX_BILLING_PORTS:
        raise HTTPException(422, f"At most {MAX_BILLING_PORTS} ports per billing tag")
    ports = [
        BillingPort(
            device_id=i.host_id, device=name, ifname=i.name, alias=i.alias, speed_bps=i.speed_bps
        )
        for i, name in rows
    ]
    series: dict[str, list[list[float]]] = {}
    try:
        for direction in ("in", "out"):
            parts = [
                f'rate(sentinel_net_if_{direction}_octets_total{{host_id="{p.device_id}",ifname={promql_string(p.ifname)}}}[5m])'
                for p in ports
            ]
            q = f"sum({' or '.join(parts)}) * 8"
            res = await metrics.query_series(t.tenant_id, q, start, end, BILLING_STEP, [])
            series[direction] = [
                [float(ts), float(v)] for ts, v in (res[0]["points"] if res else [])
            ]
    except metrics.MetricsUnavailable:
        raise HTTPException(503, "Metrics are unavailable right now") from None
    inbound, outbound = _summarise(series["in"]), _summarise(series["out"])
    expected = max((end - start) // BILLING_STEP, 1)
    samples = max(len(series["in"]), len(series["out"]))
    return BandwidthOut(
        tag=tag,
        start=start,
        end=end,
        timezone=tzname,
        ports=ports,
        inbound=inbound,
        outbound=outbound,
        billable_p95_bps=max(inbound.p95_bps, outbound.p95_bps),
        samples=samples,
        expected_samples=expected,
        coverage_pct=round(min(100.0, 100 * samples / expected), 2),
        method="95th percentile (nearest rank) of 5-minute average rates, ports summed per sample, "
        "missing samples skipped; billable = the higher of inbound and outbound",
        series_in=series["in"],
        series_out=series["out"],
    )
