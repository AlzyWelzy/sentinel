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

from app.models import Host, NetworkInterface, NetworkLink, NetworkTrap, SNMPCredential
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
    # Proxmox VE API token (version 'proxmox').
    token_user: str | None = Field(default=None, max_length=255, description="e.g. monitoring@pve")
    token_name: str | None = Field(default=None, max_length=255)
    token_value: str | None = Field(default=None, max_length=255)
    insecure_tls: bool | None = Field(
        default=None, description="accept Proxmox's self-signed certificate"
    )

    @field_validator("auth_protocol", "priv_protocol")
    @classmethod
    def _lower(cls, v: str | None) -> str | None:
        return v.strip().lower() or None if v else None


class CredentialIn(_CredentialSecrets):
    name: Annotated[str, Trimmed, Field(min_length=1, max_length=100)]
    version: Literal["1", "2c", "3", "proxmox"] = "2c"


class CredentialPatch(_CredentialSecrets):
    name: Annotated[str, Trimmed, Field(min_length=1, max_length=100)] | None = None
    version: Literal["1", "2c", "3", "proxmox"] | None = None


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
    token_user: str | None = None
    token_name: str | None = None
    token_set: bool = False
    insecure_tls: bool = False
    devices: int
    created_at: datetime


def _check_secret(version: str, s: dict) -> dict:
    """Keep what the version uses and check it's complete."""
    if version == "proxmox":
        user, name, value = s.get("token_user"), s.get("token_name"), s.get("token_value")
        if not (user and name and value):
            raise HTTPException(
                422,
                "A Proxmox API token needs the user (e.g. monitoring@pve), token name and secret",
            )
        if "@" not in user or any(c in user + name for c in "!= \t\r\n"):
            raise HTTPException(
                422, "The token user looks like name@realm, and neither has '!', '=' or spaces"
            )
        return {
            "token_user": user,
            "token_name": name,
            "token_value": value,
            "insecure_tls": bool(s.get("insecure_tls")),
        }
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
        token_user=s.get("token_user"),
        token_name=s.get("token_name"),
        token_set=bool(s.get("token_value")),
        insecure_tls=bool(s.get("insecure_tls")),
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
    if body.insecure_tls is not None:  # False is a choice too
        merged["insecure_tls"] = body.insecure_tls
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
    trap_port: int | None  # UDP port it receives traps on; None: not listening


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
            trap_port=h.trap_port,
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
    poller_trap_port: int | None
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
        poller_trap_port=(
            await t.db.scalar(select(Host.trap_port).where(Host.id == h.poller_host_id))
            if h.poller_host_id
            else None
        ),
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


def server_parents(
    servers: set[uuid.UUID], devices: set[uuid.UUID], links: list[tuple[uuid.UUID, uuid.UUID]]
) -> dict[uuid.UUID, uuid.UUID]:
    """A server seen (by LLDP, from its NIC) on exactly one device depends on
    it. One cabled to two switches stays up when either fails, so it gets
    none."""
    seen: dict[uuid.UUID, set[uuid.UUID]] = {}
    for dev, remote in links:
        if dev in devices and remote in servers:
            seen.setdefault(remote, set()).add(dev)
    return {s: next(iter(ds)) for s, ds in seen.items() if len(ds) == 1}


async def apply_topology(db, tenant_id: uuid.UUID) -> int:
    """Sets automatic upstreams from LLDP for one organisation (a session
    scoped to it): devices toward a core device (when one is marked), and
    servers to the switch they're cabled to. Hand-set dependencies are left
    alone. Returns changes."""
    hosts = list(
        await db.scalars(select(Host).where(Host.tenant_id == tenant_id, Host.revoked_at.is_(None)))
    )
    devices = {h.id: h.network_role for h in hosts if h.kind == "network"}
    if not devices:
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
    has_core = any(r == "core" for r in devices.values())
    want: dict[uuid.UUID, uuid.UUID | None] = {}
    if has_core:
        parents = compute_parents(devices, links)
        want.update({d: parents.get(d) for d in devices})
    servers = {h.id for h in hosts if h.kind == "server"}
    want.update({s: None for s in servers})
    want.update(server_parents(servers, set(devices), links))
    by_id = {h.id: h for h in hosts}

    def upstream(h: Host) -> uuid.UUID | None:
        if h.depends_on_host_id and not h.depends_on_auto:
            return h.depends_on_host_id
        if h.id in want:
            return want[h.id] or h.poller_host_id
        return h.depends_on_host_id or h.poller_host_id

    def loops(start: uuid.UUID, target: uuid.UUID) -> bool:
        """Whether following upstreams from start reaches target."""
        cur: uuid.UUID | None = start
        visited: set[uuid.UUID] = set()
        while cur is not None and cur in by_id and cur not in visited:
            if cur == target:
                return True
            visited.add(cur)
            cur = upstream(by_id[cur])
        return False

    # A server never depends on a switch whose own upstream leads back to it
    # (its poller, typically): the two would hide each other's outage.
    # Dropping one can settle another's chain, so repeat until nothing moves.
    settled = False
    while not settled:
        settled = True
        for s in sorted(servers, key=str):
            if (sw := want.get(s)) and loops(sw, s):
                want[s] = None
                settled = False
    changed = 0
    for h in hosts:
        if h.id not in want or (h.depends_on_host_id and not h.depends_on_auto):
            continue
        if want[h.id] != h.depends_on_host_id:
            h.depends_on_host_id, h.depends_on_auto = want[h.id], want[h.id] is not None
            changed += 1
    await db.flush()
    return changed


async def topology_everywhere() -> int:
    """apply_topology for every organisation with network devices (jobs)."""
    from sqlalchemy import text

    from app.db import AppSession, ServiceSession

    async with ServiceSession() as sdb:
        tenants = list(
            await sdb.scalars(
                text(
                    "SELECT DISTINCT h.tenant_id FROM hosts h JOIN tenants t ON t.id = h.tenant_id "
                    "WHERE h.kind = 'network' AND t.status = 'active'"
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


# ── SNMP traps ───────────────────────────────────────────────────────────────


class TrapOut(BaseModel):
    id: int
    host_id: uuid.UUID | None
    hostname: str | None  # the device; None for a sender that isn't one
    source: str
    version: str
    name: str
    title: str
    action: str  # event, open, clear
    rule: str | None
    rule_name: str | None
    severity: str
    labels: dict[str, str]
    repeats: int
    received_at: datetime
    last_at: datetime


@router.get("/traps")
async def list_traps(
    t: Tenant,
    device_id: uuid.UUID | None = None,
    alerting: Annotated[bool, Query(description="only traps that open or close an alert")] = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[TrapOut]:
    """Recent traps (30 days), newest first: for one device, or all of them,
    including senders that aren't devices (recorded, never alerting)."""
    from app.services.netconditions import CONDITIONS

    q = (
        select(NetworkTrap, Host.hostname)
        .outerjoin(Host, Host.id == NetworkTrap.host_id)
        .where(NetworkTrap.tenant_id == t.tenant_id)
        .order_by(NetworkTrap.last_at.desc(), NetworkTrap.id.desc())
        .limit(limit)
    )
    if device_id is not None:
        q = q.where(NetworkTrap.host_id == device_id)
    if alerting:
        q = q.where(NetworkTrap.action != "event")
    rows = (await t.db.execute(q)).all()
    return [
        TrapOut(
            id=tr.id,
            host_id=tr.host_id,
            hostname=hostname,
            source=tr.source,
            version=tr.version,
            name=tr.name,
            title=tr.title,
            action=tr.action,
            rule=tr.rule,
            rule_name=CONDITIONS[tr.rule].name if tr.rule in CONDITIONS else None,
            severity=tr.severity,
            labels={str(k): str(v) for k, v in (tr.labels or {}).items()},
            repeats=tr.repeats,
            received_at=tr.received_at,
            last_at=tr.last_at,
        )
        for tr, hostname in rows
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


# ── Proxmox VE ───────────────────────────────────────────────────────────────


class PVEResource(BaseModel):
    type: Literal["node", "qemu", "lxc", "storage"]
    node: str
    name: str
    vmid: int | None = None
    up: bool
    cpu_pct: float | None = None
    cpus: float | None = None
    memory_used: float | None = None
    memory_size: float | None = None
    disk_used: float | None = None
    disk_size: float | None = None
    uptime_seconds: float | None = None
    shared: bool = False


class PVEOut(BaseModel):
    cluster: str | None
    quorate: bool | None
    resources: list[PVEResource]


@router.get("/devices/{device_id}/proxmox")
async def proxmox_resources(device_id: uuid.UUID, t: Tenant) -> PVEOut:
    """Nodes, guests and storage of a Proxmox VE cluster, as last polled."""
    h = await _get_device(t, device_id)
    sel = f'host_id="{h.id}"'
    names = (
        "up",
        "cpu_ratio",
        "cpus",
        "memory_used_bytes",
        "memory_size_bytes",
        "disk_used_bytes",
        "disk_size_bytes",
        "uptime_seconds",
    )
    found: dict[tuple, dict] = {}
    try:
        for n in names:
            for labels, v in await metrics.query_instant(
                t.tenant_id, f"last_over_time(sentinel_net_pve_{n}{{{sel}}}[5m])"
            ):
                key = (
                    labels.get("type"),
                    labels.get("node"),
                    labels.get("vmid"),
                    labels.get("storage"),
                )
                r = found.setdefault(key, {"labels": labels})
                r[n] = v
        quorum = await metrics.query_instant(
            t.tenant_id, f"last_over_time(sentinel_net_pve_cluster_quorate{{{sel}}}[5m])"
        )
    except metrics.MetricsUnavailable:
        raise HTTPException(503, "Metrics are unavailable right now") from None
    out = []
    for (typ, node, vmid, storage), r in found.items():
        if typ not in ("node", "qemu", "lxc", "storage") or "up" not in r:
            continue
        lab = r["labels"]
        out.append(
            PVEResource(
                type=typ,
                node=node or "",
                name=lab.get("name") or storage or node or "",
                vmid=int(vmid) if vmid and vmid.isdigit() else None,
                up=r["up"] == 1,
                cpu_pct=round(r["cpu_ratio"] * 100, 1) if "cpu_ratio" in r else None,
                cpus=r.get("cpus"),
                memory_used=r.get("memory_used_bytes"),
                memory_size=r.get("memory_size_bytes"),
                disk_used=r.get("disk_used_bytes"),
                disk_size=r.get("disk_size_bytes"),
                uptime_seconds=r.get("uptime_seconds"),
                shared=lab.get("shared") == "1",
            )
        )
    order = {"node": 0, "qemu": 1, "lxc": 2, "storage": 3}
    out.sort(key=lambda r: (order[r.type], r.node, r.vmid or 0, r.name))
    return PVEOut(
        cluster=quorum[0][0].get("cluster") if quorum else None,
        quorate=quorum[0][1] == 1 if quorum else None,
        resources=out,
    )


# ── Discovery ────────────────────────────────────────────────────────────────


def _address_key(address: str) -> tuple:
    """Sorts addresses numerically: 10.0.0.9 before 10.0.0.10."""
    host = address.rsplit(":", 1)[0] if address.count(":") == 1 else address.strip("[]")
    try:
        return (0, int(ipaddress.ip_address(host)))
    except ValueError:
        return (1, address)


def _status(value: str | None) -> Literal["pending", "running", "done"]:
    if value == "running":
        return "running"
    return "done" if value == "done" else "pending"


DISCOVERY_KEY = "pg:netdisc:"  # shared with ingest/discovery.go
DISCOVERY_POLLER_KEY = "pg:netdisc:poller:"
DISCOVERY_TTL = 86400
MAX_DISCOVERY_ADDRESSES = 1024
MAX_RUNNING_DISCOVERIES = 3
# The agent picks a scan up with its next config (within a minute) and
# reports every 5 seconds; past these, the scan has stopped (server offline,
# agent restarted for good) and shouldn't hold a slot for the rest of the day.
DISCOVERY_START_WITHIN = 600
DISCOVERY_SILENT_AFTER = 120


# RFC 1918 and carrier-grade NAT. Python's is_private also counts 0/8,
# 198.18/15, 240/4 and the documentation ranges, which hold no devices.
DISCOVERY_RANGES = tuple(
    ipaddress.IPv4Network(r)
    for r in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")
)


class DiscoveryIn(BaseModel):
    cidr: str = Field(
        description="an IPv4 range of your own network, e.g. 10.0.10.0/24 (up to /22)"
    )
    credential_id: uuid.UUID
    poller_host_id: uuid.UUID
    port: int = Field(default=161, ge=1, le=65535)

    @field_validator("cidr")
    @classmethod
    def _cidr(cls, v: str) -> str:
        try:
            net = ipaddress.ip_network(v.strip(), strict=False)
        except ValueError:
            raise ValueError("give a range like 10.0.10.0/24") from None
        if net.version != 4:
            raise ValueError("discovery scans IPv4 ranges")
        if net.num_addresses > MAX_DISCOVERY_ADDRESSES:
            raise ValueError("ranges are up to 1024 addresses (/22); scan larger ones in parts")
        # Only your own network: scanning other people's addresses from a
        # customer's server isn't something Sentinel does.
        if not (
            isinstance(net, ipaddress.IPv4Network)
            and any(net.subnet_of(r) for r in DISCOVERY_RANGES)
        ):
            raise ValueError(
                "discovery scans private ranges only (10/8, 172.16/12, 192.168/16, 100.64/10)"
            )
        return str(net)


class DiscoveredOut(BaseModel):
    address: str
    sys_name: str | None = None
    sys_descr: str | None = None
    vendor: str | None = None
    profile: str | None = None
    already_added: bool = False


class DiscoveryOut(BaseModel):
    id: str
    cidr: str
    status: Literal["pending", "running", "done"]
    scanned: int
    total: int
    error: str | None
    credential_id: uuid.UUID
    poller_host_id: uuid.UUID
    found: list[DiscoveredOut]


async def _discovery(discovery_id: str, t: TenantContext) -> dict[str, str]:
    """The scan's stored hash, settled first: one that never started or
    stopped reporting is marked done with the reason."""
    if not re.fullmatch(r"[0-9a-f]{32}", discovery_id):
        raise HTTPException(404, "Discovery not found")
    key = DISCOVERY_KEY + discovery_id
    raw = await heartbeats.redis.hgetall(key)
    h = {str(k): str(v) for k, v in raw.items()}
    if not h or h.get("tenant") != str(t.tenant_id) or "poller" not in h:
        raise HTTPException(404, "Discovery not found (results are kept for a day)")
    now = int(datetime.now(UTC).timestamp())
    reason = None
    if h.get("status") == "pending" and now - int(h.get("created") or now) > DISCOVERY_START_WITHIN:
        reason = "The server didn't start the scan within 10 minutes. Is it reporting?"
    elif (
        h.get("status") == "running"
        and now - int(h.get("updated") or h.get("created") or now) > DISCOVERY_SILENT_AFTER
    ):
        reason = (
            "The server stopped reporting progress (offline or restarted);"
            " results so far are below."
        )
    if reason:
        await _end_discovery(discovery_id, h, reason)
    return h


async def _end_discovery(discovery_id: str, h: dict[str, str], reason: str) -> None:
    """Done, so ingest stops handing it out and ignores later results."""
    h.update(status="done", error=reason)
    await heartbeats.redis.hset(
        DISCOVERY_KEY + discovery_id, mapping={"status": "done", "error": reason}
    )
    await heartbeats.redis.srem(DISCOVERY_POLLER_KEY + h["poller"], discovery_id)


async def _discovery_ids(t: TenantContext) -> list[str]:
    ids = []
    async for key in heartbeats.redis.scan_iter(match=f"{DISCOVERY_KEY}*", count=500):
        key = str(key)
        if key.startswith(DISCOVERY_POLLER_KEY):
            continue
        if await heartbeats.redis.hget(key, "tenant") == str(t.tenant_id):
            ids.append(key.removeprefix(DISCOVERY_KEY))
    return ids


class DiscoverySummary(BaseModel):
    id: str
    cidr: str
    status: Literal["pending", "running", "done"]
    scanned: int
    total: int
    found: int
    error: str | None
    created: int


@router.get("/discoveries")
async def list_discoveries(t: Tenant) -> list[DiscoverySummary]:
    """This organisation's scans of the last day, newest first."""
    import json

    out = []
    for did in await _discovery_ids(t):
        try:
            h = await _discovery(did, t)
        except HTTPException:
            continue  # expired meanwhile
        try:
            found = len(json.loads(h.get("found") or "[]"))
        except ValueError:
            found = 0
        out.append(
            DiscoverySummary(
                id=did,
                cidr=h.get("cidr", ""),
                status=_status(h.get("status")),
                scanned=int(h.get("scanned") or 0),
                total=int(h.get("total") or 0),
                found=found,
                error=h.get("error") or None,
                created=int(h.get("created") or 0),
            )
        )
    out.sort(key=lambda d: d.created, reverse=True)
    return out


@router.delete("/discoveries/{discovery_id}", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_discovery(discovery_id: str, t: Tenant) -> None:
    """Stop waiting for a scan; what it found so far stays. A scan already
    running on the server finishes there, but its results are ignored."""
    h = await _discovery(discovery_id, t)
    if h.get("status") != "done":
        await _end_discovery(discovery_id, h, "Cancelled.")


@router.post("/discoveries", status_code=status.HTTP_201_CREATED)
async def start_discovery(body: DiscoveryIn, t: Tenant) -> DiscoveryOut:
    """Scan a range from one of your servers for devices answering SNMP with
    this credential. The server starts within a minute; results stay a day."""
    cred = await _get_credential(t, body.credential_id)
    if cred.version == "proxmox":
        raise HTTPException(422, "Discovery uses an SNMP credential")
    await _check_poller(t, body.poller_host_id)
    redis = heartbeats.redis
    running = 0
    for did in await _discovery_ids(t):
        try:
            h = await _discovery(did, t)
        except HTTPException:
            continue
        running += h.get("status") != "done"
    if running >= MAX_RUNNING_DISCOVERIES:
        raise HTTPException(429, "Three scans are running already; wait for one to finish")
    did = uuid.uuid4().hex
    key = DISCOVERY_KEY + did
    await redis.hset(
        key,
        mapping={
            "tenant": str(t.tenant_id),
            "poller": str(body.poller_host_id),
            "cidr": body.cidr,
            "port": body.port,
            "credential": str(body.credential_id),
            "status": "pending",
            "scanned": 0,
            "total": 0,
            "found": "[]",
            "created": int(datetime.now(UTC).timestamp()),
        },
    )
    await redis.expire(key, DISCOVERY_TTL)
    pk = DISCOVERY_POLLER_KEY + str(body.poller_host_id)
    await redis.sadd(pk, did)
    await redis.expire(pk, DISCOVERY_TTL)
    return await get_discovery(did, t)


@router.get("/discoveries/{discovery_id}")
async def get_discovery(discovery_id: str, t: Tenant) -> DiscoveryOut:
    import json

    h = await _discovery(discovery_id, t)
    try:
        found = json.loads(h.get("found") or "[]")
    except ValueError:
        found = []
    have = set(
        await t.db.scalars(
            select(Host.address).where(
                Host.tenant_id == t.tenant_id,
                Host.kind == "network",
                Host.poller_host_id == uuid.UUID(h["poller"]),
            )
        )
    )
    out = []
    for f in found:
        try:
            addr = normalize_address(f.get("address", ""))
        except ValueError:
            continue
        out.append(
            DiscoveredOut(
                address=addr,
                sys_name=f.get("sys_name"),
                sys_descr=f.get("sys_descr"),
                vendor=f.get("vendor"),
                profile=f.get("profile"),
                already_added=addr in have,
            )
        )
    out.sort(key=lambda d: _address_key(d.address))
    return DiscoveryOut(
        id=discovery_id,
        cidr=h.get("cidr", ""),
        status=_status(h.get("status")),
        scanned=int(h.get("scanned") or 0),
        total=int(h.get("total") or 0),
        error=h.get("error") or None,
        credential_id=uuid.UUID(h["credential"]),
        poller_host_id=uuid.UUID(h["poller"]),
        found=out,
    )
