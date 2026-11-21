"""Resource and uptime checks.

A check runs on one server, on every server with a tag (ports, URLs,
certificates, DNS, files, log patterns: "from inside"), or on the public
probes in several regions (uptime: "from outside"). Agents receive their
checks with their config, so nothing has to be installed per check.

Creating a check also creates its alert rule unless alert=false, so the
common case ("tell me when my site is down") is one request.
"""

import ipaddress
import json
import re
import secrets
import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import delete, func, select, update

from app.config import settings
from app.db import ServiceSession
from app.models import AlertRule, AlertState, Check, Host, Incident
from app.routes.ranges import RANGES, Range
from app.services import checkresults
from app.services.heartbeats import is_online, last_seen
from app.services.metrics import MetricsUnavailable, query_instant, query_series
from app.tenancy import Tenant, TenantContext
from app.validation import Trimmed, normalize_tag

router = APIRouter(prefix="/v1")

MAX_CHECKS = 200
MIN_PROBE_INTERVAL = 30
CheckType = Literal[
    "tcp",
    "http",
    "tls",
    "dns",
    "file",
    "log",
    "ping",
    "websocket",
    "smtp",
    "ntp",
    "redis",
    "postgres",
    "mysql",
    "mongodb",
    "kafka",
    "mqtt",
    "grpc",
    "sip",
    "radius",
    "game",
    "snmp",
    "docker",
    "service",
    "push",
    "group",
]
# What can run on the public probes: anything over the network. Files, logs,
# containers and services are only on the server itself.
LOCAL_TYPES = {"file", "log", "docker", "service", "push", "group"}
PROBE_TYPES = set(CheckType.__args__) - LOCAL_TYPES
# Answered as this placeholder, never in the clear; sending it back on an
# update keeps the stored value.
MASK = "••••••••"
SECRET_PARAMS = {
    "password", "secret", "bearer_token", "basic_password", "client_key", "oauth_client_secret",
}  # fmt: skip
PROXY_SCHEMES = ("http", "https", "socks5", "socks5h")
URL_TARGET_TYPES = {"redis", "postgres", "mysql", "mongodb"}
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)

COMPARISONS = {"==", "!=", "<", "<=", ">", ">=", "contains", "not_contains"}
SERVICE_RE = re.compile(r"^[A-Za-z0-9@._:\\-]{1,128}$")
OID_RE = re.compile(r"^\.?\d+(\.\d+)+$")


def _url_target(target: str, schemes: tuple[str, ...]) -> str:
    u = urlparse(target)
    if u.scheme not in schemes or not u.hostname:
        raise ValueError(f"target must be a {' or '.join(s + '://' for s in schemes)} URL")
    _hostname(u.hostname)
    return u.hostname


def _target_host(t: str, target: str) -> str | None:
    """The host a network check connects to, for the probe address rule."""
    if t in URL_TARGET_TYPES:
        return _url_target(
            target,
            {
                "redis": ("redis", "rediss"),
                "postgres": ("postgres", "postgresql"),
                "mysql": ("mysql",),
                "mongodb": ("mongodb",),
            }[t],
        )
    if t == "websocket":
        return _url_target(target, ("ws", "wss"))
    if t == "mqtt":
        target = target.removeprefix("mqtt://").removeprefix("mqtts://")
    host, sep, port = target.rpartition(":")
    if sep and port.isdigit() and not host.endswith(":"):
        if not 1 <= int(port) <= 65535:
            raise ValueError("the port must be 1-65535")
        return _hostname(host.strip("[]"))
    return _hostname(target.strip("[]"))


def push_url(token: str) -> str:
    return f"{settings.PUBLIC_INGEST_URL.rstrip('/')}/push/{token}"


def mask(c_type: str, target: str, params: dict[str, str]) -> tuple[str, dict[str, str]]:
    """A check as answered: passwords and tokens replaced with MASK."""
    out = {k: (MASK if k in SECRET_PARAMS and v else v) for k, v in params.items()}
    if c_type in URL_TARGET_TYPES:
        u = urlparse(target)
        if u.password:
            target = u._replace(
                netloc=u.netloc.replace(":" + u.password + "@", ":" + MASK + "@", 1)
            ).geturl()
    if out.get("proxy") and (pw := urlparse(out["proxy"]).password):
        out["proxy"] = out["proxy"].replace(":" + pw + "@", ":" + MASK + "@", 1)
    if c_type == "http" and "headers" in out:
        out["headers"] = (
            MASK
            if any(
                k.lower() in ("authorization", "cookie", "x-api-key")
                for k in _headers(out["headers"])
            )
            else out["headers"]
        )
    return target, out


def _headers(raw: str) -> dict[str, str]:
    try:
        v = json.loads(raw)
    except ValueError:
        return {}
    return v if isinstance(v, dict) else {}


def unmask(
    c_type: str, target: str, params: dict[str, str], old: "Check"
) -> tuple[str, dict[str, str]]:
    """An update that sends MASK back keeps the stored secret."""
    old_params = old.params or {}
    params = {k: (old_params.get(k, "") if v == MASK else v) for k, v in params.items()}
    if MASK in params.get("proxy", ""):
        old_pw = urlparse(old_params.get("proxy", "")).password or ""
        params["proxy"] = params["proxy"].replace(MASK, old_pw, 1)
    if MASK in target and old.type == c_type:
        old_pw = urlparse(old.target).password or ""
        target = target.replace(MASK, old_pw, 1)
    return target, params


# Parameters each check type understands; anything else is rejected, so a
# typo doesn't silently do nothing.
PARAMS: dict[str, set[str]] = {
    "tcp": {"timeout_seconds"},
    "ping": {"timeout_seconds"},
    "http": {
        "method",
        "expect_status",
        "keyword",
        "keyword_absent",
        "timeout_seconds",
        "tls_skip_verify",
        "follow_redirects",
        "tls_expiry_days",
        "body",
        "body_encoding",
        "headers",
        "basic_user",
        "basic_password",
        "bearer_token",
        "json_path",
        "json_op",
        "json_expect",
        "keyword_case_insensitive",
        "max_redirects",
        "cache_bust",
        "proxy",
        "client_cert",
        "client_key",
        "oauth_token_url",
        "oauth_client_id",
        "oauth_client_secret",
        "oauth_scopes",
        "oauth_auth_method",
    },
    "tls": {"tls_expiry_days", "timeout_seconds"},
    "websocket": {"subprotocol", "tls_skip_verify", "timeout_seconds"},
    "smtp": {"security", "tls_skip_verify", "timeout_seconds"},
    "ntp": {"max_offset_ms", "max_stratum", "timeout_seconds"},
    "redis": {"tls_skip_verify", "timeout_seconds"},
    "postgres": {"query", "expect", "timeout_seconds"},
    "mysql": {"query", "expect", "tls_skip_verify", "timeout_seconds"},
    "mongodb": {"tls", "tls_skip_verify", "timeout_seconds"},
    "kafka": {"tls", "tls_skip_verify", "timeout_seconds"},
    "mqtt": {
        "topic",
        "expect",
        "username",
        "password",
        "tls",
        "tls_skip_verify",
        "timeout_seconds",
    },
    "grpc": {"service", "metadata", "tls", "tls_skip_verify", "timeout_seconds"},
    "sip": {"timeout_seconds"},
    "radius": {
        "secret",
        "username",
        "password",
        "called_station_id",
        "calling_station_id",
        "timeout_seconds",
    },
    "game": {"protocol", "timeout_seconds"},
    "snmp": {"oid", "community", "version", "op", "expect", "timeout_seconds"},
    "docker": {"socket"},
    "service": set(),
    "push": {"grace_seconds"},
    "group": set(),
    "dns": {"record_type", "expect", "server", "timeout_seconds"},
    "file": {"mode", "value"},
    "log": {"pattern", "threshold"},
}


def _host_port(target: str) -> tuple[str, int]:
    host, sep, port = target.rpartition(":")
    if not sep or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError("target must be host:port, e.g. db.example.com:5432")
    host = host.strip("[]")
    _hostname(host)
    return host, int(port)


def _hostname(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if not HOSTNAME_RE.match(host):
        raise ValueError(f"{host!r} isn't a valid host name or IP address")
    return host


def _is_private(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host in ("localhost",) or host.endswith((".local", ".internal", ".localhost"))
    return not ip.is_global


class CheckIn(BaseModel):
    name: Annotated[str, Trimmed, Field(min_length=1, max_length=100)]
    type: CheckType
    target: Annotated[str, Trimmed, Field(max_length=2048)] = ""
    params: dict[str, str] = Field(default_factory=dict)
    interval_seconds: int = Field(
        default=60, ge=10, le=604800, description="up to 3600; push checks up to a week"
    )
    host_id: uuid.UUID | None = None
    tag: str | None = None
    on_probes: bool = False
    parent_id: uuid.UUID | None = Field(default=None, description="the group this check is in")
    probe_regions: list[str] = Field(default_factory=list, max_length=20)
    min_failing: int = Field(default=1, ge=1, le=10)
    enabled: bool = True
    slo_target: float = Field(default=99.9, gt=0, lt=100, description="promised availability, %")
    alert: bool = Field(default=True, description="also create an alert rule (on create)")
    severity: Literal["critical", "warning", "info"] = "critical"

    @field_validator("tag")
    @classmethod
    def _tag(cls, v: str | None) -> str | None:
        return None if v is None or v.strip() == "" else normalize_tag(v)

    @field_validator("params", mode="before")
    @classmethod
    def _params(cls, v: object) -> object:
        # Accept JSON numbers and booleans; agents read every param as text.
        if isinstance(v, dict):
            if len(v) > 40:
                raise ValueError("too many params")
            for k, val in v.items():
                if len(str(k)) > 64 or len(str(val)) > 16384:
                    raise ValueError(f"param {str(k)[:64]} is too long (16384 characters at most)")
            return {
                str(k): str(val).lower() if isinstance(val, bool) else str(val)
                for k, val in v.items()
                if val is not None
            }
        return v

    @model_validator(mode="after")
    def _validate(self) -> "CheckIn":
        if self.type == "group":
            # Nothing runs it: its members are its state.
            if self.host_id or self.tag or self.on_probes:
                raise ValueError("a group runs nowhere: leave host_id, tag and on_probes out")
            self.target, self.interval_seconds = "group", 60
        elif self.type == "push":
            # Nothing runs it: something calls in.
            if self.host_id or self.tag or self.on_probes:
                raise ValueError("a push check runs nowhere: leave host_id, tag and on_probes out")
            self.target = "push"
            if self.interval_seconds < 60:
                raise ValueError("a push check expects a push at least a minute apart")
        elif self.interval_seconds > 3600:
            raise ValueError("interval_seconds is at most 3600 (push checks: a week)")
        elif not self.target.strip():
            raise ValueError("a target is required")
        elif sum([self.host_id is not None, self.tag is not None, self.on_probes]) != 1:
            raise ValueError("a check runs on one server (host_id), a tag, or the probes")
        if self.on_probes:
            if self.type not in PROBE_TYPES:
                raise ValueError(f"{self.type} checks run on a server, not the probes")
            self.interval_seconds = max(self.interval_seconds, MIN_PROBE_INTERVAL)
        else:
            self.probe_regions, self.min_failing = [], 1
        unknown = set(self.params) - PARAMS[self.type] - {"invert"}
        if unknown:
            raise ValueError(f"unknown params for {self.type}: {', '.join(sorted(unknown))}")
        self.params = {
            k: str(v).lower() if isinstance(v, bool) else str(v) for k, v in self.params.items()
        }
        self.target = self.target.strip()
        t = self.type
        if t in ("tcp", "tls"):
            host, _ = _host_port(self.target)
            if self.on_probes and _is_private(host):
                raise ValueError("public probes can only check public addresses")
        elif t == "ping":
            _hostname(self.target)
            if self.on_probes and _is_private(self.target):
                raise ValueError("public probes can only check public addresses")
        elif t == "dns":
            _hostname(self.target)
            rt = self.params.get("record_type", "A").upper()
            if rt not in {"A", "AAAA", "CNAME", "MX", "NS", "TXT"}:
                raise ValueError("record_type must be A, AAAA, CNAME, MX, NS or TXT")
            self.params["record_type"] = rt
        elif t == "http":
            u = urlparse(self.target)
            if u.scheme not in ("http", "https") or not u.hostname:
                raise ValueError("target must be an http:// or https:// URL")
            if self.on_probes and _is_private(u.hostname):
                raise ValueError("public probes can only check public addresses")
            method = self.params.get("method", "GET").upper()
            if method not in ("GET", "HEAD", "POST"):
                raise ValueError("method must be GET, HEAD or POST")
            if "expect_status" in self.params and not re.match(
                r"^\d{3}(-\d{3})?$", self.params["expect_status"]
            ):
                raise ValueError("expect_status is a code (200) or a range (200-399)")
        elif t in ("file", "log"):
            if not (self.target.startswith("/") or re.match(r"^[A-Za-z]:\\", self.target)):
                raise ValueError("target must be an absolute path")
            if t == "file":
                mode = self.params.get("mode", "exists")
                if mode not in {"exists", "absent", "changed", "max_age_seconds", "max_size_bytes"}:
                    raise ValueError(
                        "mode is exists, absent, changed, max_age_seconds or max_size_bytes"
                    )
                if (
                    mode in ("max_age_seconds", "max_size_bytes")
                    and not self.params.get("value", "").isdigit()
                ):
                    raise ValueError(f"mode {mode} needs a numeric value")
            else:
                pattern = self.params.get("pattern", "")
                if not pattern:
                    raise ValueError("log checks need a pattern (a regular expression)")
                try:
                    re.compile(pattern)
                except re.error as exc:
                    raise ValueError(f"invalid pattern: {exc}") from None
                if "(?" in pattern and "(?i)" not in pattern:
                    raise ValueError(
                        "lookarounds and other (? constructs aren't supported, except (?i)"
                    )
        elif t in ("push", "group"):
            pass
        elif t in ("docker", "service"):
            if not SERVICE_RE.match(self.target) or self.target.startswith("-"):
                raise ValueError(
                    f"target must be a {'container' if t == 'docker' else 'service'} name"
                )
        elif t != "http":
            host = _target_host(t, self.target)
            if self.on_probes and host and _is_private(host):
                raise ValueError("public probes can only check public addresses")
        p = self.params
        if t == "http":
            if "headers" in p and p["headers"] != MASK:
                try:
                    h = json.loads(p["headers"])
                except ValueError:
                    raise ValueError("headers must be a JSON object") from None
                if not isinstance(h, dict) or not all(
                    isinstance(k, str) and isinstance(v, str) for k, v in h.items()
                ):
                    raise ValueError("headers must be a JSON object of strings")
            if p.get("body_encoding", "json") not in ("json", "form", "xml"):
                raise ValueError("body_encoding is json, form or xml")
            auths = [k for k in ("basic_user", "bearer_token", "oauth_token_url") if p.get(k)]
            if len(auths) > 1:
                raise ValueError(f"use one way to sign in, not {' and '.join(auths)}")
            if proxy := p.get("proxy"):
                if MASK not in proxy:
                    host = _url_target(proxy, PROXY_SCHEMES)
                    if self.on_probes and _is_private(host):
                        raise ValueError("public probes can only use a proxy at a public address")
            if bool(p.get("client_cert")) != bool(p.get("client_key")):
                raise ValueError("a client certificate needs both client_cert and client_key")
            if (cert := p.get("client_cert")) and "BEGIN CERTIFICATE" not in cert:
                raise ValueError("client_cert is a PEM certificate (-----BEGIN CERTIFICATE-----)")
            if (key := p.get("client_key")) and key != MASK and "PRIVATE KEY" not in key:
                raise ValueError("client_key is a PEM private key")
            if p.get("oauth_token_url"):
                host = _url_target(p["oauth_token_url"], ("https", "http"))
                if self.on_probes and _is_private(host):
                    raise ValueError("public probes can only reach a public token URL")
                if p.get("oauth_auth_method", "basic") not in ("basic", "post"):
                    raise ValueError("oauth_auth_method is basic or post")
                if not (p.get("oauth_client_id") and p.get("oauth_client_secret")):
                    raise ValueError("OAuth needs oauth_client_id and oauth_client_secret")
        if "json_op" in p and p["json_op"] not in COMPARISONS:
            raise ValueError(f"json_op is one of {', '.join(sorted(COMPARISONS))}")
        if "op" in p and p["op"] not in COMPARISONS:
            raise ValueError(f"op is one of {', '.join(sorted(COMPARISONS))}")
        if t == "smtp" and p.get("security", "none") not in ("none", "starttls", "tls"):
            raise ValueError("security is none, starttls or tls")
        if t == "game" and p.get("protocol", "a2s") not in ("a2s", "minecraft"):
            raise ValueError("protocol is a2s (Source/Steam games) or minecraft")
        if t == "snmp":
            if not OID_RE.match(p.get("oid", "")):
                raise ValueError("an SNMP check needs an oid, e.g. 1.3.6.1.2.1.1.3.0")
            if p.get("version", "2c") not in ("1", "2c"):
                raise ValueError("version is 1 or 2c (v3 devices are polled as network devices)")
        if t == "radius" and not (p.get("secret") and p.get("username")):
            raise ValueError("a RADIUS check needs secret and username")
        if t == "grpc" and "metadata" in p:
            try:
                md = json.loads(p["metadata"])
            except ValueError:
                md = None
            if not isinstance(md, dict):
                raise ValueError("metadata must be a JSON object")
        if p.get("invert") not in (None, "true", "false"):
            raise ValueError("invert is true or false")
        for key in ("max_offset_ms", "max_stratum", "max_redirects", "grace_seconds"):
            if key in p and not p[key].isdigit():
                raise ValueError(f"{key} must be a whole number")
        for key in ("timeout_seconds", "tls_expiry_days", "threshold"):
            if key in self.params and not self.params[key].isdigit():
                raise ValueError(f"{key} must be a whole number")
        return self


CheckStatus = Literal["up", "down", "pending", "paused"]


def _event_like(body: CheckIn) -> bool:
    """Log matches and file changes are events: alert on the first one."""
    return body.type == "log" or (body.type == "file" and body.params.get("mode") == "changed")


class CheckResultOut(BaseModel):
    ok: bool
    detail: str | None = None
    latency_ms: float | None = None
    ts: int
    host_id: str | None = None
    region: str | None = None
    # A failing network check: DNS, a connect to each address, the path.
    diagnosis: dict | None = None


class CheckOut(BaseModel):
    id: uuid.UUID
    name: str
    type: str
    target: str
    params: dict[str, str]
    interval_seconds: int
    host_id: uuid.UUID | None
    tag: str | None
    on_probes: bool
    probe_regions: list[str]
    min_failing: int
    enabled: bool
    slo_target: float
    parent_id: uuid.UUID | None = None
    members: list[uuid.UUID] = Field(default_factory=list, description="groups: direct members")
    created_at: datetime
    updated_at: datetime
    status: CheckStatus
    results: list[CheckResultOut]
    last_failure: CheckResultOut | None
    rule_id: uuid.UUID | None
    open_incident_id: uuid.UUID | None
    push_url: str | None = Field(
        default=None, description="push checks: call this (GET or POST) ?status=up|down&msg=&ping="
    )


def _status(c: Check, results: list[dict]) -> CheckStatus:
    if not c.enabled:
        return "paused"
    if not results:
        return "pending"
    if c.type == "push":
        # Silence is down too: the alerter counts it the same way.
        grace = c.params.get("grace_seconds", "0") if c.params else "0"
        limit = (c.interval_seconds + (int(grace) if str(grace).isdigit() else 0)) * 1000
        last = results[0]
        stale = datetime.now(UTC).timestamp() * 1000 - last.get("ts", 0) > limit
        return "down" if stale or not last.get("ok") else "up"
    failing = sum(1 for r in results if not r.get("ok"))
    need = min(c.min_failing, len(results)) if c.on_probes else 1
    return "down" if failing >= max(need, 1) else "up"


def _rollup(statuses: list[str]) -> CheckStatus:
    live = [s for s in statuses if s != "paused"]
    if not live:
        return "pending"
    if "down" in live:
        return "down"
    return "up" if "up" in live else "pending"


async def _groups(
    t: TenantContext, checks: list[Check]
) -> tuple[dict[uuid.UUID, list[uuid.UUID]], dict[uuid.UUID, CheckStatus]]:
    """Each group's direct members, and its state: down while any member
    (through nested groups) is down; paused members don't count."""
    if not any(c.type == "group" for c in checks):
        return {}, {}
    every = list(await t.db.scalars(select(Check).where(Check.tenant_id == t.tenant_id)))
    by_id = {c.id: c for c in every}
    latest = await checkresults.latest([c.id for c in every if c.type != "group"])
    tree: dict[uuid.UUID, list[uuid.UUID]] = {}
    for c in every:
        if c.parent_id is not None and c.parent_id in by_id:
            tree.setdefault(c.parent_id, []).append(c.id)

    def state(cid: uuid.UUID, seen: frozenset[uuid.UUID]) -> CheckStatus:
        c = by_id[cid]
        if not c.enabled:
            return "paused"
        if c.type != "group":
            return _status(c, latest.get(cid, []))
        return _rollup([state(m, seen | {m}) for m in tree.get(cid, []) if m not in seen])

    return tree, {c.id: state(c.id, frozenset({c.id})) for c in checks if c.type == "group"}


async def _check_parent(
    t: TenantContext, parent_id: uuid.UUID | None, self_id: uuid.UUID | None
) -> None:
    """The parent is one of this account's groups, and not inside this check."""
    seen: set[uuid.UUID] = set()
    cur = parent_id
    while cur is not None:
        if cur == self_id or cur in seen:
            raise HTTPException(status_code=422, detail="a group can't be inside itself")
        seen.add(cur)
        if len(seen) > 5:
            raise HTTPException(status_code=422, detail="groups nest at most 5 deep")
        row = (
            await t.db.execute(
                select(Check.type, Check.parent_id).where(
                    Check.id == cur, Check.tenant_id == t.tenant_id
                )
            )
        ).one_or_none()
        if row is None:
            raise HTTPException(status_code=422, detail="parent_id not found")
        if row.type != "group" and cur == parent_id:
            raise HTTPException(status_code=422, detail="parent_id must be a group")
        cur = row.parent_id


async def _out(t: TenantContext, checks: list[Check]) -> list[CheckOut]:
    latest = await checkresults.latest([c.id for c in checks])
    failures = await checkresults.last_failures([c.id for c in checks])
    ids = [str(c.id) for c in checks]
    rules: dict[str, uuid.UUID] = {}
    if ids:
        rule_rows = await t.db.execute(
            select(AlertRule.id, AlertRule.target).where(
                AlertRule.tenant_id == t.tenant_id,
                AlertRule.kind == "check",
                AlertRule.target.in_(ids),
            )
        )
        for row in rule_rows:
            if row.target is not None:
                rules.setdefault(row.target, row.id)
    open_incidents: dict[uuid.UUID, uuid.UUID] = {}
    if checks:
        incident_rows = await t.db.execute(
            select(Incident.id, Incident.check_id).where(
                Incident.tenant_id == t.tenant_id,
                Incident.status == "open",
                Incident.check_id.in_([c.id for c in checks]),
            )
        )
        for row in incident_rows:
            if row.check_id is not None:
                open_incidents.setdefault(row.check_id, row.id)
    tree, group_status = await _groups(t, checks)
    out = []
    for c in checks:
        results = latest.get(c.id, [])
        target, params = mask(c.type, c.target, {k: str(v) for k, v in (c.params or {}).items()})
        out.append(
            CheckOut(
                id=c.id,
                name=c.name,
                type=c.type,
                target=target,
                params=params,
                interval_seconds=c.interval_seconds,
                host_id=c.host_id,
                tag=c.tag,
                on_probes=c.on_probes,
                probe_regions=list(c.probe_regions or []),
                min_failing=c.min_failing,
                enabled=c.enabled,
                slo_target=float(c.slo_target),
                parent_id=c.parent_id,
                members=tree.get(c.id, []),
                created_at=c.created_at,
                updated_at=c.updated_at,
                status=group_status[c.id] if c.type == "group" else _status(c, results),
                results=[CheckResultOut(**r) for r in results],
                last_failure=CheckResultOut(**failures[c.id]) if c.id in failures else None,
                rule_id=rules.get(str(c.id)),
                open_incident_id=open_incidents.get(c.id),
                push_url=push_url(c.push_token) if c.type == "push" and c.push_token else None,
            )
        )
    return out


async def _get(t: TenantContext, check_id: uuid.UUID) -> Check:
    c = await t.db.scalar(select(Check).where(Check.id == check_id, Check.tenant_id == t.tenant_id))
    if c is None:
        raise HTTPException(status_code=404, detail="Check not found")
    return c


async def _check_host(t: TenantContext, host_id: uuid.UUID | None) -> None:
    if host_id is None:
        return
    found = await t.db.scalar(
        select(Host.id).where(Host.id == host_id, Host.tenant_id == t.tenant_id)
    )
    if found is None:
        raise HTTPException(status_code=422, detail="host_id not found")


@router.get("/checks")
async def list_checks(
    t: Tenant,
    host_id: uuid.UUID | None = None,
    on_probes: bool | None = None,
) -> list[CheckOut]:
    q = select(Check).where(Check.tenant_id == t.tenant_id)
    if host_id is not None:
        tags = await t.db.scalar(
            select(Host.tags).where(Host.id == host_id, Host.tenant_id == t.tenant_id)
        )
        q = q.where((Check.host_id == host_id) | (Check.tag.in_(tags or [])))
    if on_probes is not None:
        q = q.where(Check.on_probes == on_probes)
    return await _out(t, list(await t.db.scalars(q.order_by(Check.created_at))))


@router.post("/checks", status_code=status.HTTP_201_CREATED)
async def create_check(body: CheckIn, t: Tenant) -> CheckOut:
    await _check_host(t, body.host_id)
    await _check_parent(t, body.parent_id, None)
    count = await t.db.scalar(
        select(func.count()).select_from(Check).where(Check.tenant_id == t.tenant_id)
    )
    if (count or 0) >= MAX_CHECKS:
        raise HTTPException(status_code=422, detail=f"at most {MAX_CHECKS} checks per account")
    if MASK in body.target or MASK in body.params.values():
        raise HTTPException(status_code=422, detail="enter the password or token itself")
    check = Check(tenant_id=t.tenant_id, **body.model_dump(exclude={"alert", "severity"}))
    if body.type == "push":
        check.push_token = secrets.token_urlsafe(24)
    t.db.add(check)
    await t.db.flush()
    if body.alert:
        t.db.add(
            AlertRule(
                tenant_id=t.tenant_id,
                name=body.name,
                kind="check",
                target=str(check.id),
                # A one-off failure (a dropped packet) shouldn't page: wait
                # for it to persist across two runs.
                # A push check's grace is its wait; a down push is news.
                duration_seconds=0
                if _event_like(body) or body.type in ("push", "group")
                else min(body.interval_seconds * 2, 600),
                severity=body.severity,
            )
        )
        await t.db.flush()
    await t.db.refresh(check)
    return (await _out(t, [check]))[0]


@router.get("/checks/{check_id}")
async def get_check(check_id: uuid.UUID, t: Tenant) -> CheckOut:
    return (await _out(t, [await _get(t, check_id)]))[0]


@router.put("/checks/{check_id}")
async def update_check(check_id: uuid.UUID, body: CheckIn, t: Tenant) -> CheckOut:
    check = await _get(t, check_id)
    await _check_host(t, body.host_id)
    await _check_parent(t, body.parent_id, check.id)
    if check.type == "group" and body.type != "group":
        members = await t.db.scalar(
            select(func.count())
            .select_from(Check)
            .where(Check.parent_id == check.id, Check.tenant_id == t.tenant_id)
        )
        if members:
            raise HTTPException(status_code=422, detail="move this group's members out first")
    body.target, body.params = unmask(body.type, body.target, body.params, check)
    if body.type == "push" and not check.push_token:
        check.push_token = secrets.token_urlsafe(24)
    elif body.type != "push":
        check.push_token = None
    for field, value in body.model_dump(exclude={"alert", "severity"}).items():
        setattr(check, field, value)
    check.updated_at = datetime.now(UTC)
    # Where or what it checks changed: the old results and alert progress no
    # longer describe it.
    await checkresults.forget(check.id)
    await t.db.execute(
        delete(AlertState).where(
            AlertState.check_id == check.id, AlertState.tenant_id == t.tenant_id
        )
    )
    await t.db.flush()
    return (await _out(t, [check]))[0]


@router.delete("/checks/{check_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_check(check_id: uuid.UUID, t: Tenant) -> None:
    check = await _get(t, check_id)
    now = datetime.now(UTC)
    rules = list(
        await t.db.scalars(
            select(AlertRule.id).where(
                AlertRule.tenant_id == t.tenant_id,
                AlertRule.kind == "check",
                AlertRule.target == str(check.id),
            )
        )
    )
    if rules:
        await t.db.execute(
            update(Incident)
            .where(
                Incident.rule_id.in_(rules),
                Incident.status == "open",
                Incident.tenant_id == t.tenant_id,
            )
            .values(status="resolved", resolved_at=now, resolved_by="check deleted")
        )
        await t.db.execute(
            delete(AlertRule).where(AlertRule.id.in_(rules), AlertRule.tenant_id == t.tenant_id)
        )
    await t.db.delete(check)
    await checkresults.forget(check.id)


class CheckStats(BaseModel):
    uptime_percent: float | None
    avg_latency_ms: float | None
    series: dict[str, list[dict]]


@router.get("/checks/{check_id}/metrics")
async def check_metrics(
    check_id: uuid.UUID,
    t: Tenant,
    range_: Annotated[Range, Query(alias="range")] = "24h",
) -> CheckStats:
    """Uptime over the range, average response time, and the response time
    and up/down series per location (probe region or host)."""
    check = await _get(t, check_id)
    seconds, step = RANGES[range_]
    end = int(datetime.now(UTC).timestamp())
    sel = f'check_id="{check.id}"'
    legend = ["probe", "host_id"]
    try:
        up = await query_instant(
            t.tenant_id, f"avg(avg_over_time(sentinel_check_up{{{sel}}}[{seconds}s])) * 100"
        )
        lat = await query_instant(
            t.tenant_id,
            f"avg(avg_over_time(sentinel_check_latency_seconds{{{sel}}}[{seconds}s])) * 1000",
        )
        series = {
            "latency": await query_series(
                t.tenant_id,
                f"sentinel_check_latency_seconds{{{sel}}} * 1000",
                end - seconds,
                end,
                step,
                legend,
            ),
            "up": await query_series(
                t.tenant_id,
                f"min_over_time(sentinel_check_up{{{sel}}}[{step}s])",
                end - seconds,
                end,
                step,
                legend,
            ),
        }
    except MetricsUnavailable:
        raise HTTPException(status_code=503, detail="metrics store unavailable") from None
    return CheckStats(
        uptime_percent=round(up[0][1], 3) if up else None,
        avg_latency_ms=round(lat[0][1], 1) if lat else None,
        series=series,
    )


class ProbeRegion(BaseModel):
    region: str
    probes: int
    online: int


@router.get("/probes")
async def list_probe_regions(t: Tenant) -> list[ProbeRegion]:
    """Where uptime checks can run from. Probes are staff-run agents, so
    they're read through the service role's view (no host details)."""
    async with ServiceSession() as db:
        rows = (
            await db.execute(
                select(Host.id, Host.probe_region).where(
                    Host.probe_region.is_not(None), Host.revoked_at.is_(None)
                )
            )
        ).all()
    seen = await last_seen([r.id for r in rows])
    regions: dict[str, ProbeRegion] = {}
    for r in rows:
        p = regions.setdefault(
            r.probe_region, ProbeRegion(region=r.probe_region, probes=0, online=0)
        )
        p.probes += 1
        p.online += int(is_online(seen.get(r.id)))
    return sorted(regions.values(), key=lambda p: p.region)


@router.post("/checks/{check_id}/push-token")
async def rotate_push_token(check_id: uuid.UUID, t: Tenant) -> CheckOut:
    """A new push URL; the old one stops working at once."""
    check = await _get(t, check_id)
    if check.type != "push":
        raise HTTPException(status_code=422, detail="only push checks have a push URL")
    check.push_token = secrets.token_urlsafe(24)
    await t.db.flush()
    return (await _out(t, [check]))[0]
