"""Resource and uptime checks.

A check runs on one server, on every server with a tag (ports, URLs,
certificates, DNS, files, log patterns: "from inside"), or on the public
probes in several regions (uptime: "from outside"). Agents receive their
checks with their config, so nothing has to be installed per check.

Creating a check also creates its alert rule unless alert=false, so the
common case ("tell me when my site is down") is one request.
"""

import ipaddress
import re
import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import delete, func, select, update

from app.db import ServiceSession
from app.models import AlertRule, AlertState, Check, Host, Incident
from app.routes.ranges import RANGES, Range
from app.services import checkresults
from app.services.heartbeats import is_online, last_seen
from app.services.metrics import MetricsUnavailable, query_instant, query_series
from app.tenancy import Tenant, TenantContext
from app.validation import normalize_tag

router = APIRouter(prefix="/v1")

MAX_CHECKS = 200
MIN_PROBE_INTERVAL = 30
CheckType = Literal["tcp", "http", "tls", "dns", "file", "log", "ping"]
PROBE_TYPES = {"tcp", "http", "tls", "dns", "ping"}
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)

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
    },
    "tls": {"tls_expiry_days", "timeout_seconds"},
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
    name: str = Field(min_length=1, max_length=100)
    type: CheckType
    target: str = Field(min_length=1, max_length=2048)
    params: dict[str, str] = Field(default_factory=dict)
    interval_seconds: int = Field(default=60, ge=10, le=3600)
    host_id: uuid.UUID | None = None
    tag: str | None = None
    on_probes: bool = False
    probe_regions: list[str] = Field(default_factory=list, max_length=20)
    min_failing: int = Field(default=1, ge=1, le=10)
    enabled: bool = True
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
            return {
                str(k): str(val).lower() if isinstance(val, bool) else str(val)
                for k, val in v.items()
                if val is not None
            }
        return v

    @model_validator(mode="after")
    def _validate(self) -> "CheckIn":
        if sum([self.host_id is not None, self.tag is not None, self.on_probes]) != 1:
            raise ValueError("a check runs on one server (host_id), a tag, or the probes")
        if self.on_probes:
            if self.type not in PROBE_TYPES:
                raise ValueError("file and log checks run on a server, not the probes")
            self.interval_seconds = max(self.interval_seconds, MIN_PROBE_INTERVAL)
        else:
            self.probe_regions, self.min_failing = [], 1
        unknown = set(self.params) - PARAMS[self.type]
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
    created_at: datetime
    updated_at: datetime
    status: CheckStatus
    results: list[CheckResultOut]
    last_failure: CheckResultOut | None
    rule_id: uuid.UUID | None
    open_incident_id: uuid.UUID | None


def _status(c: Check, results: list[dict]) -> CheckStatus:
    if not c.enabled:
        return "paused"
    if not results:
        return "pending"
    failing = sum(1 for r in results if not r.get("ok"))
    need = min(c.min_failing, len(results)) if c.on_probes else 1
    return "down" if failing >= max(need, 1) else "up"


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
    out = []
    for c in checks:
        results = latest.get(c.id, [])
        out.append(
            CheckOut(
                id=c.id,
                name=c.name,
                type=c.type,
                target=c.target,
                params={k: str(v) for k, v in (c.params or {}).items()},
                interval_seconds=c.interval_seconds,
                host_id=c.host_id,
                tag=c.tag,
                on_probes=c.on_probes,
                probe_regions=list(c.probe_regions or []),
                min_failing=c.min_failing,
                enabled=c.enabled,
                created_at=c.created_at,
                updated_at=c.updated_at,
                status=_status(c, results),
                results=[CheckResultOut(**r) for r in results],
                last_failure=CheckResultOut(**failures[c.id]) if c.id in failures else None,
                rule_id=rules.get(str(c.id)),
                open_incident_id=open_incidents.get(c.id),
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
    count = await t.db.scalar(
        select(func.count()).select_from(Check).where(Check.tenant_id == t.tenant_id)
    )
    if (count or 0) >= MAX_CHECKS:
        raise HTTPException(status_code=422, detail=f"at most {MAX_CHECKS} checks per account")
    check = Check(tenant_id=t.tenant_id, **body.model_dump(exclude={"alert", "severity"}))
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
                duration_seconds=0 if _event_like(body) else min(body.interval_seconds * 2, 600),
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
            t.tenant_id, f"avg(avg_over_time(pulsegrid_check_up{{{sel}}}[{seconds}s])) * 100"
        )
        lat = await query_instant(
            t.tenant_id,
            f"avg(avg_over_time(pulsegrid_check_latency_seconds{{{sel}}}[{seconds}s])) * 1000",
        )
        series = {
            "latency": await query_series(
                t.tenant_id,
                f"pulsegrid_check_latency_seconds{{{sel}}} * 1000",
                end - seconds,
                end,
                step,
                legend,
            ),
            "up": await query_series(
                t.tenant_id,
                f"min_over_time(pulsegrid_check_up{{{sel}}}[{step}s])",
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
