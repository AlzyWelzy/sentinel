# ruff: noqa: E501, S608 -- SQL built only from constants; values are bound parameters
"""IPDR: search an organisation's evidence (firewall sessions with NAT,
flows, syslog, VPN/auth identities, MAC/ARP tables), export it with a
manifest, and prove it wasn't changed (hash-chained audit, daily seals).

Who: owners, admins and investigators search and export; owners, admins
and auditors read the audit and seals. A search needs a reason and a person
(not an API token, not a staff impersonation): the audit row names them,
and is written before any data is returned.
"""

import json
import uuid
from datetime import UTC, datetime, timedelta
from ipaddress import ip_network
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Response, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select, text

from app.models import Host
from app.services import billing, clickhouse, ipdr
from app.services.heartbeats import redis
from app.tenancy import Tenant, TenantContext
from app.validation import Trimmed

router = APIRouter(prefix="/v1/ipdr", tags=["ipdr"])

Reason = Annotated[str, Trimmed, Field(min_length=5, max_length=500)]


def _person(t: TenantContext, roles: set[str]) -> tuple[uuid.UUID, str]:
    p = t.principal
    if t.role not in roles:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Your role can't use IPDR for this")
    if p.user_id is None or p.api_token_id is not None or p.impersonation_id is not None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "IPDR needs a signed-in member, by name")
    return uuid.UUID(p.user_id), p.email or p.name or p.user_id


async def _settings(t: TenantContext) -> Any:
    return (
        await t.db.execute(
            text(
                "SELECT ipdr_enabled, ipdr_retention_days, ipdr_collector_host_id, ipdr_allow,"
                " ipdr_export_approval_rows FROM tenants WHERE id = :t"
            ),
            {"t": t.tenant_id},
        )
    ).one()


def _unavailable(exc: Exception) -> HTTPException:
    return HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))


# ── Settings ──────────────────────────────────────────────────────────────


class SettingsOut(BaseModel):
    available: bool = Field(description="the server has an evidence store")
    enabled: bool
    retention_days: int
    collector_host_id: uuid.UUID | None
    allow: list[str]
    export_approval_rows: int
    ports: dict[str, int] = Field(description="where the collector listens")
    collector: dict | None = Field(description="the collector's latest report")


class SettingsIn(BaseModel):
    enabled: bool
    retention_days: int = Field(ge=30, le=2000)
    collector_host_id: uuid.UUID | None = None
    allow: list[str] = Field(default_factory=list, max_length=50)
    export_approval_rows: int = Field(default=100_000, ge=1000, le=5_000_000)

    @field_validator("allow")
    @classmethod
    def _cidrs(cls, v: list[str]) -> list[str]:
        out = []
        for c in v:
            try:
                n = ip_network(c.strip(), strict=False)
            except ValueError:
                raise ValueError(f"{c!r} isn't an address or range") from None
            if n.num_addresses > 65536:
                raise ValueError(f"{c} is wider than a /16 (IPv4) or /112 (IPv6)")
            out.append(str(n))
        return out


PORTS = {"syslog_udp": 1514, "syslog_tcp": 1601, "sflow": 6343, "netflow": 2055, "ipfix": 4739}


async def _settings_out(t: TenantContext) -> SettingsOut:
    s = await _settings(t)
    raw = await redis.get(f"pg:evidence:stats:{t.tenant_id}")

    return SettingsOut(
        available=clickhouse.enabled(),
        enabled=s.ipdr_enabled,
        retention_days=s.ipdr_retention_days,
        collector_host_id=s.ipdr_collector_host_id,
        allow=list(s.ipdr_allow or []),
        export_approval_rows=s.ipdr_export_approval_rows,
        ports=PORTS,
        collector=json.loads(raw) if raw else None,
    )


@router.get("/settings")
async def get_settings(t: Tenant) -> SettingsOut:
    return await _settings_out(t)


@router.put("/settings")
async def put_settings(body: SettingsIn, t: Tenant) -> SettingsOut:
    uid, actor = _person(t, ipdr.APPROVER_ROLES)
    if body.enabled:
        await billing.require_ipdr(t.db, t.tenant_id)
    if body.enabled and not clickhouse.enabled():
        raise HTTPException(422, "This server has no evidence store (CLICKHOUSE_URL)")
    if body.collector_host_id is not None:
        kind = await t.db.scalar(
            select(Host.kind).where(
                Host.id == body.collector_host_id, Host.tenant_id == t.tenant_id
            )
        )
        if kind is None:
            raise HTTPException(422, "collector_host_id not found")
        if kind != "server":
            raise HTTPException(422, "The collector is one of your servers (with the agent)")
    if body.enabled and body.collector_host_id is None:
        raise HTTPException(422, "Pick the server that receives the evidence")
    old = await _settings(t)
    await t.db.execute(
        text(
            "UPDATE tenants SET ipdr_enabled = :e, ipdr_retention_days = :r,"
            " ipdr_collector_host_id = :c, ipdr_allow = :a, ipdr_export_approval_rows = :x"
            " WHERE id = :t"
        ),
        {
            "e": body.enabled,
            "r": body.retention_days,
            "c": body.collector_host_id,
            "a": body.allow,
            "x": body.export_approval_rows,
            "t": t.tenant_id,
        },
    )
    await ipdr.audit(
        t.db,
        t.tenant_id,
        user_id=uid,
        actor=actor,
        action="settings",
        params={
            "before": {
                "enabled": old.ipdr_enabled,
                "retention_days": old.ipdr_retention_days,
                "collector_host_id": str(old.ipdr_collector_host_id or ""),
                "allow": list(old.ipdr_allow or []),
            },
            "after": body.model_dump(mode="json"),
        },
    )
    # The collector's agent picks the change up within a push or two
    # (ingest re-reads host configs every 10 s).
    return await _settings_out(t)


# ── Search ────────────────────────────────────────────────────────────────


class SearchIn(BaseModel):
    kind: ipdr.Kind
    reason: Reason
    start: datetime
    end: datetime
    ip: str | None = Field(default=None, max_length=64)
    port: int | None = None
    user: str | None = Field(default=None, max_length=200)
    mac: str | None = Field(default=None, max_length=32)
    text: str | None = Field(default=None, max_length=200)
    limit: int = Field(default=200, ge=1, le=1000)
    offset: int = Field(default=0, ge=0, le=100_000)


class SearchOut(BaseModel):
    rows: list[dict]
    total: int
    audit_hash: str


def _window(t: TenantContext, start: datetime, end: datetime) -> tuple[datetime, datetime]:
    if start.tzinfo is None or end.tzinfo is None:
        raise HTTPException(422, "start and end need a timezone")
    if end <= start:
        raise HTTPException(422, "end is after start")
    days = ipdr.WINDOW_DAYS.get(t.role, 62)
    if end - start > timedelta(days=days):
        raise HTTPException(422, f"Search at most {days} days at a time")
    return start, min(end, datetime.now(UTC) + timedelta(minutes=5))


async def _enabled(t: TenantContext) -> None:
    if not clickhouse.enabled():
        raise HTTPException(503, "This server has no evidence store")


def _filters(b: "SearchIn | ExportIn") -> dict[str, Any]:
    return {
        k: v
        for k, v in {
            "kind": b.kind,
            "ip": b.ip,
            "port": b.port,
            "user": b.user,
            "mac": b.mac,
            "text": b.text,
            "start": b.start.isoformat(),
            "end": b.end.isoformat(),
        }.items()
        if v is not None
    }


def _query(t: TenantContext, b: "SearchIn | ExportIn") -> tuple[str, str, dict[str, Any]]:
    start, end = _window(t, b.start, b.end)
    try:
        return ipdr.build_query(
            b.kind,
            t.tenant_id,
            start,
            end,
            ip=b.ip,
            port=b.port,
            user=b.user,
            mac=b.mac,
            text_=b.text,
        )
    except ipdr.SearchError as exc:
        raise HTTPException(422, str(exc)) from None


@router.post("/search")
async def search(body: SearchIn, t: Tenant) -> SearchOut:
    uid, actor = _person(t, ipdr.SEARCH_ROLES)
    await _enabled(t)
    table, where, params = _query(t, body)
    try:
        rows, total = await ipdr.search(table, where, params, body.limit, body.offset)
    except clickhouse.EvidenceUnavailable as exc:
        raise _unavailable(exc) from None
    h = await ipdr.audit(
        t.db,
        t.tenant_id,
        user_id=uid,
        actor=actor,
        action="search",
        reason=body.reason,
        params=_filters(body) | {"offset": body.offset},
        result_rows=len(rows),
    )
    await t.db.commit()  # the audit row is stored before the data leaves
    return SearchOut(rows=rows, total=total, audit_hash=h)


class HistoryIn(BaseModel):
    ip: str = Field(max_length=64)
    reason: Reason
    start: datetime
    end: datetime


@router.post("/ip-history")
async def ip_history(body: HistoryIn, t: Tenant) -> SearchOut:
    uid, actor = _person(t, ipdr.SEARCH_ROLES)
    await _enabled(t)
    start, end = _window(t, body.start, body.end)
    try:
        rows = await ipdr.ip_history(t.tenant_id, body.ip, start, end)
    except ipdr.SearchError as exc:
        raise HTTPException(422, str(exc)) from None
    except clickhouse.EvidenceUnavailable as exc:
        raise _unavailable(exc) from None
    h = await ipdr.audit(
        t.db,
        t.tenant_id,
        user_id=uid,
        actor=actor,
        action="ip_history",
        reason=body.reason,
        params={"ip": body.ip, "start": start.isoformat(), "end": end.isoformat()},
        result_rows=len(rows),
    )
    await t.db.commit()
    return SearchOut(rows=rows, total=len(rows), audit_hash=h)


# ── Sources ───────────────────────────────────────────────────────────────


class SourceOut(BaseModel):
    source: str
    device_id: str
    device: str | None
    table: str
    records_24h: int
    last_received: str
    unparsed_24h: int = 0


@router.get("/sources")
async def sources(t: Tenant) -> list[SourceOut]:
    """Who has sent evidence in the last 7 days, and how much today."""
    await _enabled(t)
    q = """
      SELECT source, device_id, tbl, countIf(received_at > now() - INTERVAL 1 DAY) AS n,
             toString(max(received_at)) AS last, countIf(received_at > now() - INTERVAL 1 DAY AND unparsed) AS bad
      FROM (
        SELECT toString(source) AS source, device_id, 'syslog' AS tbl, received_at, parsed = 0 AS unparsed
          FROM syslog WHERE tenant_id = {t:UUID} AND received_at > now() - INTERVAL 7 DAY
        UNION ALL SELECT toString(source), device_id, 'fw_sessions', received_at, 0
          FROM fw_sessions WHERE tenant_id = {t:UUID} AND received_at > now() - INTERVAL 7 DAY
        UNION ALL SELECT toString(exporter), device_id, 'flows', received_at, 0
          FROM flows WHERE tenant_id = {t:UUID} AND received_at > now() - INTERVAL 7 DAY
        UNION ALL SELECT '', device_id, 'mac_table', received_at, 0
          FROM mac_table WHERE tenant_id = {t:UUID} AND received_at > now() - INTERVAL 7 DAY
      ) GROUP BY source, device_id, tbl ORDER BY last DESC LIMIT 500
    """
    try:
        rows = await clickhouse.rows(q, {"t": t.tenant_id})
    except clickhouse.EvidenceUnavailable as exc:
        raise _unavailable(exc) from None
    ids = {uuid.UUID(r["device_id"]) for r in rows if _is_uuid(r["device_id"])}
    names = {
        str(h.id): h.hostname
        for h in await t.db.scalars(
            select(Host).where(Host.id.in_(ids), Host.tenant_id == t.tenant_id)
        )
    }
    return [
        SourceOut(
            source=r["source"].removeprefix("::ffff:"),
            device_id=r["device_id"],
            device=names.get(r["device_id"]),
            table=r["tbl"],
            records_24h=int(r["n"]),
            last_received=r["last"],
            unparsed_24h=int(r["bad"]),
        )
        for r in rows
    ]


def _is_uuid(v: str) -> bool:
    try:
        uuid.UUID(v)
    except ValueError:
        return False
    return True


# ── Exports ───────────────────────────────────────────────────────────────


class ExportIn(BaseModel):
    kind: ipdr.Kind
    reason: Reason
    start: datetime
    end: datetime
    ip: str | None = Field(default=None, max_length=64)
    port: int | None = None
    user: str | None = Field(default=None, max_length=200)
    mac: str | None = Field(default=None, max_length=32)
    text: str | None = Field(default=None, max_length=200)


class ExportOut(BaseModel):
    id: uuid.UUID
    requester: str
    reason: str
    params: dict
    row_count: int
    status: str
    decided_by: str | None
    decided_at: datetime | None
    sha256: str | None
    created_at: datetime
    expires_at: datetime


def _export_out(r: Any) -> ExportOut:
    return ExportOut(
        id=r.id,
        requester=r.requester,
        reason=r.reason,
        params=r.params,
        row_count=r.row_count,
        status=r.status,
        decided_by=r.decided_by,
        decided_at=r.decided_at,
        sha256=r.sha256,
        created_at=r.created_at,
        expires_at=r.expires_at,
    )


EXPORT_COLS = (
    "id, requester, reason, params, row_count, status, decided_by, decided_at, sha256,"
    " created_at, expires_at, requested_by"
)


async def _build(t: TenantContext, export_id: uuid.UUID, params: dict, manifest: dict) -> None:
    body = ExportIn(**params, reason=manifest["reason"])
    table, where, qp = _query(t, body)
    try:
        blob, sha, _rows = await ipdr.build_export(table, where, qp, manifest)
    except clickhouse.EvidenceUnavailable:
        await t.db.execute(
            text("UPDATE ipdr_exports SET status = 'failed' WHERE id = :i"), {"i": export_id}
        )
        return
    await t.db.execute(
        text("UPDATE ipdr_exports SET status = 'ready', file = :f, sha256 = :s WHERE id = :i"),
        {"f": blob, "s": sha, "i": export_id},
    )


@router.post("/exports", status_code=status.HTTP_201_CREATED)
async def create_export(body: ExportIn, t: Tenant) -> ExportOut:
    """Small exports are built at once; above the organisation's threshold
    an owner or admin other than the requester has to approve first."""
    uid, actor = _person(t, ipdr.SEARCH_ROLES)
    await _enabled(t)
    table, where, qp = _query(t, body)
    try:
        n = await ipdr.count(table, where, qp)
    except clickhouse.EvidenceUnavailable as exc:
        raise _unavailable(exc) from None
    if n == 0:
        raise HTTPException(422, "Nothing matches: there's nothing to export")
    s = await _settings(t)
    pending = n > s.ipdr_export_approval_rows
    params = body.model_dump(mode="json", exclude={"reason"})
    row = (
        await t.db.execute(
            text(
                "INSERT INTO ipdr_exports (tenant_id, requested_by, requester, reason, params,"
                " row_count, status) VALUES (:t, :u, :a, :r, CAST(:p AS jsonb), :n, :s)"
                f" RETURNING {EXPORT_COLS}"
            ),
            {
                "t": t.tenant_id,
                "u": uid,
                "a": actor,
                "r": body.reason,
                "p": json.dumps(params),
                "n": n,
                "s": "pending" if pending else "approved",
            },
        )
    ).one()
    await ipdr.audit(
        t.db,
        t.tenant_id,
        user_id=uid,
        actor=actor,
        action="export_request",
        reason=body.reason,
        params=_filters(body) | {"export_id": str(row.id)},
        result_rows=n,
    )
    if not pending:
        await _build(t, row.id, params, _manifest(t, row.id, actor, body.reason, params, None))
    return await _get_export(t, row.id)


def _manifest(
    t: TenantContext,
    export_id: uuid.UUID,
    requester: str,
    reason: str,
    params: dict,
    approver: str | None,
) -> dict:
    return {
        "export_id": str(export_id),
        "organisation": str(t.tenant_id),
        "requested_by": requester,
        "approved_by": approver,
        "reason": reason,
        "filters": params,
    }


async def _get_export(t: TenantContext, export_id: uuid.UUID) -> ExportOut:
    row = (
        await t.db.execute(
            text(f"SELECT {EXPORT_COLS} FROM ipdr_exports WHERE id = :i AND tenant_id = :t"),
            {"i": export_id, "t": t.tenant_id},
        )
    ).one_or_none()
    if row is None:
        raise HTTPException(404, "Export not found")
    return _export_out(row)


@router.get("/exports")
async def list_exports(t: Tenant) -> list[ExportOut]:
    _person(t, ipdr.SEARCH_ROLES | ipdr.AUDIT_ROLES)
    rows = (
        await t.db.execute(
            text(
                f"SELECT {EXPORT_COLS} FROM ipdr_exports WHERE tenant_id = :t"
                " ORDER BY created_at DESC LIMIT 200"
            ),
            {"t": t.tenant_id},
        )
    ).all()
    return [_export_out(r) for r in rows]


class DecisionIn(BaseModel):
    approve: bool
    reason: Reason


@router.post("/exports/{export_id}/decision")
async def decide_export(export_id: uuid.UUID, body: DecisionIn, t: Tenant) -> ExportOut:
    uid, actor = _person(t, ipdr.APPROVER_ROLES)
    row = (
        await t.db.execute(
            text(
                f"SELECT {EXPORT_COLS} FROM ipdr_exports WHERE id = :i AND tenant_id = :t FOR UPDATE"
            ),
            {"i": export_id, "t": t.tenant_id},
        )
    ).one_or_none()
    if row is None:
        raise HTTPException(404, "Export not found")
    if row.status != "pending":
        raise HTTPException(409, f"This export is already {row.status}")
    if row.requested_by == uid:
        raise HTTPException(403, "Someone other than the requester has to approve it")
    await t.db.execute(
        text(
            "UPDATE ipdr_exports SET status = :s, decided_by = :a, decided_at = now() WHERE id = :i"
        ),
        {"s": "approved" if body.approve else "denied", "a": actor, "i": export_id},
    )
    await ipdr.audit(
        t.db,
        t.tenant_id,
        user_id=uid,
        actor=actor,
        action="export_approve" if body.approve else "export_deny",
        reason=body.reason,
        params={"export_id": str(export_id)},
    )
    if body.approve:
        await _build(
            t,
            export_id,
            row.params,
            _manifest(t, export_id, row.requester, row.reason, row.params, actor),
        )
    return await _get_export(t, export_id)


@router.get(
    "/exports/{export_id}/download",
    response_class=Response,
    responses={200: {"content": {"application/zip": {}}}},
)
async def download_export(export_id: uuid.UUID, t: Tenant) -> Response:
    uid, actor = _person(t, ipdr.SEARCH_ROLES)
    row = (
        await t.db.execute(
            text(
                "SELECT status, file, sha256, requested_by, expires_at FROM ipdr_exports"
                " WHERE id = :i AND tenant_id = :t"
            ),
            {"i": export_id, "t": t.tenant_id},
        )
    ).one_or_none()
    if row is None:
        raise HTTPException(404, "Export not found")
    if row.status != "ready" or row.file is None:
        raise HTTPException(409, f"This export is {row.status}")
    if row.expires_at < datetime.now(UTC):
        raise HTTPException(410, "This export has expired; request it again")
    if row.requested_by != uid and t.role not in ipdr.APPROVER_ROLES:
        raise HTTPException(403, "Only the requester or an owner or admin can download it")
    await ipdr.audit(
        t.db,
        t.tenant_id,
        user_id=uid,
        actor=actor,
        action="export_download",
        params={"export_id": str(export_id), "sha256": row.sha256},
    )
    await t.db.commit()
    return Response(
        bytes(row.file),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="ipdr-export-{export_id}.zip"',
            "X-Content-SHA256": row.sha256,
        },
    )


# ── Audit and seals ───────────────────────────────────────────────────────


class AuditRow(BaseModel):
    seq: int
    at: datetime
    actor: str
    action: str
    reason: str
    params: dict
    result_rows: int | None
    hash: str


@router.get("/audit")
async def audit_log(t: Tenant, before: Annotated[int | None, Query(ge=1)] = None) -> list[AuditRow]:
    _person(t, ipdr.AUDIT_ROLES)
    rows = (
        await t.db.execute(
            text(
                "SELECT seq, at, actor, action, reason, params, result_rows, hash FROM ipdr_audit"
                " WHERE tenant_id = :t AND (CAST(:b AS bigint) IS NULL OR seq < :b)"
                " ORDER BY seq DESC LIMIT 200"
            ),
            {"t": t.tenant_id, "b": before},
        )
    ).all()
    return [AuditRow(**r._mapping) for r in rows]


@router.post("/audit/verify")
async def verify_audit(t: Tenant) -> dict:
    _person(t, ipdr.AUDIT_ROLES)
    return await ipdr.verify_audit(t.db, t.tenant_id)


class SealOut(BaseModel):
    day: str
    table: str
    rows: int
    hash: str
    created_at: datetime


@router.get("/seals")
async def seals(t: Tenant) -> list[SealOut]:
    _person(t, ipdr.AUDIT_ROLES)
    rows = (
        await t.db.execute(
            text(
                "SELECT day, tbl, row_count, hash, created_at FROM ipdr_seals WHERE tenant_id = :t"
                " ORDER BY day DESC, tbl LIMIT 500"
            ),
            {"t": t.tenant_id},
        )
    ).all()
    return [
        SealOut(
            day=r.day.isoformat(),
            table=r.tbl,
            rows=r.row_count,
            hash=r.hash,
            created_at=r.created_at,
        )
        for r in rows
    ]


@router.post("/seals/verify")
async def verify_seals(t: Tenant, days: Annotated[int, Query(ge=1, le=400)] = 14) -> list[dict]:
    uid, actor = _person(t, ipdr.AUDIT_ROLES)
    await _enabled(t)
    try:
        out = await ipdr.verify_seals(t.db, t.tenant_id, days)
    except clickhouse.EvidenceUnavailable as exc:
        raise _unavailable(exc) from None
    bad = [s for s in out if not s["chain_ok"] or s["data_ok"] is False]
    await ipdr.audit(
        t.db,
        t.tenant_id,
        user_id=uid,
        actor=actor,
        action="seals_verify",
        params={"days": days, "checked": len(out), "failed": len(bad)},
    )
    return out
