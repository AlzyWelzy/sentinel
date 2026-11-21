# ruff: noqa: E501, S608 -- SQL built only from constants; values are bound parameters
"""IPDR: who used an IP address, when, and what it talked to.

- Searches and exports read the organisation's evidence in ClickHouse.
- Every search, export, approval and download first goes into a
  hash-chained audit (ipdr_audit): each row's hash covers its content and
  the previous row's hash, so editing or deleting any row breaks the
  chain. No audit row, no data.
- Daily seals (ipdr_seals) record each evidence table's row count and an
  order-independent digest for one day, chained to the previous seal and to
  the audit head at the time; re-computing them later shows whether stored
  evidence was changed.
"""

import hashlib
import io
import json
import uuid
import zipfile
from datetime import UTC, date, datetime, timedelta
from ipaddress import ip_address
from typing import Any, Literal

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services import clickhouse

Kind = Literal["sessions", "flows", "syslog", "identity", "mac"]
TABLES: dict[str, str] = {
    "sessions": "fw_sessions",
    "flows": "flows",
    "syslog": "syslog",
    "identity": "ip_users",
    "mac": "mac_table",
}
SEALED_TABLES = tuple(TABLES.values())
GENESIS = "0" * 64
SEARCH_ROLES = {"owner", "admin", "investigator"}
AUDIT_ROLES = {"owner", "admin", "auditor"}
APPROVER_ROLES = {"owner", "admin"}
# Days one search may span.
WINDOW_DAYS = {"investigator": 62, "admin": 370, "owner": 370}
EXPORT_CAP = 500_000

COLUMNS: dict[str, str] = {
    "fw_sessions": "received_at, event_time, toString(source) AS source, device_id, devname, action, policy_id,"
    " proto, service, app, toString(src_ip) AS src_ip, src_port, src_intf, src_mac,"
    " toString(dst_ip) AS dst_ip, dst_port, dst_intf, toString(nat_src_ip) AS nat_src_ip, nat_src_port,"
    " toString(nat_dst_ip) AS nat_dst_ip, nat_dst_port, user, duration, sent_bytes, rcvd_bytes, raw",
    "flows": "received_at, flow_start, flow_end, toString(exporter) AS exporter, device_id, flow_type, sampling,"
    " proto, toString(src_ip) AS src_ip, src_port, toString(dst_ip) AS dst_ip, dst_port, in_if, out_if,"
    " bytes, packets, vlan, src_mac, dst_mac",
    "syslog": "received_at, event_time, toString(source) AS source, device_id, severity, hostname, program,"
    " message, parsed",
    "ip_users": "received_at, event_time, toString(ip) AS ip, user, toString(source) AS source, device_id,"
    " action, raw",
    "mac_table": "received_at, device_id, port, if_index, vlan, mac, toString(ip) AS ip, source",
}


class SearchError(ValueError):
    pass


def _canon(v: Any) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), default=str)


def _audit_hash(prev: str, row: dict[str, Any]) -> str:
    return hashlib.sha256((prev + "|" + _canon(row)).encode()).hexdigest()


def _audit_body(r: Any) -> dict[str, Any]:
    return {
        "seq": r.seq,
        "at": r.at.astimezone(UTC).isoformat(timespec="microseconds"),
        "user_id": str(r.user_id) if r.user_id else None,
        "actor": r.actor,
        "action": r.action,
        "reason": r.reason,
        "params": r.params,
        "result_rows": r.result_rows,
    }


async def audit(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    user_id: uuid.UUID | None,
    actor: str,
    action: str,
    reason: str = "",
    params: dict[str, Any] | None = None,
    result_rows: int | None = None,
) -> str:
    """Append one row to the organisation's chain; returns its hash. A
    transaction-level lock keeps two appends from taking the same seq."""
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtext('ipdr_audit:' || :t))"), {"t": str(tenant_id)}
    )
    last = (
        await db.execute(
            text("SELECT seq, hash FROM ipdr_audit WHERE tenant_id = :t ORDER BY seq DESC LIMIT 1"),
            {"t": tenant_id},
        )
    ).one_or_none()
    seq, prev = (last.seq + 1, last.hash) if last else (1, GENESIS)
    at = datetime.now(UTC)
    body = {
        "seq": seq,
        "at": at.isoformat(timespec="microseconds"),
        "user_id": str(user_id) if user_id else None,
        "actor": actor,
        "action": action,
        "reason": reason,
        "params": params or {},
        "result_rows": result_rows,
    }
    h = _audit_hash(prev, body)
    await db.execute(
        text(
            "INSERT INTO ipdr_audit (tenant_id, seq, at, user_id, actor, action, reason, params,"
            " result_rows, prev_hash, hash) VALUES (:t, :seq, :at, :u, :actor, :action, :reason,"
            " CAST(:params AS jsonb), :rows, :prev, :hash)"
        ),
        {
            "t": tenant_id,
            "seq": seq,
            "at": at,
            "u": user_id,
            "actor": actor,
            "action": action,
            "reason": reason,
            "params": json.dumps(params or {}),
            "rows": result_rows,
            "prev": prev,
            "hash": h,
        },
    )
    await db.flush()
    return h


async def verify_audit(db: AsyncSession, tenant_id: uuid.UUID) -> dict[str, Any]:
    """Walk the whole chain. Returns ok, the rows checked, and the first
    broken seq if any (a changed row, a deleted one, or a reordering)."""
    rows = (
        await db.execute(
            text(
                "SELECT seq, at, user_id, actor, action, reason, params, result_rows, prev_hash, hash"
                " FROM ipdr_audit WHERE tenant_id = :t ORDER BY seq"
            ),
            {"t": tenant_id},
        )
    ).all()
    prev = GENESIS
    for i, r in enumerate(rows, 1):
        if r.seq != i or r.prev_hash != prev or _audit_hash(prev, _audit_body(r)) != r.hash:
            return {"ok": False, "checked": i - 1, "broken_at": r.seq}
        prev = r.hash
    return {"ok": True, "checked": len(rows), "broken_at": None, "head": prev}


async def audit_head(db: AsyncSession, tenant_id: uuid.UUID) -> str:
    h = await db.scalar(
        text("SELECT hash FROM ipdr_audit WHERE tenant_id = :t ORDER BY seq DESC LIMIT 1"),
        {"t": tenant_id},
    )
    return h or GENESIS


# ── Search ────────────────────────────────────────────────────────────────


def _ip(v: str) -> str:
    try:
        return str(ip_address(v.strip()))
    except ValueError:
        raise SearchError(f"{v!r} isn't an IP address") from None


def build_query(
    kind: Kind,
    tenant_id: uuid.UUID,
    start: datetime,
    end: datetime,
    *,
    ip: str | None = None,
    port: int | None = None,
    user: str | None = None,
    mac: str | None = None,
    text_: str | None = None,
) -> tuple[str, str, dict[str, Any]]:
    """(table, WHERE clause, params) for one search. At least one subject
    (ip, port, user, mac, text) is required: no dragnet listings."""
    table = TABLES[kind]
    where = [
        "tenant_id = {t:UUID}",
        "received_at >= {start:DateTime64(3)}",
        "received_at < {end:DateTime64(3)}",
    ]
    p: dict[str, Any] = {
        "t": tenant_id,
        "start": start.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "end": end.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
    }
    subject = False
    if ip:
        p["ip"] = _ip(ip)
        cols = {
            "fw_sessions": ["src_ip", "dst_ip", "nat_src_ip", "nat_dst_ip"],
            "flows": ["src_ip", "dst_ip"],
            "ip_users": ["ip"],
            "mac_table": ["ip"],
        }.get(table)
        if cols:
            where.append("(" + " OR ".join(f"{c} = toIPv6({{ip:String}})" for c in cols) + ")")
        else:  # syslog
            where.append("(has(ips, toIPv6({ip:String})) OR source = toIPv6({ip:String}))")
        subject = True
    if port is not None:
        if not 0 < port < 65536:
            raise SearchError("port is 1-65535")
        cols = {
            "fw_sessions": ["src_port", "dst_port", "nat_src_port", "nat_dst_port"],
            "flows": ["src_port", "dst_port"],
        }.get(table)
        if not cols:
            raise SearchError(f"{kind} records have no ports")
        p["port"] = port
        where.append("(" + " OR ".join(f"{c} = {{port:UInt16}}" for c in cols) + ")")
        subject = True
    if user:
        if table not in ("fw_sessions", "ip_users"):
            raise SearchError(f"{kind} records have no users")
        p["user"] = user.strip()
        where.append("user = {user:String}")
        subject = True
    if mac:
        m = mac.strip().lower().replace("-", ":")
        if table == "mac_table":
            where.append("mac = {mac:String}")
        elif table == "fw_sessions":
            where.append("src_mac = {mac:String}")
        elif table == "flows":
            where.append("(src_mac = {mac:String} OR dst_mac = {mac:String})")
        else:
            raise SearchError(f"{kind} records have no MAC addresses")
        p["mac"] = m
        subject = True
    if text_:
        if table != "syslog":
            raise SearchError("text search is for syslog")
        if len(text_.strip()) < 3:
            raise SearchError("search for at least 3 characters")
        p["q"] = text_.strip()
        where.append("positionCaseInsensitive(message, {q:String}) > 0")
        subject = True
    if not subject:
        raise SearchError("search for an IP address, port, user, MAC or text")
    return table, " AND ".join(where), p


async def search(
    table: str, where: str, params: dict[str, Any], limit: int, offset: int
) -> tuple[list[dict], int]:
    rows = await clickhouse.rows(
        f"SELECT {COLUMNS[table]} FROM {table} WHERE {where}"  # noqa: S608 (built from constants)
        " ORDER BY received_at DESC LIMIT {lim:UInt32} OFFSET {off:UInt32}",
        params | {"lim": limit, "off": offset},
    )
    total = await count(table, where, params)
    return rows, total


async def count(table: str, where: str, params: dict[str, Any]) -> int:
    r = await clickhouse.rows(
        f"SELECT count() AS n FROM {table} WHERE {where}",  # noqa: S608
        params,
    )
    return int(r[0]["n"]) if r else 0


async def ip_history(
    tenant_id: uuid.UUID, ip: str, start: datetime, end: datetime
) -> list[dict[str, Any]]:
    """Per day: where the IP showed up (sessions, NAT, flows, logs,
    identity), first and last seen, and how much."""
    p = {
        "t": tenant_id,
        "ip": _ip(ip),
        "start": start.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S"),
        "end": end.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S"),
    }
    span = (
        "tenant_id = {t:UUID} AND received_at >= {start:DateTime64(3)}"
        " AND received_at < {end:DateTime64(3)}"
    )
    q = f"""
        SELECT toString(day) AS day, role, min(first) AS first_seen, max(last) AS last_seen,
               sum(n) AS events, sum(b) AS bytes FROM (
          SELECT toDate(received_at) AS day, multiIf(src_ip = toIPv6({{ip:String}}), 'session source',
                 dst_ip = toIPv6({{ip:String}}), 'session destination', 'nat') AS role,
                 min(received_at) AS first, max(received_at) AS last, count() AS n,
                 sum(sent_bytes + rcvd_bytes) AS b
            FROM fw_sessions WHERE {span} AND (src_ip = toIPv6({{ip:String}}) OR dst_ip = toIPv6({{ip:String}})
              OR nat_src_ip = toIPv6({{ip:String}}) OR nat_dst_ip = toIPv6({{ip:String}}))
           GROUP BY day, role
          UNION ALL
          SELECT toDate(received_at), if(src_ip = toIPv6({{ip:String}}), 'flow source', 'flow destination'),
                 min(received_at), max(received_at), count(), sum(bytes)
            FROM flows WHERE {span} AND (src_ip = toIPv6({{ip:String}}) OR dst_ip = toIPv6({{ip:String}}))
           GROUP BY 1, 2
          UNION ALL
          SELECT toDate(received_at), 'log', min(received_at), max(received_at), count(), toUInt64(0)
            FROM syslog WHERE {span} AND has(ips, toIPv6({{ip:String}})) GROUP BY 1
          UNION ALL
          SELECT toDate(received_at), concat('user ', user), min(received_at), max(received_at), count(),
                 toUInt64(0)
            FROM ip_users WHERE {span} AND ip = toIPv6({{ip:String}}) GROUP BY 1, user
        ) GROUP BY day, role ORDER BY day DESC, role LIMIT 2000
    """  # noqa: S608 (span is a constant)
    return await clickhouse.rows(q, p)


# ── Exports ───────────────────────────────────────────────────────────────


async def build_export(
    table: str, where: str, params: dict[str, Any], manifest: dict[str, Any]
) -> tuple[bytes, str, int]:
    """A zip of data.csv and manifest.json (who, when, why, filters, the
    data's SHA-256); returns it, its own SHA-256, and the row count."""
    data = await clickhouse.csv(
        f"SELECT {COLUMNS[table]} FROM {table} WHERE {where}"  # noqa: S608
        " ORDER BY received_at LIMIT {cap:UInt32}",
        params | {"cap": EXPORT_CAP},
    )
    rows = max(data.count(b"\n") - 1, 0)
    man = manifest | {
        "rows": rows,
        "data_sha256": hashlib.sha256(data).hexdigest(),
        "generated_at": datetime.now(UTC).isoformat(),
        "capped_at": EXPORT_CAP if rows >= EXPORT_CAP else None,
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("data.csv", data)
        z.writestr("manifest.json", json.dumps(man, indent=2, default=str))
    blob = buf.getvalue()
    return blob, hashlib.sha256(blob).hexdigest(), rows


# ── Seals ─────────────────────────────────────────────────────────────────


async def table_digest(tenant_id: uuid.UUID, tbl: str, day: date) -> tuple[int, str]:
    """Row count and an order-independent digest of one table-day."""
    r = await clickhouse.rows(
        f"SELECT count() AS n, toString(groupBitXor(cityHash64(*))) AS d FROM {tbl}"  # noqa: S608
        " WHERE tenant_id = {t:UUID} AND toDate(received_at) = {day:Date}",
        {"t": tenant_id, "day": day.isoformat()},
    )
    return (int(r[0]["n"]), str(r[0]["d"])) if r else (0, "0")


def seal_hash(prev: str, day: date, tbl: str, rows: int, digest: str, head: str) -> str:
    return hashlib.sha256(
        f"{prev}|{day.isoformat()}|{tbl}|{rows}|{digest}|{head}".encode()
    ).hexdigest()


async def seal_day(db: AsyncSession, tenant_id: uuid.UUID, day: date) -> int:
    """Seal every table for one day (once). Runs as the service role."""
    made = 0
    head = await audit_head(db, tenant_id)
    for tbl in SEALED_TABLES:
        exists = await db.scalar(
            text("SELECT 1 FROM ipdr_seals WHERE tenant_id = :t AND day = :d AND tbl = :tbl"),
            {"t": tenant_id, "d": day, "tbl": tbl},
        )
        if exists:
            continue
        rows, digest = await table_digest(tenant_id, tbl, day)
        prev = (
            await db.scalar(
                text("SELECT hash FROM ipdr_seals WHERE tenant_id = :t ORDER BY id DESC LIMIT 1"),
                {"t": tenant_id},
            )
            or GENESIS
        )
        h = seal_hash(prev, day, tbl, rows, digest, head)
        await db.execute(
            text(
                "INSERT INTO ipdr_seals (tenant_id, day, tbl, row_count, digest, audit_head,"
                " prev_hash, hash) VALUES (:t, :d, :tbl, :n, :dg, :head, :prev, :h)"
            ),
            {
                "t": tenant_id,
                "d": day,
                "tbl": tbl,
                "n": rows,
                "dg": digest,
                "head": head,
                "prev": prev,
                "h": h,
            },
        )
        made += 1
    return made


async def verify_seals(
    db: AsyncSession, tenant_id: uuid.UUID, days: int = 14
) -> list[dict[str, Any]]:
    """Re-check the chain of all seals, and re-compute the last `days`
    days of evidence against them."""
    seals = (
        await db.execute(
            text(
                "SELECT id, day, tbl, row_count, digest, audit_head, prev_hash, hash"
                " FROM ipdr_seals WHERE tenant_id = :t ORDER BY id"
            ),
            {"t": tenant_id},
        )
    ).all()
    since = datetime.now(UTC).date() - timedelta(days=days)
    out = []
    prev = GENESIS
    for s in seals:
        chain_ok = s.prev_hash == prev and s.hash == seal_hash(
            prev, s.day, s.tbl, s.row_count, s.digest, s.audit_head
        )
        prev = s.hash
        item: dict[str, Any] = {
            "day": s.day.isoformat(),
            "table": s.tbl,
            "rows": s.row_count,
            "chain_ok": chain_ok,
            "data_ok": None,
        }
        if s.day >= since:
            rows, digest = await table_digest(tenant_id, s.tbl, s.day)
            item["data_ok"] = rows == s.row_count and digest == s.digest
            if not item["data_ok"]:
                item["found_rows"] = rows
        out.append(item)
    return out
