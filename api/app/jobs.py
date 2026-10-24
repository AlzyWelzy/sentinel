"""Background jobs: python -m app.jobs

- Monthly report emails, on the 1st (UTC), to each account's verified email
  contacts, unless the account turned them off.
- Hourly rollups (downsampling): each hour of raw metrics becomes one
  sample per series in the long-term VictoriaMetrics, so charts can reach
  back years after raw samples expire. Gauges keep their hourly average;
  counters keep their value at the end of the hour, so rate() still works.
- Daily cleanup of delivered messages, finished actions and old incidents.

Run one or more replicas: a Postgres advisory lock lets one work while the
others stand by.
"""

import asyncio
import logging
import time
from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy import select, text

from app.config import settings
from app.db import ServiceSession
from app.models import Host, NotificationChannel, OutboundMessage, Tenant
from app.services.heartbeats import redis
from app.services.reports import build_summary, previous_month, render_html, render_text

log = logging.getLogger("pulsegrid.jobs")

LOCK_ID = 0x50474A42  # "PGJB"
ROLLUP_KEY = "pg:rollup:last_hour"
CLEANUP_KEY = "pg:cleanup:last_day"
# On first start (or after a long outage), roll up at most this many hours.
ROLLUP_BACKFILL_HOURS = 48

# Raw series rolled up. Counters (… _total) keep their last value.
ROLLUP_GAUGES = [
    "pulsegrid_cpu_usage_percent",
    "pulsegrid_cpu_mode_percent",
    "pulsegrid_memory_used_percent",
    "pulsegrid_swap_used_percent",
    "pulsegrid_disk_used_percent",
    "pulsegrid_disk_inodes_used_percent",
    "pulsegrid_load",
    "pulsegrid_processes_total",
    "pulsegrid_check_up",
    "pulsegrid_check_latency_seconds",
    "pulsegrid_uptime_seconds",
]
ROLLUP_COUNTERS = [
    "pulsegrid_network_bytes_total",
    "pulsegrid_disk_read_bytes_total",
    "pulsegrid_disk_written_bytes_total",
    "pulsegrid_disk_reads_total",
    "pulsegrid_disk_writes_total",
    "pulsegrid_disk_io_time_seconds_total",
]


async def send_monthly_reports(now: datetime) -> int:
    start, end = previous_month(now)
    sent = 0
    async with ServiceSession() as db, db.begin():
        tenants = list(
            await db.scalars(
                select(Tenant).where(
                    Tenant.status == "active",
                    Tenant.monthly_report,
                    (Tenant.report_sent_for.is_(None)) | (Tenant.report_sent_for < start.date()),
                )
            )
        )
    for tenant in tenants:
        async with ServiceSession() as db, db.begin():
            # Only accounts that had a server during the month get a report.
            had_hosts = await db.scalar(
                select(Host.id)
                .where(
                    Host.tenant_id == tenant.id, Host.created_at < end, Host.probe_region.is_(None)
                )
                .limit(1)
            )
            locked = await db.scalar(
                select(Tenant).where(Tenant.id == tenant.id).with_for_update(skip_locked=True)
            )
            if locked is None or (
                locked.report_sent_for and locked.report_sent_for >= start.date()
            ):
                continue
            locked.report_sent_for = start.date()
            if had_hosts is None:
                continue
            channels = list(
                await db.scalars(
                    select(NotificationChannel).where(
                        NotificationChannel.tenant_id == tenant.id,
                        NotificationChannel.type == "email",
                        NotificationChannel.verified_at.is_not(None),
                    )
                )
            )
            if not channels:
                continue
            summary = await build_summary(db, tenant.id, start, end)
            account = tenant.display_name or tenant.email or "your account"
            payload = {
                "subject": f"[Pulsegrid] Monitoring report for {start:%B %Y}",
                "text": render_text(summary, account),
                "html": render_html(summary, account, settings.PUBLIC_DASHBOARD_URL),
                "event": {"type": "report", "month": f"{start:%Y-%m}"},
            }
            for c in channels:
                db.add(
                    OutboundMessage(
                        tenant_id=tenant.id, channel_id=c.id, kind="report", payload=payload
                    )
                )
            sent += 1
    return sent


async def rollup(now: datetime) -> int:
    """Roll up every complete hour since the last one done."""
    if not settings.VICTORIAMETRICS_LONG_URL:
        return 0
    current = int(now.timestamp()) // 3600 * 3600  # start of the current (incomplete) hour
    last = await redis.get(ROLLUP_KEY)
    first = int(last) + 3600 if last else current - ROLLUP_BACKFILL_HOURS * 3600
    first = max(first, current - ROLLUP_BACKFILL_HOURS * 3600)
    done = 0
    async with httpx.AsyncClient(timeout=120) as client:
        for hour_end in range(first + 3600, current + 1, 3600):
            lines: list[str] = []
            for name in ROLLUP_GAUGES + ROLLUP_COUNTERS:
                fn = "last_over_time" if name in ROLLUP_COUNTERS else "avg_over_time"
                r = await client.get(
                    f"{settings.VICTORIAMETRICS_URL}/api/v1/query",
                    params={"query": f"{fn}({name}[1h])", "time": hour_end},
                )
                r.raise_for_status()
                for res in r.json()["data"]["result"]:
                    labels = res["metric"]
                    if "tenant_id" not in labels:
                        continue
                    lbl = ",".join(
                        f'{k}="{_escape(v)}"' for k, v in sorted(labels.items()) if k != "__name__"
                    )
                    lines.append(f"{name}{{{lbl}}} {res['value'][1]} {hour_end * 1000}")
            if lines:
                w = await client.post(
                    f"{settings.VICTORIAMETRICS_LONG_URL}/api/v1/import/prometheus",
                    content="\n".join(lines) + "\n",
                )
                w.raise_for_status()
            await redis.set(ROLLUP_KEY, hour_end)
            done += 1
    return done


def _escape(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


async def cleanup(now: datetime) -> None:
    async with ServiceSession() as db, db.begin():
        await db.execute(
            text(
                "DELETE FROM outbound_messages WHERE status IN ('sent', 'failed') "
                "AND created_at < :t"
            ),
            {"t": now - timedelta(days=90)},
        )
        await db.execute(
            text("DELETE FROM host_actions WHERE status <> 'pending' AND created_at < :t"),
            {"t": now - timedelta(days=90)},
        )
        await db.execute(
            text("DELETE FROM incidents WHERE status = 'resolved' AND resolved_at < :t"),
            {"t": now - timedelta(days=400)},
        )


async def tick() -> None:
    now = datetime.now(UTC)
    try:
        n = await rollup(now)
        if n:
            log.info("rolled up %d hour(s)", n)
    except Exception:
        log.exception("rollup failed")
    # The report goes out once the 1st is a few hours old (UTC).
    if now.day > 1 or now.hour >= 6:
        try:
            n = await send_monthly_reports(now)
            if n:
                log.info("queued %d monthly report(s)", n)
        except Exception:
            log.exception("monthly reports failed")
    today = now.date().isoformat()
    if await redis.get(CLEANUP_KEY) != today:
        try:
            await cleanup(now)
            await redis.set(CLEANUP_KEY, today)
            log.info("cleanup done")
        except Exception:
            log.exception("cleanup failed")


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    while True:
        async with ServiceSession() as db:
            conn = await db.connection()
            got = await conn.scalar(text("SELECT pg_try_advisory_lock(:id)"), {"id": LOCK_ID})
            if not got:
                await asyncio.sleep(30)  # another replica is working; stand by
                continue
            log.info("jobs worker active")
            try:
                while True:
                    started = time.monotonic()
                    await tick()
                    await conn.scalar(text("SELECT 1"))  # keep the lock's connection alive
                    await asyncio.sleep(max(60 - (time.monotonic() - started), 5))
            finally:
                await conn.scalar(text("SELECT pg_advisory_unlock(:id)"), {"id": LOCK_ID})


if __name__ == "__main__":
    asyncio.run(main())
