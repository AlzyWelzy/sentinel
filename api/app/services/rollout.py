"""Agent rollouts. Ingest offers each server one agent version (see
ingest/rollout.go, which must pick exactly as version_for does here):

1. the account's pin, if staff set one;
2. else the candidate, if the server's bucket (FNV-1a of its host id, mod
   100) is below candidate_percent;
3. else the stable version.

A new agent version (AGENT_VERSION on deploy) becomes the candidate for
AGENT_CANARY_PERCENT of servers. The health gate rolls a candidate back when
its servers go silent noticeably more than the rest.
"""

import logging
import os
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.services import heartbeats

log = logging.getLogger("pulsegrid.rollout")

VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$")
# Health gate: judge a candidate once it has had time to reach its servers.
GATE_AFTER = timedelta(minutes=75)
SILENT_AFTER = timedelta(minutes=10)
GATE_MIN_HOSTS = 2
GATE_SILENT_SHARE = 0.2
GATE_MARGIN = 0.1


@dataclass
class Rollout:
    stable_version: str
    candidate_version: str | None = None
    candidate_percent: int = 0
    candidate_since: datetime | None = None
    rolled_back_version: str | None = None
    rollback_reason: str | None = None
    updated_at: datetime | None = None
    updated_by: str | None = None


def parse(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("-", 1)[0].split("+", 1)[0].split("."))


def bucket(host_id: uuid.UUID | str) -> int:
    """FNV-1a (32-bit) of the host id's canonical text, mod 100."""
    h = 0x811C9DC5
    for b in str(host_id).lower().encode():
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h % 100


def version_for(r: Rollout, host_id: uuid.UUID | str, pin: str | None) -> str:
    if pin:
        return pin
    if r.candidate_version and bucket(host_id) < r.candidate_percent:
        return r.candidate_version
    return r.stable_version


def available_versions() -> list[str]:
    """Agent versions whose binaries this API serves, newest first."""
    try:
        names = os.listdir(settings.AGENT_DIST_DIR)
    except OSError:
        return []
    found = [
        n
        for n in names
        if VERSION_RE.match(n) and os.path.isdir(os.path.join(settings.AGENT_DIST_DIR, n))
    ]
    return sorted(found, key=parse, reverse=True)


async def current(db: AsyncSession) -> Rollout:
    row = (
        await db.execute(
            text(
                "SELECT stable_version, candidate_version, candidate_percent, candidate_since, "
                "rolled_back_version, rollback_reason, updated_at, updated_by "
                "FROM agent_rollout WHERE id = 1"
            )
        )
    ).one_or_none()
    if row is None:
        return Rollout(stable_version=settings.AGENT_VERSION)
    return Rollout(**row._mapping)


async def save(db: AsyncSession, r: Rollout, actor: str) -> Rollout:
    r.updated_at, r.updated_by = datetime.now(UTC), actor
    await db.execute(
        text("""
            INSERT INTO agent_rollout (id, stable_version, candidate_version, candidate_percent,
                                       candidate_since, rolled_back_version, rollback_reason,
                                       updated_at, updated_by)
            VALUES (1, :stable_version, :candidate_version, :candidate_percent, :candidate_since,
                    :rolled_back_version, :rollback_reason, :updated_at, :updated_by)
            ON CONFLICT (id) DO UPDATE SET
                stable_version = EXCLUDED.stable_version,
                candidate_version = EXCLUDED.candidate_version,
                candidate_percent = EXCLUDED.candidate_percent,
                candidate_since = EXCLUDED.candidate_since,
                rolled_back_version = EXCLUDED.rolled_back_version,
                rollback_reason = EXCLUDED.rollback_reason,
                updated_at = EXCLUDED.updated_at,
                updated_by = EXCLUDED.updated_by
        """),
        r.__dict__,
    )
    return r


async def adopt_release(db: AsyncSession) -> str | None:
    """On a deploy with a new AGENT_VERSION: the first ever becomes stable; a
    newer one becomes the candidate (unless it was rolled back). Returns what
    changed, for the log."""
    new = settings.AGENT_VERSION
    if not VERSION_RE.match(new):
        return None
    exists = await db.scalar(text("SELECT 1 FROM agent_rollout WHERE id = 1"))
    r = await current(db)
    if not exists:
        await save(db, r, "deploy")
        return f"stable {new}"
    known = {r.stable_version, r.candidate_version, r.rolled_back_version}
    if new in known or parse(new) <= parse(r.stable_version):
        return None
    percent = max(0, min(100, settings.AGENT_CANARY_PERCENT))
    r.candidate_version, r.candidate_percent = new, percent
    r.candidate_since = datetime.now(UTC)
    await save(db, r, "deploy")
    return f"candidate {new} at {percent}%"


async def health_gate(db: AsyncSession, now: datetime) -> str | None:
    """Roll the candidate back when its servers went silent noticeably more
    than the others since it started. Returns the reason when it did."""
    r = await current(db)
    if not r.candidate_version or not r.candidate_percent or r.candidate_since is None:
        return None
    if now - r.candidate_since < GATE_AFTER:
        return None
    rows = (
        await db.execute(
            text("""
                SELECT h.id, t.agent_version_pin FROM hosts h JOIN tenants t ON t.id = h.tenant_id
                 WHERE h.revoked_at IS NULL AND t.status = 'active'
                   AND h.last_seen_at > :since
            """),
            {"since": r.candidate_since - timedelta(hours=1)},
        )
    ).all()
    cohort = [h for h, pin in rows if not pin and bucket(h) < r.candidate_percent]
    others = [h for h, pin in rows if not pin and bucket(h) >= r.candidate_percent]
    if len(cohort) < GATE_MIN_HOSTS:
        return None
    seen = await heartbeats.last_seen(cohort + others)

    def silent_share(ids: list) -> float:
        if not ids:
            return 0.0
        quiet = sum(
            1
            for h in ids
            if (s := seen.get(h)) is None or now.timestamp() - s > SILENT_AFTER.total_seconds()
        )
        return quiet / len(ids)

    bad, base = silent_share(cohort), silent_share(others)
    if bad < GATE_SILENT_SHARE or bad < base + GATE_MARGIN:
        return None
    reason = (
        f"{bad:.0%} of servers offered {r.candidate_version} went silent "
        f"(others: {base:.0%}); rolled back automatically"
    )
    r.rolled_back_version, r.rollback_reason = r.candidate_version, reason
    r.candidate_version, r.candidate_percent, r.candidate_since = None, 0, None
    await save(db, r, "health gate")
    log.warning(reason)
    return reason
