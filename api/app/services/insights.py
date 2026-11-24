"""Insights: what the monitoring data says you should change.

- Noisy rules: rules that fire a lot, flap, or resolve on their own within
  minutes (nobody needed to act), with a concrete suggestion for each.
- Response: how fast incidents are acknowledged and resolved.
- Rightsizing: servers that are much bigger or smaller than their load,
  from seven days of CPU and memory.
- SLOs: each check's availability against its target, the error budget
  left, and how fast it's being spent.
"""

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AlertRule, Check, Host, Incident
from app.services.metrics import MetricsUnavailable, query_instant

QUICK_RESOLVE = timedelta(minutes=5)
SLO_TYPES = ("http", "tcp", "tls", "dns", "ping")


@dataclass
class RuleInsight:
    rule_id: uuid.UUID | None
    rule_name: str
    incidents: int
    flapping: int
    self_resolved_quickly: int
    mtta_seconds: float | None
    mttr_seconds: float | None
    last_opened_at: datetime
    advice: str | None


@dataclass
class HostInsight:
    host_id: uuid.UUID
    hostname: str
    cpu_cores: int | None
    memory_bytes: int | None
    cpu_avg: float | None
    cpu_p95: float | None
    memory_avg: float | None
    memory_max: float | None
    verdict: str  # oversized, undersized, ok, unknown
    advice: str | None


@dataclass
class SloInsight:
    check_id: uuid.UUID
    name: str
    target: float
    availability: float | None
    budget_minutes: float
    budget_used_minutes: float | None
    budget_left_percent: float | None
    burn_rate_1h: float | None
    status: str  # healthy, at_risk, breached, unknown


@dataclass
class DependencySuggestion:
    """Servers that keep going quiet together. With an upstream: it was
    down in most of those outages and usually first, so making the others
    depend on it holds their alerts back while it's down. Without one: a
    group with no server of ours in front of it (a router, a NAT, a link)."""

    host_ids: list[uuid.UUID]
    hostnames: list[str]
    together: int
    upstream_host_id: uuid.UUID | None = None
    upstream_hostname: str | None = None


@dataclass
class Insights:
    days: int
    incidents: int = 0
    mtta_seconds: float | None = None
    mttr_seconds: float | None = None
    self_resolved_quickly: int = 0
    rules: list[RuleInsight] = field(default_factory=list)
    hosts: list[HostInsight] = field(default_factory=list)
    slos: list[SloInsight] = field(default_factory=list)
    dependencies: list[DependencySuggestion] = field(default_factory=list)
    metrics_available: bool = True


TOGETHER_WINDOW = timedelta(minutes=3)
MIN_TOGETHER = 3


def outage_groups(
    events: list[tuple[uuid.UUID, datetime]], window: timedelta = TOGETHER_WINDOW
) -> list[list[uuid.UUID]]:
    """Not-reporting starts that fall within `window` of the previous one,
    in the order they went down; groups of two or more servers."""
    groups: list[list[uuid.UUID]] = []
    cur: list[uuid.UUID] = []
    last: datetime | None = None
    for host, at in sorted(events, key=lambda e: e[1]):
        if last is not None and at - last > window:
            if len(set(cur)) > 1:
                groups.append(cur)
            cur = []
        if host not in cur:
            cur.append(host)
        last = at
    if len(set(cur)) > 1:
        groups.append(cur)
    return groups


def suggest_dependencies(
    groups: list[list[uuid.UUID]],
    depends_on: dict[uuid.UUID, uuid.UUID | None],
    min_together: int = MIN_TOGETHER,
) -> list[tuple[list[uuid.UUID], int, uuid.UUID | None]]:
    """(servers to give a dependency, outages together, upstream or None).

    Two servers are linked when they went down together at least
    `min_together` times; each linked cluster is one suggestion. Its
    upstream is the member that was down in nearly all of the cluster's
    outages and went first in most of them. Servers that already have a
    dependency (or a poller) are left alone."""
    pairs: dict[frozenset[uuid.UUID], int] = {}
    for g in groups:
        members = sorted(set(g), key=str)
        for i, x in enumerate(members):
            for y in members[i + 1 :]:
                k = frozenset((x, y))
                pairs[k] = pairs.get(k, 0) + 1
    linked: dict[uuid.UUID, set[uuid.UUID]] = {}
    for k, n in pairs.items():
        if n >= min_together:
            x, y = tuple(k)
            linked.setdefault(x, set()).add(y)
            linked.setdefault(y, set()).add(x)
    out: list[tuple[list[uuid.UUID], int, uuid.UUID | None]] = []
    seen: set[uuid.UUID] = set()
    for start in sorted(linked, key=str):
        if start in seen:
            continue
        cluster, todo = set(), [start]
        while todo:
            h = todo.pop()
            if h not in cluster:
                cluster.add(h)
                todo.extend(linked[h] - cluster)
        seen |= cluster
        outages = [g for g in groups if len(cluster.intersection(g)) >= 2]
        present: dict[uuid.UUID, int] = {}
        first: dict[uuid.UUID, int] = {}
        for g in outages:
            for h in cluster.intersection(g):
                present[h] = present.get(h, 0) + 1
            lead = next(h for h in g if h in cluster)
            first[lead] = first.get(lead, 0) + 1
        upstream = None
        if first:
            lead, n = max(first.items(), key=lambda kv: (kv[1], str(kv[0])))
            if n * 2 > len(outages) and present.get(lead, 0) * 10 >= len(outages) * 9:
                upstream = lead
        followers = sorted((h for h in cluster if h != upstream and not depends_on.get(h)), key=str)
        if followers:
            out.append((followers, len(outages), upstream))
    out.sort(key=lambda s: (-s[1], -len(s[0])))
    return out


def rule_advice(incidents: int, flapping: int, quick: int, days: int) -> str | None:
    """One sentence a person can act on, or None for a rule that's fine."""
    if incidents == 0:
        return None
    if flapping and flapping * 3 >= incidents:
        return "Flaps often: set a recovery threshold a little past the trigger so it settles."
    if quick * 2 >= incidents and incidents >= 3:
        return (
            f"{quick} of {incidents} cleared by themselves within 5 minutes: "
            "raise the duration so short spikes don't page anyone."
        )
    if incidents / max(days, 1) >= 3:
        return "Fires several times a day: raise the threshold, or fix the cause and keep it."
    return None


def host_verdict(
    cpu_p95: float | None, mem_max: float | None, cores: int | None, mem_bytes: int | None
) -> tuple[str, str | None]:
    if cpu_p95 is None or mem_max is None:
        return "unknown", None
    if cpu_p95 >= 85 or mem_max >= 92:
        what = "CPU" if cpu_p95 >= 85 else "memory"
        return "undersized", f"Runs out of {what} at busy times: move to a larger plan."
    if cpu_p95 < 20 and mem_max < 45 and (cores or 0) >= 2:
        smaller = []
        if cores and cores >= 2:
            smaller.append(f"{max(1, cores // 2)} vCPU")
        if mem_bytes and mem_bytes >= 2 * 1024**3:
            smaller.append(f"{round(mem_bytes / 2 / 1024**3)} GB RAM")
        hint = f" (about {', '.join(smaller)})" if smaller else ""
        return "oversized", f"Busy hours use under 20% CPU: a plan half the size would do{hint}."
    return "ok", None


def slo_numbers(
    target: float, availability: float | None, days: int, recent: float | None
) -> tuple[float, float | None, float | None, float | None, str]:
    """Error budget in minutes for the period, minutes spent, percent left,
    and the last hour's burn rate (1 = spending exactly on budget)."""
    budget = (100 - target) / 100 * days * 24 * 60
    if availability is None:
        return budget, None, None, None, "unknown"
    used = (100 - availability) / 100 * days * 24 * 60
    left = 100.0 if budget <= 0 else max(-999.0, (budget - used) / budget * 100)
    burn = None
    if recent is not None and target < 100:
        burn = round((100 - recent) / (100 - target), 2)
    status = "breached" if left < 0 else "at_risk" if left < 25 or (burn or 0) >= 6 else "healthy"
    return budget, used, left, burn, status


async def build(db: AsyncSession, tenant_id: uuid.UUID, days: int) -> Insights:
    out = Insights(days=days)
    since = datetime.now(UTC) - timedelta(days=days)
    in_period = (Incident.tenant_id == tenant_id) & (Incident.opened_at >= since)
    quick = (
        (Incident.resolved_at.is_not(None))
        & (Incident.acknowledged_at.is_(None))
        & (Incident.resolved_by.is_(None))
        & ((Incident.resolved_at - Incident.opened_at) <= QUICK_RESOLVE)
    )
    row = (
        await db.execute(
            select(
                func.count(),
                func.avg(func.extract("epoch", Incident.acknowledged_at - Incident.opened_at)),
                func.avg(func.extract("epoch", Incident.resolved_at - Incident.opened_at)),
                func.count().filter(quick),
            ).where(in_period)
        )
    ).one()
    out.incidents = row[0] or 0
    out.mtta_seconds = float(row[1]) if row[1] is not None else None
    out.mttr_seconds = float(row[2]) if row[2] is not None else None
    out.self_resolved_quickly = row[3] or 0
    for r in await db.execute(
        select(
            Incident.rule_id,
            Incident.rule_name,
            func.count(),
            func.count().filter(Incident.flapping),
            func.count().filter(quick),
            func.avg(func.extract("epoch", Incident.acknowledged_at - Incident.opened_at)),
            func.avg(func.extract("epoch", Incident.resolved_at - Incident.opened_at)),
            func.max(Incident.opened_at),
        )
        .where(in_period)
        .group_by(Incident.rule_id, Incident.rule_name)
        .order_by(func.count().desc())
        .limit(15)
    ):
        out.rules.append(
            RuleInsight(
                rule_id=r[0],
                rule_name=r[1],
                incidents=r[2],
                flapping=r[3],
                self_resolved_quickly=r[4],
                mtta_seconds=float(r[5]) if r[5] is not None else None,
                mttr_seconds=float(r[6]) if r[6] is not None else None,
                last_opened_at=r[7],
                advice=rule_advice(r[2], r[3], r[4], days),
            )
        )

    hosts = list(
        await db.scalars(
            select(Host)
            .where(
                Host.tenant_id == tenant_id, Host.revoked_at.is_(None), Host.probe_region.is_(None)
            )
            .order_by(Host.hostname)
        )
    )
    # SLOs are about availability: file and log checks answer other questions.
    checks = list(
        await db.scalars(
            select(Check)
            .where(Check.tenant_id == tenant_id, Check.type.in_(SLO_TYPES))
            .order_by(Check.name)
        )
    )
    metrics: dict[str, dict[str, float]] = {}
    up: dict[str, float] = {}
    up_1h: dict[str, float] = {}

    async def by(label: str, query: str) -> dict[str, float]:
        return {lbl.get(label, ""): v for lbl, v in await query_instant(tenant_id, query)}

    try:
        metrics["cpu_avg"] = await by("host_id", "avg_over_time(sentinel_cpu_usage_percent[7d])")
        metrics["cpu_p95"] = await by(
            "host_id", "quantile_over_time(0.95, sentinel_cpu_usage_percent[7d])"
        )
        metrics["mem_avg"] = await by("host_id", "avg_over_time(sentinel_memory_used_percent[7d])")
        metrics["mem_max"] = await by("host_id", "max_over_time(sentinel_memory_used_percent[7d])")
        if checks:
            up = await by(
                "check_id", f"avg by (check_id) (avg_over_time(sentinel_check_up[{days}d])) * 100"
            )
            up_1h = await by(
                "check_id", "avg by (check_id) (avg_over_time(sentinel_check_up[1h])) * 100"
            )
    except MetricsUnavailable:
        out.metrics_available = False

    def r(v: float | None, n: int = 1) -> float | None:
        return round(v, n) if v is not None else None

    for h in hosts:
        k = str(h.id)
        p95, mem_max = metrics.get("cpu_p95", {}).get(k), metrics.get("mem_max", {}).get(k)
        verdict, advice = host_verdict(p95, mem_max, h.cpu_cores, h.memory_bytes)
        out.hosts.append(
            HostInsight(
                host_id=h.id,
                hostname=h.hostname,
                cpu_cores=h.cpu_cores,
                memory_bytes=h.memory_bytes,
                cpu_avg=r(metrics.get("cpu_avg", {}).get(k)),
                cpu_p95=r(p95),
                memory_avg=r(metrics.get("mem_avg", {}).get(k)),
                memory_max=r(mem_max),
                verdict=verdict,
                advice=advice,
            )
        )
    for c in checks:
        target = float(c.slo_target)
        availability = up.get(str(c.id))
        budget, used, left, burn, state = slo_numbers(
            target, availability, days, up_1h.get(str(c.id))
        )
        out.slos.append(
            SloInsight(
                check_id=c.id,
                name=c.name,
                target=target,
                availability=r(availability, 3),
                budget_minutes=round(budget, 1),
                budget_used_minutes=r(used),
                budget_left_percent=r(left),
                burn_rate_1h=burn,
                status=state,
            )
        )
    out.dependencies = await dependency_suggestions(db, tenant_id, since)
    return out


async def dependency_suggestions(
    db: AsyncSession, tenant_id: uuid.UUID, since: datetime
) -> list[DependencySuggestion]:
    events = [
        (r[0], r[1])
        for r in await db.execute(
            select(Incident.host_id, Incident.opened_at)
            .join(AlertRule, AlertRule.id == Incident.rule_id)
            .where(
                Incident.tenant_id == tenant_id,
                Incident.opened_at >= since,
                Incident.host_id.is_not(None),
                AlertRule.kind == "host_down",
            )
        )
    ]
    groups = outage_groups(events)
    if not groups:
        return []
    ids = {x for g in groups for x in g}
    hosts = {
        h.id: h
        for h in await db.scalars(select(Host).where(Host.tenant_id == tenant_id, Host.id.in_(ids)))
    }
    deps = {hid: h.depends_on_host_id or h.poller_host_id for hid, h in hosts.items()}
    out = []
    for followers, together, upstream in suggest_dependencies(groups, deps):
        followers = [f for f in followers if f in hosts]
        if not followers:
            continue
        up = hosts.get(upstream) if upstream else None
        out.append(
            DependencySuggestion(
                host_ids=followers,
                hostnames=[hosts[f].hostname for f in followers],
                together=together,
                upstream_host_id=up.id if up else None,
                upstream_hostname=up.hostname if up else None,
            )
        )
    return out[:10]
