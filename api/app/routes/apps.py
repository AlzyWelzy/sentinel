# ruff: noqa: E501 -- chart queries read best on one line
"""What runs on a host beyond the OS: plugins (MySQL, Redis, …), Docker
containers and custom metrics, with charts for each.

Queries come from fixed tables per plugin type; the only values taken from
the request are a plugin or metric name, matched against what the host
actually reports and quoted, and the host id, which RLS has checked.
"""

import json
import re
import time
import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select

from app.models import Host, HostInventory
from app.routes.ranges import RANGES, Range
from app.services.metrics import MetricsUnavailable, query_instant, query_series
from app.tenancy import Tenant, TenantContext

router = APIRouter(prefix="/v1/hosts")

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
CUSTOM_RE = re.compile(r"^pulsegrid_custom_[a-zA-Z0-9_]{1,150}$")

# [title, query (SEL = the host and plugin matcher), unit, legend labels]
PLUGIN_CHARTS: dict[str, list[tuple[str, str, str, list[str]]]] = {
    "mysql": [
        ("Queries", "rate(pulsegrid_mysql_queries_total{SEL}[2m])", "ops_per_second", []),
        ("Connections", "pulsegrid_mysql_connections{SEL}", "count", []),
        ("Threads running", "pulsegrid_mysql_threads_running{SEL}", "count", []),
        (
            "Slow queries",
            "rate(pulsegrid_mysql_slow_queries_total{SEL}[5m]) * 60",
            "per_minute",
            [],
        ),
        (
            "InnoDB disk reads",
            "rate(pulsegrid_mysql_innodb_disk_reads_total{SEL}[2m])",
            "ops_per_second",
            [],
        ),
        ("Replication lag", "pulsegrid_mysql_replication_lag_seconds{SEL}", "seconds", []),
    ],
    "postgres": [
        (
            "Transactions",
            "sum(rate(pulsegrid_postgres_commits_total{SEL}[2m]) + rate(pulsegrid_postgres_rollbacks_total{SEL}[2m]))",
            "ops_per_second",
            [],
        ),
        ("Connections", "pulsegrid_postgres_connections{SEL}", "count", ["state"]),
        (
            "Cache hit ratio",
            "100 * sum(rate(pulsegrid_postgres_blocks_hit_total{SEL}[5m])) / clamp_min(sum(rate(pulsegrid_postgres_blocks_hit_total{SEL}[5m])) + sum(rate(pulsegrid_postgres_blocks_read_total{SEL}[5m])), 1)",
            "percent",
            [],
        ),
        ("Database size", "pulsegrid_postgres_database_size_bytes{SEL}", "bytes", ["database"]),
        ("Deadlocks", "sum(increase(pulsegrid_postgres_deadlocks_total{SEL}[5m]))", "count", []),
        (
            "Longest transaction",
            "pulsegrid_postgres_longest_transaction_seconds{SEL}",
            "seconds",
            [],
        ),
        ("Replication lag", "pulsegrid_postgres_replication_lag_seconds{SEL}", "seconds", []),
    ],
    "redis": [
        ("Commands", "rate(pulsegrid_redis_commands_total{SEL}[2m])", "ops_per_second", []),
        ("Clients", "pulsegrid_redis_clients{SEL}", "count", []),
        ("Memory used", "pulsegrid_redis_memory_used_bytes{SEL}", "bytes", []),
        (
            "Hit ratio",
            "100 * rate(pulsegrid_redis_keyspace_hits_total{SEL}[5m]) / clamp_min(rate(pulsegrid_redis_keyspace_hits_total{SEL}[5m]) + rate(pulsegrid_redis_keyspace_misses_total{SEL}[5m]), 0.0001)",
            "percent",
            [],
        ),
        ("Keys", "pulsegrid_redis_keys{SEL}", "count", []),
        (
            "Evicted keys",
            "rate(pulsegrid_redis_evicted_keys_total{SEL}[5m]) * 60",
            "per_minute",
            [],
        ),
    ],
    "nginx": [
        ("Requests", "rate(pulsegrid_nginx_requests_total{SEL}[2m])", "ops_per_second", []),
        ("Active connections", "pulsegrid_nginx_connections_active{SEL}", "count", []),
        ("Connections by state", "pulsegrid_nginx_connections{SEL}", "count", ["state"]),
    ],
    "apache": [
        ("Requests", "rate(pulsegrid_apache_requests_total{SEL}[2m])", "ops_per_second", []),
        ("Busy workers", "pulsegrid_apache_workers_busy{SEL}", "count", []),
        ("Idle workers", "pulsegrid_apache_workers_idle{SEL}", "count", []),
        (
            "Traffic",
            "rate(pulsegrid_apache_sent_kilobytes_total{SEL}[2m]) * 1024",
            "bytes_per_second",
            [],
        ),
    ],
    "docker": [
        (
            "Container CPU",
            "rate(pulsegrid_container_cpu_seconds_total{SEL}[2m]) * 100",
            "percent",
            ["container"],
        ),
        ("Container memory", "pulsegrid_container_memory_bytes{SEL}", "bytes", ["container"]),
        ("Containers by state", "pulsegrid_containers{SEL}", "count", ["state"]),
    ],
}


class PluginOut(BaseModel):
    name: str
    type: str
    ok: bool | None
    error: str | None = None
    charts: list[str]


class ChartOut(BaseModel):
    title: str
    unit: str
    series: list[dict]


class ContainerOut(BaseModel):
    name: str
    image: str | None
    running: bool
    cpu_percent: float | None
    memory_bytes: float | None
    memory_percent: float | None


async def _host(t: TenantContext, host_id: uuid.UUID) -> Host:
    host = await t.db.scalar(select(Host).where(Host.id == host_id, Host.tenant_id == t.tenant_id))
    if host is None:
        raise HTTPException(status_code=404, detail="Host not found")
    return host


def _sel(host_id: uuid.UUID, plugin: str | None = None) -> str:
    sel = f'host_id="{uuid.UUID(str(host_id))}"'
    if plugin is not None:
        sel += f",plugin={json.dumps(plugin)}"
    return sel


@router.get("/{host_id}/plugins")
async def plugins(host_id: uuid.UUID, t: Tenant) -> list[PluginOut]:
    """Plugins configured on the host and whether their last run worked."""
    host = await _host(t, host_id)
    try:
        up = await query_instant(
            t.tenant_id, f"last_over_time(pulsegrid_plugin_up{{{_sel(host.id)}}}[5m])"
        )
    except MetricsUnavailable:
        up = []
    errors: dict[str, str] = {}
    inv = await t.db.scalar(select(HostInventory).where(HostInventory.host_id == host.id))
    for p in ((inv.data or {}).get("plugins") or []) if inv else []:
        if p.get("error"):
            errors[p.get("name", "")] = p["error"]
    out = [
        PluginOut(
            name=labels.get("plugin", ""),
            type=labels.get("type", ""),
            ok=v >= 1,
            error=errors.get(labels.get("plugin", "")) if v < 1 else None,
            charts=[c[0] for c in PLUGIN_CHARTS.get(labels.get("type", ""), [])],
        )
        for labels, v in up
    ]
    # Plugin files the agent couldn't load at all.
    for name, err in errors.items():
        if name == "config":
            out.append(PluginOut(name="config", type="invalid", ok=False, error=err, charts=[]))
    return sorted(out, key=lambda p: p.name)


@router.get("/{host_id}/plugins/{plugin}/metrics")
async def plugin_metrics(
    host_id: uuid.UUID,
    plugin: str,
    t: Tenant,
    type_: Annotated[str, Query(alias="type")],
    range_: Annotated[Range, Query(alias="range")] = "1h",
) -> list[ChartOut]:
    if not NAME_RE.match(plugin) or type_ not in PLUGIN_CHARTS:
        raise HTTPException(status_code=422, detail="unknown plugin")
    host = await _host(t, host_id)
    seconds, step = RANGES[range_]
    end = int(time.time())
    sel = _sel(host.id, plugin)
    out = []
    try:
        for title, query, unit, legend in PLUGIN_CHARTS[type_]:
            series = await query_series(
                t.tenant_id, query.replace("SEL", sel), end - seconds, end, step, legend
            )
            out.append(ChartOut(title=title, unit=unit, series=series))
    except MetricsUnavailable:
        raise HTTPException(status_code=503, detail="metrics store unavailable") from None
    return out


@router.get("/{host_id}/containers")
async def containers(host_id: uuid.UUID, t: Tenant) -> list[ContainerOut]:
    host = await _host(t, host_id)
    sel = _sel(host.id)
    try:
        running = await query_instant(
            t.tenant_id, f"last_over_time(pulsegrid_container_running{{{sel}}}[3m])"
        )
        cpu = await query_instant(
            t.tenant_id, f"rate(pulsegrid_container_cpu_seconds_total{{{sel}}}[2m]) * 100"
        )
        mem = await query_instant(
            t.tenant_id, f"last_over_time(pulsegrid_container_memory_bytes{{{sel}}}[3m])"
        )
        memp = await query_instant(
            t.tenant_id, f"last_over_time(pulsegrid_container_memory_percent{{{sel}}}[3m])"
        )
    except MetricsUnavailable:
        raise HTTPException(status_code=503, detail="metrics store unavailable") from None

    def by_name(rows: list[tuple[dict[str, str], float]]) -> dict[str, float]:
        return {labels.get("container", ""): v for labels, v in rows}

    c, m, mp = by_name(cpu), by_name(mem), by_name(memp)
    out = [
        ContainerOut(
            name=labels.get("container", ""),
            image=labels.get("image"),
            running=v >= 1,
            cpu_percent=round(c[name], 2) if (name := labels.get("container", "")) in c else None,
            memory_bytes=m.get(name),
            memory_percent=round(mp[name], 2) if name in mp else None,
        )
        for labels, v in running
    ]
    return sorted(out, key=lambda x: (not x.running, x.name))


class CustomMetricOut(BaseModel):
    name: str
    series: int


@router.get("/{host_id}/custom-metrics")
async def custom_metrics(host_id: uuid.UUID, t: Tenant) -> list[CustomMetricOut]:
    """Metric names from script and Prometheus plugins on this host."""
    host = await _host(t, host_id)
    try:
        rows = await query_instant(
            t.tenant_id,
            f'count by (__name__) (last_over_time({{__name__=~"pulsegrid_custom_.+",{_sel(host.id)}}}[10m]))',
        )
    except MetricsUnavailable:
        raise HTTPException(status_code=503, detail="metrics store unavailable") from None
    return sorted(
        (CustomMetricOut(name=labels.get("__name__", ""), series=int(v)) for labels, v in rows),
        key=lambda m: m.name,
    )[:500]


@router.get("/{host_id}/custom-metrics/{name}")
async def custom_metric(
    host_id: uuid.UUID,
    name: str,
    t: Tenant,
    range_: Annotated[Range, Query(alias="range")] = "1h",
) -> ChartOut:
    if not CUSTOM_RE.match(name):
        raise HTTPException(status_code=422, detail="not a custom metric")
    host = await _host(t, host_id)
    seconds, step = RANGES[range_]
    end = int(time.time())
    try:
        series = await query_series(
            t.tenant_id, f"{name}{{{_sel(host.id)}}}", end - seconds, end, step, ["plugin", "*"]
        )
    except MetricsUnavailable:
        raise HTTPException(status_code=503, detail="metrics store unavailable") from None
    return ChartOut(title=name.removeprefix("pulsegrid_custom_"), unit="value", series=series)
