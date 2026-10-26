"""Reads metrics from VictoriaMetrics, always scoped to one tenant.

Callers never send PromQL. They pick a metric from CATALOG, and the query is
built here from a host id that RLS has already confirmed belongs to them.
On top of that, every query carries `extra_label=tenant_id=<id>`, which makes
VictoriaMetrics add that label to every series selector in the query. So even
a wrong host id can't reach another tenant's series.
"""

import time
import uuid
from dataclasses import dataclass

import httpx

from app.config import settings


@dataclass(frozen=True)
class MetricDef:
    query: str  # SEL is replaced with the host's label matcher (host_id="...")
    unit: str
    legend: list[str]  # labels that tell the returned series apart


def _read_write(read: str, write: str) -> str:
    """Two counters as one rate series per direction (MetricsQL label_set)."""
    return (
        f'sum by (direction) (label_set(rate({read}{{SEL}}[2m]), "direction", "read") '
        f'or label_set(rate({write}{{SEL}}[2m]), "direction", "write"))'
    )


CATALOG: dict[str, MetricDef] = {
    "cpu": MetricDef("pulsegrid_cpu_usage_percent{SEL}", "percent", []),
    # Where CPU time goes, idle left out so the busy modes are readable.
    "cpu_modes": MetricDef('pulsegrid_cpu_mode_percent{SEL,mode!="idle"}', "percent", ["mode"]),
    "cpu_cores": MetricDef("pulsegrid_cpu_core_usage_percent{SEL}", "percent", ["core"]),
    "memory": MetricDef("pulsegrid_memory_used_percent{SEL}", "percent", []),
    "swap": MetricDef("pulsegrid_swap_used_percent{SEL}", "percent", []),
    "disk": MetricDef("pulsegrid_disk_used_percent{SEL}", "percent", ["mountpoint"]),
    "inodes": MetricDef("pulsegrid_disk_inodes_used_percent{SEL}", "percent", ["mountpoint"]),
    "disk_io": MetricDef(
        _read_write("pulsegrid_disk_read_bytes_total", "pulsegrid_disk_written_bytes_total"),
        "bytes_per_second",
        ["direction"],
    ),
    "disk_iops": MetricDef(
        _read_write("pulsegrid_disk_reads_total", "pulsegrid_disk_writes_total"),
        "ops_per_second",
        ["direction"],
    ),
    "disk_busy": MetricDef(
        "rate(pulsegrid_disk_io_time_seconds_total{SEL}[2m]) * 100", "percent", ["device"]
    ),
    "load": MetricDef("pulsegrid_load{SEL}", "load", ["period"]),
    "network": MetricDef(
        "sum by (direction) (rate(pulsegrid_network_bytes_total{SEL}[2m]))",
        "bytes_per_second",
        ["direction"],
    ),
    "processes": MetricDef("pulsegrid_processes_total{SEL}", "count", []),
    # Where memory goes, and paging.
    "memory_breakdown": MetricDef(
        'pulsegrid_memory_bytes{SEL,kind=~"used|cached|buffers|free"}', "bytes", ["kind"]
    ),
    "swap_io": MetricDef(
        "sum by (direction) (rate(pulsegrid_swap_io_bytes_total{SEL}[2m]))",
        "bytes_per_second",
        ["direction"],
    ),
    "page_faults": MetricDef(
        "sum by (kind) (rate(pulsegrid_memory_page_faults_total{SEL}[2m]))",
        "ops_per_second",
        ["kind"],
    ),
    # Average time per read and write, and how many requests wait.
    "disk_latency": MetricDef(
        "label_set(sum(rate(pulsegrid_disk_read_time_seconds_total{SEL}[2m])) * 1000 / "
        'clamp_min(sum(rate(pulsegrid_disk_reads_total{SEL}[2m])), 0.001), "op", "read") or '
        "label_set(sum(rate(pulsegrid_disk_write_time_seconds_total{SEL}[2m])) * 1000 / "
        'clamp_min(sum(rate(pulsegrid_disk_writes_total{SEL}[2m])), 0.001), "op", "write")',
        "ms",
        ["op"],
    ),
    "disk_queue": MetricDef(
        "sum(rate(pulsegrid_disk_weighted_io_seconds_total{SEL}[2m]))", "count", []
    ),
    "network_interfaces": MetricDef(
        "sum by (interface, direction) (rate(pulsegrid_network_bytes_total{SEL}[2m]))",
        "bytes_per_second",
        ["interface", "direction"],
    ),
    "network_packets": MetricDef(
        "sum by (direction) (rate(pulsegrid_network_packets_total{SEL}[2m]))",
        "ops_per_second",
        ["direction"],
    ),
    "network_errors": MetricDef(
        'label_set(sum(rate(pulsegrid_network_errors_total{SEL}[2m])), "what", "errors") or '
        'label_set(sum(rate(pulsegrid_network_drops_total{SEL}[2m])), "what", "drops")',
        "ops_per_second",
        ["what"],
    ),
    "tcp_connections": MetricDef("pulsegrid_tcp_connections{SEL}", "count", ["state"]),
    "context_switches": MetricDef(
        'label_set(rate(pulsegrid_context_switches_total{SEL}[2m]), "what", "context switches") or '
        'label_set(rate(pulsegrid_interrupts_total{SEL}[2m]), "what", "interrupts")',
        "ops_per_second",
        ["what"],
    ),
    "proc_states": MetricDef("pulsegrid_procs{SEL}", "count", ["state"]),
    "threads": MetricDef("pulsegrid_threads_total{SEL}", "count", []),
    "pressure": MetricDef(
        'pulsegrid_pressure_percent{SEL,window="60"}', "percent", ["resource", "kind"]
    ),
    "users_logged_in": MetricDef("pulsegrid_users_logged_in{SEL}", "count", []),
    "user_cpu": MetricDef("pulsegrid_user_cpu_percent{SEL}", "percent", ["user"]),
    "user_memory": MetricDef("pulsegrid_user_memory_bytes{SEL}", "bytes", ["user"]),
    "process_cpu": MetricDef("pulsegrid_process_cpu_percent{SEL}", "percent", ["process"]),
    "process_memory": MetricDef("pulsegrid_process_memory_bytes{SEL}", "bytes", ["process"]),
}


# One line per server, for comparing servers: each metric folded to a single
# value per host (the fullest disk, total network, CPU busy time...).
COMPARE: dict[str, str] = {
    "cpu": "max by (host_id) (pulsegrid_cpu_usage_percent{SEL})",
    "cpu_modes": 'sum by (host_id) (pulsegrid_cpu_mode_percent{SEL,mode!="idle"})',
    "cpu_cores": "max by (host_id) (pulsegrid_cpu_core_usage_percent{SEL})",
    "memory": "max by (host_id) (pulsegrid_memory_used_percent{SEL})",
    "swap": "max by (host_id) (pulsegrid_swap_used_percent{SEL})",
    "disk": "max by (host_id) (pulsegrid_disk_used_percent{SEL})",
    "inodes": "max by (host_id) (pulsegrid_disk_inodes_used_percent{SEL})",
    "disk_io": (
        "sum by (host_id) (rate(pulsegrid_disk_read_bytes_total{SEL}[2m])) + "
        "sum by (host_id) (rate(pulsegrid_disk_written_bytes_total{SEL}[2m]))"
    ),
    "disk_iops": (
        "sum by (host_id) (rate(pulsegrid_disk_reads_total{SEL}[2m])) + "
        "sum by (host_id) (rate(pulsegrid_disk_writes_total{SEL}[2m]))"
    ),
    "disk_busy": "max by (host_id) (rate(pulsegrid_disk_io_time_seconds_total{SEL}[2m]) * 100)",
    "load": 'max by (host_id) (pulsegrid_load{SEL,period="1m"})',
    "network": "sum by (host_id) (rate(pulsegrid_network_bytes_total{SEL}[2m]))",
    "processes": "max by (host_id) (pulsegrid_processes_total{SEL})",
}


class MetricsUnavailable(Exception):
    pass


def _source(query: str, start: int, end: int, step: int) -> tuple[str, str, int]:
    """Where to read a range from: the raw store, or for ranges older than
    raw retention or longer than a month, the hourly rollups (with rate
    windows widened to cover hourly samples)."""
    long_url = settings.VICTORIAMETRICS_LONG_URL
    raw_from = time.time() - (settings.RAW_RETENTION_DAYS - 1) * 86400
    if long_url and (start < raw_from or end - start > 31 * 86400):
        return long_url, query.replace("[2m]", "[2h]").replace("[3m]", "[2h]"), max(step, 3600)
    return settings.VICTORIAMETRICS_URL, query, step


async def query_range(
    tenant_id: uuid.UUID, host_id: uuid.UUID, metric: str, start: int, end: int, step: int
) -> list[dict]:
    definition = CATALOG[metric]
    base, query, step = _source(
        definition.query.replace("SEL", _host_matcher(host_id)), start, end, step
    )
    try:
        async with httpx.AsyncClient(base_url=base) as client:
            response = await client.get(
                "/api/v1/query_range",
                params={
                    "query": query,
                    "start": start,
                    "end": end,
                    "step": step,
                    "extra_label": f"tenant_id={tenant_id}",
                },
                timeout=15,
            )
            response.raise_for_status()
    except httpx.HTTPError as exc:
        raise MetricsUnavailable(str(exc)) from exc

    series = []
    for result in response.json()["data"]["result"]:
        labels = result["metric"]
        series.append(
            {
                "labels": {k: labels[k] for k in definition.legend if k in labels},
                "points": [[int(ts), float(v)] for ts, v in result["values"]],
            }
        )
    return series


def _host_matcher(host_id: uuid.UUID) -> str:
    # host_id is a UUID object, so it can't carry anything but hex and dashes.
    return f'host_id="{uuid.UUID(str(host_id))}"'


async def query_latest(
    tenant_id: uuid.UUID, host_id: uuid.UUID, metric_name: str, window: str = "3m"
) -> list[tuple[dict[str, str], float]]:
    """The newest value of each series of one raw metric for a host, as
    (labels, value). metric_name comes from code, never from a request."""
    query = f"last_over_time({metric_name}{{{_host_matcher(host_id)}}}[{window}])"
    try:
        async with httpx.AsyncClient(base_url=settings.VICTORIAMETRICS_URL) as client:
            response = await client.get(
                "/api/v1/query",
                params={"query": query, "extra_label": f"tenant_id={tenant_id}"},
                timeout=15,
            )
            response.raise_for_status()
    except httpx.HTTPError as exc:
        raise MetricsUnavailable(str(exc)) from exc
    return [(r["metric"], float(r["value"][1])) for r in response.json()["data"]["result"]]


async def delete_host_series(tenant_id: uuid.UUID, host_id: uuid.UUID) -> None:
    """Drop a deleted host's metrics. The tenant matcher keeps this from ever
    touching another tenant's data, even with a wrong host id."""
    try:
        async with httpx.AsyncClient(base_url=settings.VICTORIAMETRICS_URL) as client:
            response = await client.post(
                "/api/v1/admin/tsdb/delete_series",
                params={"match[]": f'{{tenant_id="{tenant_id}",host_id="{host_id}"}}'},
                timeout=30,
            )
            response.raise_for_status()
    except httpx.HTTPError as exc:
        raise MetricsUnavailable(str(exc)) from exc


async def query_instant(tenant_id: uuid.UUID, query: str) -> list[tuple[dict[str, str], float]]:
    """Run a query built in code (never from a request) for one tenant."""
    try:
        async with httpx.AsyncClient(base_url=settings.VICTORIAMETRICS_URL) as client:
            response = await client.get(
                "/api/v1/query",
                params={"query": query, "extra_label": f"tenant_id={tenant_id}"},
                timeout=20,
            )
            response.raise_for_status()
    except httpx.HTTPError as exc:
        raise MetricsUnavailable(str(exc)) from exc
    out = []
    for r in response.json()["data"]["result"]:
        try:
            out.append((r["metric"], float(r["value"][1])))
        except (TypeError, ValueError):
            continue
    return out


async def query_series(
    tenant_id: uuid.UUID, query: str, start: int, end: int, step: int, legend: list[str]
) -> list[dict]:
    """A range query built in code, for one tenant, as chart series."""
    base, query, step = _source(query, start, end, step)
    try:
        async with httpx.AsyncClient(base_url=base) as client:
            response = await client.get(
                "/api/v1/query_range",
                params={
                    "query": query,
                    "start": start,
                    "end": end,
                    "step": step,
                    "extra_label": f"tenant_id={tenant_id}",
                },
                timeout=20,
            )
            response.raise_for_status()
    except httpx.HTTPError as exc:
        raise MetricsUnavailable(str(exc)) from exc

    def labels(metric: dict[str, str]) -> dict[str, str]:
        # "*" in legend: every label except the ones the platform sets.
        if "*" in legend:
            return {
                k: v for k, v in metric.items() if k not in ("__name__", "tenant_id", "host_id")
            }
        return {k: metric[k] for k in legend if k in metric}

    return [
        {
            "labels": labels(r["metric"]),
            "points": [[int(ts), float(v)] for ts, v in r["values"]],
        }
        for r in response.json()["data"]["result"]
    ]


async def query_compare(
    tenant_id: uuid.UUID, host_ids: list[uuid.UUID], metric: str, start: int, end: int, step: int
) -> list[dict]:
    """One series per host: {host_id, points}."""
    ids = "|".join(str(uuid.UUID(str(h))) for h in host_ids)
    base, query, step = _source(
        COMPARE[metric].replace("SEL", f'host_id=~"{ids}"'), start, end, step
    )
    try:
        async with httpx.AsyncClient(base_url=base) as client:
            response = await client.get(
                "/api/v1/query_range",
                params={
                    "query": query,
                    "start": start,
                    "end": end,
                    "step": step,
                    "extra_label": f"tenant_id={tenant_id}",
                },
                timeout=15,
            )
            response.raise_for_status()
    except httpx.HTTPError as exc:
        raise MetricsUnavailable(str(exc)) from exc
    return [
        {
            "host_id": r["metric"].get("host_id", ""),
            "points": [[int(ts), float(v)] for ts, v in r["values"]],
        }
        for r in response.json()["data"]["result"]
    ]
