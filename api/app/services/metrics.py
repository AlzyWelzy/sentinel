"""Reads metrics from VictoriaMetrics, always scoped to one tenant.

Callers never send PromQL. They pick a metric from CATALOG, and the query is
built here from a host id that RLS has already confirmed belongs to them.
On top of that, every query carries `extra_label=tenant_id=<id>`, which makes
VictoriaMetrics add that label to every series selector in the query. So even
a wrong host id can't reach another tenant's series.
"""

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
}


class MetricsUnavailable(Exception):
    pass


async def query_range(
    tenant_id: uuid.UUID, host_id: uuid.UUID, metric: str, start: int, end: int, step: int
) -> list[dict]:
    definition = CATALOG[metric]
    query = definition.query.replace("SEL", _host_matcher(host_id))
    try:
        async with httpx.AsyncClient(base_url=settings.VICTORIAMETRICS_URL) as client:
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
