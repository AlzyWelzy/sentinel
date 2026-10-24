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
    query: str  # {sel} is replaced with the host's label selector
    unit: str
    legend: list[str]  # labels that tell the returned series apart


CATALOG: dict[str, MetricDef] = {
    "cpu": MetricDef("pulsegrid_cpu_usage_percent{sel}", "percent", []),
    "memory": MetricDef("pulsegrid_memory_used_percent{sel}", "percent", []),
    "swap": MetricDef("pulsegrid_swap_used_percent{sel}", "percent", []),
    "disk": MetricDef("pulsegrid_disk_used_percent{sel}", "percent", ["mountpoint"]),
    "load": MetricDef("pulsegrid_load{sel}", "load", ["period"]),
    "network": MetricDef(
        "sum by (direction) (rate(pulsegrid_network_bytes_total{sel}[2m]))",
        "bytes_per_second",
        ["direction"],
    ),
}


class MetricsUnavailable(Exception):
    pass


async def query_range(
    tenant_id: uuid.UUID, host_id: uuid.UUID, metric: str, start: int, end: int, step: int
) -> list[dict]:
    definition = CATALOG[metric]
    # host_id is a UUID object, so it can't carry anything but hex and dashes.
    query = definition.query.replace("{sel}", f'{{host_id="{host_id}"}}')
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
