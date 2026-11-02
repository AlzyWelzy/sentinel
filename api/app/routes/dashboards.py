"""Custom dashboards and server comparison.

A dashboard is a named list of panels; each panel compares one metric across
chosen servers (or every server with a tag). /v1/metrics/compare draws one
line per server for any metric.
"""

import time
import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import any_, literal, select
from sqlalchemy.exc import IntegrityError

from app.models import Dashboard, Host
from app.routes.v1 import MetricName
from app.services import metrics
from app.tenancy import Tenant, TenantContext
from app.validation import Trimmed, normalize_tag

router = APIRouter(prefix="/v1", tags=["dashboards"])

MAX_COMPARE = 12
MAX_PANELS = 24


class Panel(BaseModel):
    title: Annotated[str, Trimmed, Field(min_length=1, max_length=100)]
    metric: MetricName
    host_ids: list[uuid.UUID] = Field(default_factory=list, max_length=MAX_COMPARE)
    tag: str | None = None
    width: Literal[1, 2] = 1  # half or full width

    @field_validator("tag")
    @classmethod
    def _tag(cls, v: str | None) -> str | None:
        return None if v is None or not v.strip() else normalize_tag(v)

    @model_validator(mode="after")
    def _scope(self) -> "Panel":
        if self.metric not in metrics.COMPARE:
            raise ValueError(f"{self.metric} can't be compared across servers")
        if not self.host_ids and not self.tag:
            raise ValueError("a panel shows some servers or a tag")
        return self


class DashboardIn(BaseModel):
    name: Annotated[str, Trimmed, Field(min_length=1, max_length=100)]
    panels: list[Panel] = Field(default_factory=list, max_length=MAX_PANELS)


class DashboardOut(DashboardIn):
    id: uuid.UUID
    created_by: str | None
    updated_at: datetime


class CompareSeries(BaseModel):
    host_id: uuid.UUID
    hostname: str
    points: list[list[float]]


class CompareOut(BaseModel):
    metric: str
    unit: str
    series: list[CompareSeries]


def _out(d: Dashboard) -> DashboardOut:
    return DashboardOut(
        id=d.id,
        name=d.name,
        panels=[Panel(**p) for p in d.panels],
        created_by=d.created_by,
        updated_at=d.updated_at,
    )


async def _check_hosts(t: TenantContext, body: DashboardIn) -> None:
    wanted = {h for p in body.panels for h in p.host_ids}
    if not wanted:
        return
    found = set(
        await t.db.scalars(
            select(Host.id).where(Host.tenant_id == t.tenant_id, Host.id.in_(wanted))
        )
    )
    if wanted - found:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Unknown server in a panel")


async def _get(t: TenantContext, dashboard_id: uuid.UUID) -> Dashboard:
    d = await t.db.get(Dashboard, dashboard_id)
    if d is None or d.tenant_id != t.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Dashboard not found")
    return d


@router.get("/dashboards")
async def list_dashboards(t: Tenant) -> list[DashboardOut]:
    rows = await t.db.scalars(
        select(Dashboard).where(Dashboard.tenant_id == t.tenant_id).order_by(Dashboard.name)
    )
    return [_out(d) for d in rows]


@router.post("/dashboards", status_code=status.HTTP_201_CREATED)
async def create_dashboard(body: DashboardIn, t: Tenant) -> DashboardOut:
    await _check_hosts(t, body)
    d = Dashboard(
        tenant_id=t.tenant_id,
        name=body.name.strip(),
        panels=[p.model_dump(mode="json") for p in body.panels],
        created_by=t.principal.email or t.principal.name,
    )
    t.db.add(d)
    try:
        await t.db.flush()
    except IntegrityError:
        raise HTTPException(status.HTTP_409_CONFLICT, "A dashboard with that name exists") from None
    await t.db.refresh(d)
    return _out(d)


@router.get("/dashboards/{dashboard_id}")
async def get_dashboard(dashboard_id: uuid.UUID, t: Tenant) -> DashboardOut:
    return _out(await _get(t, dashboard_id))


@router.put("/dashboards/{dashboard_id}")
async def update_dashboard(dashboard_id: uuid.UUID, body: DashboardIn, t: Tenant) -> DashboardOut:
    d = await _get(t, dashboard_id)
    await _check_hosts(t, body)
    d.name, d.panels = body.name.strip(), [p.model_dump(mode="json") for p in body.panels]
    d.updated_at = datetime.now(UTC)
    try:
        await t.db.flush()
    except IntegrityError:
        raise HTTPException(status.HTTP_409_CONFLICT, "A dashboard with that name exists") from None
    return _out(d)


@router.delete("/dashboards/{dashboard_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_dashboard(dashboard_id: uuid.UUID, t: Tenant) -> None:
    await t.db.delete(await _get(t, dashboard_id))


@router.get("/metrics/compare")
async def compare(
    t: Tenant,
    metric: MetricName,
    host_id: Annotated[list[uuid.UUID] | None, Query()] = None,
    tag: str | None = None,
    start: Annotated[int | None, Query(description="unix seconds; default 1h ago")] = None,
    end: Annotated[int | None, Query(description="unix seconds; default now")] = None,
    step: Annotated[int | None, Query(ge=15, le=86400)] = None,
) -> CompareOut:
    """One line per server: the chosen servers, or every server with a tag."""
    if metric not in metrics.COMPARE:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "This metric can't be compared")
    q = select(Host.id, Host.hostname).where(
        Host.tenant_id == t.tenant_id, Host.revoked_at.is_(None)
    )
    if host_id:
        q = q.where(Host.id.in_(host_id[:MAX_COMPARE]))
    elif tag:
        q = q.where(literal(normalize_tag(tag)) == any_(Host.tags))
    else:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Choose servers or a tag")
    names = {
        r.id: r.hostname for r in await t.db.execute(q.order_by(Host.hostname).limit(MAX_COMPARE))
    }
    unit = metrics.CATALOG[metric].unit
    if not names:
        return CompareOut(metric=metric, unit=unit, series=[])
    end = end or int(time.time())
    start = start or end - 3600
    if start >= end:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "start must be before end")
    step = step or max(60, (end - start) // 300)
    try:
        rows = await metrics.query_compare(t.tenant_id, list(names), metric, start, end, step)
    except metrics.MetricsUnavailable:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "Metrics store unavailable"
        ) from None
    out = []
    for r in rows:
        try:
            hid = uuid.UUID(r["host_id"])
        except ValueError:
            continue
        if hid in names:
            out.append(CompareSeries(host_id=hid, hostname=names[hid], points=r["points"]))
    out.sort(key=lambda s: s.hostname)
    return CompareOut(metric=metric, unit=unit, series=out)
