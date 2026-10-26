"""Reports: availability, incidents, resource use and capacity for a
period, as JSON or CSV; and the monthly report email preference."""

import csv
import io
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select

from app.models import Tenant as TenantRow
from app.services import oncall
from app.services.reports import Summary, build_summary
from app.tenancy import Tenant, TenantContext

router = APIRouter(prefix="/v1/reports")


class ReportSettings(BaseModel):
    monthly_report: bool
    digest: Literal["off", "daily", "weekly"] = "weekly"
    digest_hour: int = Field(default=9, ge=0, le=23, description="in digest_timezone")
    digest_timezone: str = "Asia/Kolkata"

    @field_validator("digest_timezone")
    @classmethod
    def _tz(cls, v: str) -> str:
        if oncall.zone(v).key != v:
            raise ValueError("unknown time zone (use a name like Asia/Kolkata)")
        return v


def _period(start: datetime | None, end: datetime | None, days: int) -> tuple[datetime, datetime]:
    end = end or datetime.now(UTC)
    start = start or end - timedelta(days=days)
    if start >= end:
        raise HTTPException(status_code=422, detail="start must be before end")
    if end - start > timedelta(days=366):
        raise HTTPException(status_code=422, detail="at most one year per report")
    return start, end


async def _summary(
    t: TenantContext, start: datetime | None, end: datetime | None, days: int
) -> Summary:
    a, b = _period(start, end, days)
    return await build_summary(t.db, t.tenant_id, a, b)


@router.get("/summary")
async def summary(
    t: Tenant,
    start: datetime | None = None,
    end: datetime | None = None,
    days: Annotated[int, Query(ge=1, le=366)] = 30,
) -> Summary:
    return await _summary(t, start, end, days)


@router.get("/summary.csv", response_class=PlainTextResponse)
async def summary_csv(
    t: Tenant,
    start: datetime | None = None,
    end: datetime | None = None,
    days: Annotated[int, Query(ge=1, le=366)] = 30,
) -> PlainTextResponse:
    s = await _summary(t, start, end, days)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(
        [
            "type",
            "name",
            "availability_percent",
            "incidents",
            "cpu_avg",
            "cpu_max",
            "memory_avg",
            "memory_max",
            "disk_max",
            "disk_full_in_days",
            "avg_latency_ms",
        ]
    )
    for h in s.hosts:
        w.writerow(
            [
                "server",
                h.hostname,
                h.availability,
                h.incidents,
                h.cpu_avg,
                h.cpu_max,
                h.memory_avg,
                h.memory_max,
                h.disk_max,
                h.disk_full_in_days,
                "",
            ]
        )
    for c in s.checks:
        w.writerow(
            ["check", c.name, c.uptime, c.incidents, "", "", "", "", "", "", c.avg_latency_ms]
        )
    name = f"pulsegrid-report-{s.start:%Y%m%d}-{s.end:%Y%m%d}.csv"
    return PlainTextResponse(
        buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


@router.get("/settings")
async def get_settings(t: Tenant) -> ReportSettings:
    row = await t.db.scalar(select(TenantRow).where(TenantRow.id == t.tenant_id))
    if row is None:
        raise HTTPException(status_code=404, detail="Account not found")
    return ReportSettings.model_validate(
        {
            "monthly_report": row.monthly_report,
            "digest": row.digest,
            "digest_hour": row.digest_hour,
            "digest_timezone": row.digest_timezone,
        }
    )


@router.put("/settings")
async def put_settings(body: ReportSettings, t: Tenant) -> ReportSettings:
    row = await t.db.scalar(select(TenantRow).where(TenantRow.id == t.tenant_id))
    if row is None:
        raise HTTPException(status_code=404, detail="Account not found")
    row.monthly_report = body.monthly_report
    row.digest, row.digest_hour, row.digest_timezone = (
        body.digest,
        body.digest_hour,
        body.digest_timezone,
    )
    return body
