"""Reports: availability, incidents, resource use and capacity for a
period, as JSON or CSV; and the monthly report email preference."""

import csv
import io
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select

from app.models import Host
from app.models import Tenant as TenantRow
from app.services import hostpdf, oncall
from app.services.reports import Summary, build_summary
from app.tenancy import Tenant, TenantContext

router = APIRouter(prefix="/v1/reports")

# A PDF covers at most this much (a server's whole life, up to five years).
PDF_MAX = timedelta(days=5 * 366)


def pdf_period(
    hosts: list[Host], start: datetime | None, end: datetime | None, lifetime: bool
) -> tuple[datetime, datetime]:
    end = end or datetime.now(UTC)
    if lifetime or start is None:
        start = hostpdf.lifetime_start(hosts) if lifetime else end - timedelta(days=30)
    if start >= end:
        raise HTTPException(status_code=422, detail="start must be before end")
    if end - start > PDF_MAX:
        raise HTTPException(status_code=422, detail="at most five years per report")
    return start, end


def pdf_response(body: bytes, hosts: list[Host], start: datetime) -> Response:
    name = hosts[0].hostname if len(hosts) == 1 else f"{len(hosts)}-servers"
    safe = "".join(c if c.isalnum() or c in "-._" else "-" for c in name)
    return Response(
        body,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="report-{safe}-{start:%Y%m%d}.pdf"'},
    )


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


@router.get("/servers.pdf", response_class=Response)
async def servers_pdf(
    t: Tenant,
    host_id: Annotated[list[uuid.UUID], Query(min_length=1, max_length=100)],
    start: datetime | None = None,
    end: datetime | None = None,
    lifetime: Annotated[bool, Query(description="from when the oldest server was added")] = False,
    tz: str = "Asia/Kolkata",
) -> Response:
    """A detailed PDF for one or more servers: availability, statistics,
    charts and incidents over the period (default the last 30 days)."""
    if oncall.zone(tz).key != tz:
        raise HTTPException(status_code=422, detail="unknown time zone")
    hosts = list(
        await t.db.scalars(
            select(Host)
            .where(Host.tenant_id == t.tenant_id, Host.id.in_(host_id))
            .order_by(Host.hostname)
        )
    )
    if len(hosts) != len(set(host_id)):
        raise HTTPException(status_code=404, detail="Host not found")
    a, b = pdf_period(hosts, start, end, lifetime)
    account = await t.db.scalar(select(TenantRow.email).where(TenantRow.id == t.tenant_id))
    datas = await hostpdf.collect(t.db, t.tenant_id, hosts, a, b)
    return pdf_response(hostpdf.render(datas, a, b, account=account or "", tz_name=tz), hosts, a)
