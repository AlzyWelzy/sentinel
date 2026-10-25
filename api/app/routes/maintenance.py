"""Maintenance windows: while one is active for a host, the alerter opens no
incidents for it and sends nothing about it. A problem that outlasts the
window alerts as soon as the window ends."""

import uuid
from datetime import UTC, datetime, time, timedelta
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import select

from app.models import Host, MaintenanceWindow
from app.services.maintenance import active_at
from app.tenancy import Tenant, TenantContext
from app.validation import normalize_tag

router = APIRouter(prefix="/v1/maintenance")

MAX_ONCE = timedelta(days=31)


class WindowIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    host_id: uuid.UUID | None = None
    tag: str | None = None
    schedule: Literal["once", "weekly"]
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    weekdays: list[int] | None = Field(default=None, description="ISO weekdays, 1 = Monday")
    start_time: time | None = Field(default=None, description="local time, in timezone")
    duration_minutes: int | None = Field(default=None, ge=1, le=10080)
    timezone: str = "UTC"
    enabled: bool = True

    @field_validator("tag")
    @classmethod
    def _tag(cls, v: str | None) -> str | None:
        return None if v is None or v.strip() == "" else normalize_tag(v)

    @field_validator("timezone")
    @classmethod
    def _tz(cls, v: str) -> str:
        try:
            ZoneInfo(v)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError("unknown timezone, e.g. Asia/Kolkata or UTC") from None
        return v

    @model_validator(mode="after")
    def _check(self) -> "WindowIn":
        if self.host_id is not None and self.tag is not None:
            raise ValueError("choose one host or one tag, not both")
        if self.schedule == "once":
            if self.starts_at is None or self.ends_at is None:
                raise ValueError("a one-off window needs starts_at and ends_at")
            if self.starts_at.tzinfo is None or self.ends_at.tzinfo is None:
                raise ValueError("starts_at and ends_at need a timezone offset")
            if not self.starts_at < self.ends_at <= self.starts_at + MAX_ONCE:
                raise ValueError("ends_at must be after starts_at, and within 31 days of it")
            self.weekdays = self.start_time = self.duration_minutes = None
        else:
            if not self.weekdays or self.start_time is None or self.duration_minutes is None:
                raise ValueError("a weekly window needs weekdays, start_time and duration_minutes")
            if any(d < 1 or d > 7 for d in self.weekdays):
                raise ValueError("weekdays are 1 (Monday) to 7 (Sunday)")
            self.weekdays = sorted(set(self.weekdays))
            self.start_time = self.start_time.replace(second=0, microsecond=0, tzinfo=None)
            self.starts_at = self.ends_at = None
        return self


class WindowOut(BaseModel):
    id: uuid.UUID
    name: str
    host_id: uuid.UUID | None
    tag: str | None
    schedule: str
    starts_at: datetime | None
    ends_at: datetime | None
    weekdays: list[int] | None
    start_time: str | None  # HH:MM
    duration_minutes: int | None
    timezone: str
    enabled: bool
    active: bool
    created_at: datetime


def _out(w: MaintenanceWindow) -> WindowOut:
    return WindowOut(
        id=w.id,
        name=w.name,
        host_id=w.host_id,
        tag=w.tag,
        schedule=w.schedule,
        starts_at=w.starts_at,
        ends_at=w.ends_at,
        weekdays=w.weekdays,
        start_time=w.start_time.strftime("%H:%M") if w.start_time else None,
        duration_minutes=w.duration_minutes,
        timezone=w.timezone,
        enabled=w.enabled,
        active=active_at(w, datetime.now(UTC)),
        created_at=w.created_at,
    )


async def _get(t: TenantContext, window_id: uuid.UUID) -> MaintenanceWindow:
    w = await t.db.scalar(
        select(MaintenanceWindow).where(
            MaintenanceWindow.id == window_id, MaintenanceWindow.tenant_id == t.tenant_id
        )
    )
    if w is None:
        raise HTTPException(status_code=404, detail="Maintenance window not found")
    return w


async def _check_host(t: TenantContext, host_id: uuid.UUID | None) -> None:
    if host_id is None:
        return
    found = await t.db.scalar(
        select(Host.id).where(Host.id == host_id, Host.tenant_id == t.tenant_id)
    )
    if found is None:
        raise HTTPException(status_code=422, detail="host_id not found")


@router.get("")
async def list_windows(t: Tenant) -> list[WindowOut]:
    rows = await t.db.scalars(
        select(MaintenanceWindow)
        .where(MaintenanceWindow.tenant_id == t.tenant_id)
        .order_by(MaintenanceWindow.created_at)
    )
    return [_out(w) for w in rows]


@router.get("/{window_id}")
async def get_window(window_id: uuid.UUID, t: Tenant) -> WindowOut:
    return _out(await _get(t, window_id))


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_window(body: WindowIn, t: Tenant) -> WindowOut:
    await _check_host(t, body.host_id)
    w = MaintenanceWindow(tenant_id=t.tenant_id, **body.model_dump())
    t.db.add(w)
    await t.db.flush()
    await t.db.refresh(w)
    return _out(w)


@router.put("/{window_id}")
async def update_window(window_id: uuid.UUID, body: WindowIn, t: Tenant) -> WindowOut:
    w = await _get(t, window_id)
    await _check_host(t, body.host_id)
    for field, value in body.model_dump().items():
        setattr(w, field, value)
    await t.db.flush()
    return _out(w)


@router.delete("/{window_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_window(window_id: uuid.UUID, t: Tenant) -> None:
    await t.db.delete(await _get(t, window_id))
