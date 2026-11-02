"""On-call schedules: who gets paged now, and who's next.

Rules and escalation steps can notify a schedule (schedule_ids) as well as
fixed contacts; the alerter pages whoever is on call when the alert goes out.
"""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import any_, func, literal, select, update
from sqlalchemy.exc import IntegrityError

from app.models import (
    AlertEscalationStep,
    AlertRule,
    NotificationChannel,
    OncallOverride,
    OncallSchedule,
)
from app.services import oncall
from app.tenancy import Tenant, TenantContext
from app.validation import Trimmed

router = APIRouter(prefix="/v1/oncall", tags=["on-call"])

MAX_RESPONDERS = 20


class Responder(BaseModel):
    name: Annotated[str, Trimmed, Field(min_length=1, max_length=60)]
    channel_ids: list[uuid.UUID] = Field(min_length=1, max_length=5)


class ScheduleIn(BaseModel):
    name: Annotated[str, Trimmed, Field(min_length=1, max_length=100)]
    timezone: str = "UTC"
    start_at: datetime = Field(description="when the first shift starts (a handoff time)")
    shift_hours: int = Field(ge=1, le=2160, description="24 daily, 168 weekly")
    responders: list[Responder] = Field(min_length=1, max_length=MAX_RESPONDERS)

    @field_validator("timezone")
    @classmethod
    def _tz(cls, v: str) -> str:
        if oncall.zone(v).key != v:
            raise ValueError("unknown time zone (use a name like Asia/Kolkata)")
        return v

    @field_validator("start_at")
    @classmethod
    def _aware(cls, v: datetime) -> datetime:
        return v if v.tzinfo else v.replace(tzinfo=UTC)


class OverrideIn(BaseModel):
    starts_at: datetime
    ends_at: datetime
    responder: Responder
    note: str | None = Field(default=None, max_length=300)

    @model_validator(mode="after")
    def _order(self) -> "OverrideIn":
        self.starts_at = (
            self.starts_at if self.starts_at.tzinfo else self.starts_at.replace(tzinfo=UTC)
        )
        self.ends_at = self.ends_at if self.ends_at.tzinfo else self.ends_at.replace(tzinfo=UTC)
        if self.ends_at <= self.starts_at:
            raise ValueError("an override ends after it starts")
        if self.ends_at - self.starts_at > timedelta(days=90):
            raise ValueError("an override lasts at most 90 days")
        return self


class OverrideOut(OverrideIn):
    id: uuid.UUID
    created_by: str | None


class ShiftOut(BaseModel):
    starts_at: datetime
    ends_at: datetime
    responder: dict
    override: bool


class ScheduleOut(BaseModel):
    id: uuid.UUID
    name: str
    timezone: str
    start_at: datetime
    shift_hours: int
    responders: list[dict]
    on_call: dict | None
    next_handoff: datetime | None
    next_on_call: dict | None
    overrides: list[OverrideOut]
    used_by_rules: int


async def _overrides(t: TenantContext, schedule_id: uuid.UUID) -> list[OncallOverride]:
    return list(
        await t.db.scalars(
            select(OncallOverride)
            .where(
                OncallOverride.tenant_id == t.tenant_id,
                OncallOverride.schedule_id == schedule_id,
                OncallOverride.ends_at > datetime.now(UTC) - timedelta(days=1),
            )
            .order_by(OncallOverride.starts_at)
        )
    )


async def _out(t: TenantContext, s: OncallSchedule) -> ScheduleOut:
    now = datetime.now(UTC)
    overrides = await _overrides(t, s.id)
    upcoming = oncall.shifts(s, overrides, now, now + timedelta(days=60))
    nxt = upcoming[1] if len(upcoming) > 1 else None
    used = await t.db.scalar(
        select(func.count())
        .select_from(AlertRule)
        .where(AlertRule.tenant_id == t.tenant_id, literal(s.id) == any_(AlertRule.schedule_ids))
    )
    return ScheduleOut(
        id=s.id,
        name=s.name,
        timezone=s.timezone,
        start_at=s.start_at,
        shift_hours=s.shift_hours,
        responders=s.responders,
        on_call=oncall.current(s, overrides, now),
        next_handoff=nxt.starts_at if nxt else None,
        next_on_call=nxt.responder if nxt else None,
        overrides=[
            OverrideOut(
                id=o.id,
                starts_at=o.starts_at,
                ends_at=o.ends_at,
                responder=Responder(**o.responder),
                note=o.note,
                created_by=o.created_by,
            )
            for o in overrides
            if o.ends_at > now
        ],
        used_by_rules=used or 0,
    )


async def _check_channels(t: TenantContext, responders: list[Responder]) -> None:
    wanted = {c for r in responders for c in r.channel_ids}
    found = set(
        await t.db.scalars(
            select(NotificationChannel.id).where(
                NotificationChannel.tenant_id == t.tenant_id, NotificationChannel.id.in_(wanted)
            )
        )
    )
    if wanted - found:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Unknown alert contact")


async def _get(t: TenantContext, schedule_id: uuid.UUID) -> OncallSchedule:
    s = await t.db.get(OncallSchedule, schedule_id)
    if s is None or s.tenant_id != t.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Schedule not found")
    return s


def _actor(t: TenantContext) -> str:
    return t.principal.email or t.principal.name or "dashboard"


@router.get("/schedules")
async def list_schedules(t: Tenant) -> list[ScheduleOut]:
    rows = await t.db.scalars(
        select(OncallSchedule)
        .where(OncallSchedule.tenant_id == t.tenant_id)
        .order_by(OncallSchedule.name)
    )
    return [await _out(t, s) for s in rows]


@router.post("/schedules", status_code=status.HTTP_201_CREATED)
async def create_schedule(body: ScheduleIn, t: Tenant) -> ScheduleOut:
    await _check_channels(t, body.responders)
    s = OncallSchedule(
        tenant_id=t.tenant_id,
        name=body.name.strip(),
        timezone=body.timezone,
        start_at=body.start_at,
        shift_hours=body.shift_hours,
        responders=[r.model_dump(mode="json") for r in body.responders],
    )
    t.db.add(s)
    try:
        await t.db.flush()
    except IntegrityError:
        raise HTTPException(status.HTTP_409_CONFLICT, "A schedule with that name exists") from None
    await t.db.refresh(s)
    return await _out(t, s)


@router.put("/schedules/{schedule_id}")
async def update_schedule(schedule_id: uuid.UUID, body: ScheduleIn, t: Tenant) -> ScheduleOut:
    s = await _get(t, schedule_id)
    await _check_channels(t, body.responders)
    s.name, s.timezone, s.start_at, s.shift_hours = (
        body.name.strip(),
        body.timezone,
        body.start_at,
        body.shift_hours,
    )
    s.responders = [r.model_dump(mode="json") for r in body.responders]
    s.updated_at = datetime.now(UTC)
    try:
        await t.db.flush()
    except IntegrityError:
        raise HTTPException(status.HTTP_409_CONFLICT, "A schedule with that name exists") from None
    return await _out(t, s)


@router.delete("/schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_schedule(schedule_id: uuid.UUID, t: Tenant) -> None:
    s = await _get(t, schedule_id)
    # Rules and escalation steps stop paging it.
    await t.db.execute(
        update(AlertRule)
        .where(AlertRule.tenant_id == t.tenant_id, literal(s.id) == any_(AlertRule.schedule_ids))
        .values(schedule_ids=func.array_remove(AlertRule.schedule_ids, s.id))
    )
    # Escalation steps stop paging it; a step left with nobody to notify
    # goes, and the rule's later steps move up.
    steps = list(
        await t.db.scalars(
            select(AlertEscalationStep).where(
                AlertEscalationStep.tenant_id == t.tenant_id,
                literal(s.id) == any_(AlertEscalationStep.schedule_ids),
            )
        )
    )
    touched = set()
    for step in steps:
        step.schedule_ids = [x for x in step.schedule_ids if x != s.id]
        touched.add(step.rule_id)
        if not step.channel_ids and not step.schedule_ids:
            await t.db.delete(step)
    await t.db.flush()
    for rule_id in touched:
        remaining = list(
            await t.db.scalars(
                select(AlertEscalationStep)
                .where(AlertEscalationStep.rule_id == rule_id)
                .order_by(AlertEscalationStep.position)
            )
        )
        # Two passes: positions are unique per rule.
        for i, step in enumerate(remaining):
            step.position = 1000 + i
        await t.db.flush()
        for i, step in enumerate(remaining):
            step.position = i
        await t.db.flush()
    await t.db.delete(s)


@router.get("/schedules/{schedule_id}/shifts")
async def schedule_shifts(
    schedule_id: uuid.UUID, t: Tenant, days: Annotated[int, Query(ge=1, le=90)] = 14
) -> list[ShiftOut]:
    s = await _get(t, schedule_id)
    now = datetime.now(UTC)
    return [
        ShiftOut(**sh.__dict__)
        for sh in oncall.shifts(s, await _overrides(t, s.id), now, now + timedelta(days=days))
    ]


@router.post("/schedules/{schedule_id}/overrides", status_code=status.HTTP_201_CREATED)
async def add_override(schedule_id: uuid.UUID, body: OverrideIn, t: Tenant) -> ScheduleOut:
    s = await _get(t, schedule_id)
    await _check_channels(t, [body.responder])
    t.db.add(
        OncallOverride(
            tenant_id=t.tenant_id,
            schedule_id=s.id,
            starts_at=body.starts_at,
            ends_at=body.ends_at,
            responder=body.responder.model_dump(mode="json"),
            note=body.note,
            created_by=_actor(t),
        )
    )
    await t.db.flush()
    return await _out(t, s)


@router.delete("/overrides/{override_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_override(override_id: uuid.UUID, t: Tenant) -> None:
    o = await t.db.get(OncallOverride, override_id)
    if o is None or o.tenant_id != t.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Override not found")
    await t.db.delete(o)
