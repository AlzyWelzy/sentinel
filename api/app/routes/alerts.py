"""Alert rules and incidents.

Rules are evaluated by the alerter service every 30 seconds. Incidents are
opened and resolved by the alerter; customers can list and acknowledge them.
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import delete, func, select, update

from app.models import AlertRule, AlertRuleChannel, AlertState, Host, Incident, NotificationChannel
from app.tenancy import Tenant, TenantContext

router = APIRouter(prefix="/v1")

# A host pushes every 30s; anything shorter than two missed pushes is noise.
MIN_HOST_DOWN_SECONDS = 60


class RuleIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    kind: Literal["metric", "host_down"]
    metric: Literal["cpu", "memory", "swap", "disk", "load1", "load5"] | None = None
    operator: Literal[">", "<"] | None = None
    threshold: float | None = None
    duration_seconds: int = Field(default=300, ge=0, le=86400)
    host_id: uuid.UUID | None = Field(default=None, description="omit to cover every host")
    channel_ids: list[uuid.UUID] = Field(
        default_factory=list, description="omit to use the default channel"
    )
    enabled: bool = True

    @model_validator(mode="after")
    def _check_kind(self) -> "RuleIn":
        if self.kind == "metric":
            if self.metric is None or self.operator is None or self.threshold is None:
                raise ValueError("metric rules need metric, operator and threshold")
        else:
            self.metric = self.operator = self.threshold = None
            if self.duration_seconds < MIN_HOST_DOWN_SECONDS:
                raise ValueError(f"host_down needs duration_seconds >= {MIN_HOST_DOWN_SECONDS}")
        return self


class RuleOut(BaseModel):
    id: uuid.UUID
    name: str
    kind: str
    metric: str | None
    operator: str | None
    threshold: float | None
    duration_seconds: int
    host_id: uuid.UUID | None
    channel_ids: list[uuid.UUID]
    enabled: bool
    firing_hosts: int
    created_at: datetime
    updated_at: datetime


class IncidentOut(BaseModel):
    id: uuid.UUID
    rule_id: uuid.UUID | None
    host_id: uuid.UUID | None
    status: str
    summary: str
    rule_name: str
    hostname: str
    value: float | None
    opened_at: datetime
    acknowledged_at: datetime | None
    resolved_at: datetime | None


def _incident_out(i: Incident) -> IncidentOut:
    return IncidentOut(
        id=i.id,
        rule_id=i.rule_id,
        host_id=i.host_id,
        status=i.status,
        summary=i.summary,
        rule_name=i.rule_name,
        hostname=i.hostname,
        value=i.value,
        opened_at=i.opened_at,
        acknowledged_at=i.acknowledged_at,
        resolved_at=i.resolved_at,
    )


async def _rule_out(t: TenantContext, r: AlertRule) -> RuleOut:
    channel_ids = list(
        await t.db.scalars(
            select(AlertRuleChannel.channel_id).where(
                AlertRuleChannel.rule_id == r.id, AlertRuleChannel.tenant_id == t.tenant_id
            )
        )
    )
    firing = await t.db.scalar(
        select(func.count())
        .select_from(AlertState)
        .where(
            AlertState.rule_id == r.id,
            AlertState.tenant_id == t.tenant_id,
            AlertState.state == "firing",
        )
    )
    return RuleOut(
        id=r.id,
        name=r.name,
        kind=r.kind,
        metric=r.metric,
        operator=r.operator,
        threshold=r.threshold,
        duration_seconds=r.duration_seconds,
        host_id=r.host_id,
        channel_ids=channel_ids,
        enabled=r.enabled,
        firing_hosts=firing or 0,
        created_at=r.created_at,
        updated_at=r.updated_at,
    )


async def _get_rule(t: TenantContext, rule_id: uuid.UUID) -> AlertRule:
    rule = await t.db.scalar(
        select(AlertRule).where(AlertRule.id == rule_id, AlertRule.tenant_id == t.tenant_id)
    )
    if rule is None:
        raise HTTPException(status_code=404, detail="Alert rule not found")
    return rule


async def _check_refs(t: TenantContext, body: RuleIn) -> None:
    """Hosts and channels must be the caller's own. RLS would hide anyone
    else's anyway, which is exactly why a missing one reads as 'not found'."""
    if body.host_id is not None:
        found = await t.db.scalar(
            select(Host.id).where(Host.id == body.host_id, Host.tenant_id == t.tenant_id)
        )
        if found is None:
            raise HTTPException(status_code=422, detail="host_id not found")
    if body.channel_ids:
        found = set(
            await t.db.scalars(
                select(NotificationChannel.id).where(
                    NotificationChannel.id.in_(body.channel_ids),
                    NotificationChannel.tenant_id == t.tenant_id,
                )
            )
        )
        if found != set(body.channel_ids):
            raise HTTPException(status_code=422, detail="channel_ids contains unknown channels")


async def _set_channels(t: TenantContext, rule_id: uuid.UUID, channel_ids: list[uuid.UUID]) -> None:
    await t.db.execute(
        delete(AlertRuleChannel).where(
            AlertRuleChannel.rule_id == rule_id, AlertRuleChannel.tenant_id == t.tenant_id
        )
    )
    for channel_id in dict.fromkeys(channel_ids):
        t.db.add(AlertRuleChannel(tenant_id=t.tenant_id, rule_id=rule_id, channel_id=channel_id))


async def _reset_rule(t: TenantContext, rule_id: uuid.UUID) -> None:
    """Forget the alerter's progress on a rule and close its open incidents.
    Used when a rule is disabled, deleted, or its condition changes, so no
    incident is left open forever by a rule that can no longer resolve it."""
    await t.db.execute(
        update(Incident)
        .where(
            Incident.rule_id == rule_id,
            Incident.tenant_id == t.tenant_id,
            Incident.status == "open",
        )
        .values(status="resolved", resolved_at=datetime.now(UTC))
    )
    await t.db.execute(
        delete(AlertState).where(AlertState.rule_id == rule_id, AlertState.tenant_id == t.tenant_id)
    )


@router.get("/alert-rules")
async def list_rules(t: Tenant) -> list[RuleOut]:
    rules = await t.db.scalars(
        select(AlertRule).where(AlertRule.tenant_id == t.tenant_id).order_by(AlertRule.created_at)
    )
    return [await _rule_out(t, r) for r in rules]


@router.post("/alert-rules", status_code=status.HTTP_201_CREATED)
async def create_rule(body: RuleIn, t: Tenant) -> RuleOut:
    await _check_refs(t, body)
    rule = AlertRule(
        tenant_id=t.tenant_id,
        **body.model_dump(exclude={"channel_ids"}),
    )
    t.db.add(rule)
    await t.db.flush()
    await _set_channels(t, rule.id, body.channel_ids)
    await t.db.flush()
    await t.db.refresh(rule)
    return await _rule_out(t, rule)


@router.get("/alert-rules/{rule_id}")
async def get_rule(rule_id: uuid.UUID, t: Tenant) -> RuleOut:
    return await _rule_out(t, await _get_rule(t, rule_id))


@router.put("/alert-rules/{rule_id}")
async def update_rule(rule_id: uuid.UUID, body: RuleIn, t: Tenant) -> RuleOut:
    rule = await _get_rule(t, rule_id)
    await _check_refs(t, body)
    condition = ("kind", "metric", "operator", "threshold", "host_id")
    changed = any(getattr(rule, f) != getattr(body, f) for f in condition)
    if changed or (rule.enabled and not body.enabled):
        await _reset_rule(t, rule.id)
    for field, value in body.model_dump(exclude={"channel_ids"}).items():
        setattr(rule, field, value)
    rule.updated_at = datetime.now(UTC)
    await _set_channels(t, rule.id, body.channel_ids)
    await t.db.flush()
    return await _rule_out(t, rule)


@router.delete("/alert-rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(rule_id: uuid.UUID, t: Tenant) -> None:
    rule = await _get_rule(t, rule_id)
    await _reset_rule(t, rule.id)
    await t.db.delete(rule)


@router.get("/incidents")
async def list_incidents(
    t: Tenant,
    status_: Annotated[Literal["open", "resolved"] | None, Query(alias="status")] = None,
    host_id: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[IncidentOut]:
    q = select(Incident).where(Incident.tenant_id == t.tenant_id)
    if status_:
        q = q.where(Incident.status == status_)
    if host_id:
        q = q.where(Incident.host_id == host_id)
    rows = await t.db.scalars(q.order_by(Incident.opened_at.desc()).limit(limit))
    return [_incident_out(i) for i in rows]


async def _get_incident(t: TenantContext, incident_id: uuid.UUID) -> Incident:
    incident = await t.db.scalar(
        select(Incident).where(Incident.id == incident_id, Incident.tenant_id == t.tenant_id)
    )
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: uuid.UUID, t: Tenant) -> IncidentOut:
    return _incident_out(await _get_incident(t, incident_id))


@router.post("/incidents/{incident_id}/acknowledge")
async def acknowledge(incident_id: uuid.UUID, t: Tenant) -> IncidentOut:
    incident = await _get_incident(t, incident_id)
    if incident.acknowledged_at is None:
        incident.acknowledged_at = datetime.now(UTC)
    return _incident_out(incident)
