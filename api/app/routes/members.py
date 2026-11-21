"""Organisations and their members.

Roles (stored name → shown as): owner, admin, operator → "member",
viewer → "read-only". Viewers read everything; operators also acknowledge
and resolve incidents, schedule maintenance and run allowed actions; admins
change anything, members included, except API tokens and deleting the
organisation, which are the owner's. tenancy.py enforces the role on every
request; the checks here only cover what's specific to members (nobody
but the owner touches the owner's row).

A user picks the organisation with X-Sentinel-Account; membership is
checked in the database (sentinel_member_tenant()), never trusted from
the client.
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, BackgroundTasks, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError

from app.db import ServiceSession
from app.models import Tenant as TenantRow
from app.models import TenantMember
from app.services import export, invitations, tenants
from app.tenancy import Tenant, TenantContext, UserTenant
from app.validation import Trimmed

router = APIRouter(prefix="/v1")

MAX_MEMBERS = 50
Role = Literal["viewer", "operator", "admin", "investigator", "auditor"]


class MemberIn(BaseModel):
    email: EmailStr
    role: Role = "viewer"


class MemberPatch(BaseModel):
    role: Role


class MemberOut(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID | None
    email: str
    role: str
    name: str | None
    joined: bool
    is_you: bool
    invited_at: datetime
    invite_expires_at: datetime | None
    last_seen_at: datetime | None


class AccountOut(BaseModel):
    tenant_id: uuid.UUID
    name: str | None
    email: str | None
    role: str


def _out(m: TenantMember, t: TenantContext) -> MemberOut:
    return MemberOut(
        id=m.id,
        user_id=m.user_id,
        email=m.email,
        role=m.role,
        name=m.display_name,
        joined=m.joined_at is not None,
        is_you=m.user_id is not None and str(m.user_id) == t.principal.user_id,
        invited_at=m.invited_at,
        invite_expires_at=m.invite_expires_at,
        last_seen_at=m.last_seen_at,
    )


def _require_manager(t: TenantContext) -> None:
    if t.role not in ("owner", "admin", "staff"):
        raise HTTPException(status_code=403, detail="Only owners and admins manage members")


@router.get("/me/accounts")
async def my_accounts(t: Tenant) -> list[AccountOut]:
    """Every organisation you belong to (for the organisation switcher)."""
    p = t.principal
    if p.user_id is None or p.impersonated:
        return []
    rows = await t.db.execute(text("SELECT * FROM sentinel_member_accounts(:u)"), {"u": p.user_id})
    return [
        AccountOut(tenant_id=r.out_tenant_id, name=r.out_name, email=r.out_email, role=r.out_role)
        for r in rows
    ]


class OrganisationIn(BaseModel):
    name: Annotated[str, Trimmed, Field(min_length=1, max_length=100)]


@router.post("/organisations", status_code=status.HTTP_201_CREATED)
async def create_organisation(
    body: OrganisationIn, t: UserTenant, tasks: BackgroundTasks
) -> AccountOut:
    """Another organisation, owned by you. Switch to it with its id in
    X-Sentinel-Account."""
    p = t.principal
    if p.user_id is None or p.impersonated:
        raise HTTPException(status_code=403, detail="Sign in as yourself to do this")
    owned = await t.db.scalar(
        text("SELECT count(*) FROM sentinel_member_accounts(:u) WHERE out_role = 'owner'"),
        {"u": p.user_id},
    )
    if (owned or 0) >= 10:
        raise HTTPException(status_code=409, detail="You own 10 organisations already")
    tenant_id = await t.db.scalar(
        text("SELECT sentinel_create_tenant(:u, :e, :n)"),
        {"u": p.user_id, "e": p.email, "n": body.name.strip()},
    )
    from app.routes.alerts import ensure_recommended

    # After the response, once the organisation is committed.
    tasks.add_task(ensure_recommended, tenant_id)
    return AccountOut(tenant_id=tenant_id, name=body.name.strip(), email=p.email, role="owner")


@router.patch("/organisation")
async def rename_organisation(body: OrganisationIn, t: Tenant) -> AccountOut:
    _require_manager(t)
    row = await t.db.get_one(TenantRow, t.tenant_id)
    row.display_name = body.name.strip()
    row.updated_at = func.now()
    return AccountOut(tenant_id=row.id, name=row.display_name, email=row.email, role=t.role)


class AlertingSettings(BaseModel):
    reminder_minutes: int = Field(
        description="re-send open, unacknowledged incidents this often; 0 turns reminders off",
    )

    @field_validator("reminder_minutes")
    @classmethod
    def _range(cls, v: int) -> int:
        if v != 0 and not 30 <= v <= 10080:
            raise ValueError("between 30 minutes and 7 days, or 0 for no reminders")
        return v


@router.get("/organisation/alerting")
async def get_alerting(t: Tenant) -> AlertingSettings:
    row = await t.db.get_one(TenantRow, t.tenant_id)
    return AlertingSettings(reminder_minutes=row.reminder_minutes)


@router.put("/organisation/alerting")
async def put_alerting(body: AlertingSettings, t: Tenant) -> AlertingSettings:
    _require_manager(t)
    row = await t.db.get_one(TenantRow, t.tenant_id)
    row.reminder_minutes = body.reminder_minutes
    row.updated_at = func.now()
    return body


class DeleteIn(BaseModel):
    confirm_name: str


@router.post("/organisation/delete", status_code=status.HTTP_204_NO_CONTENT)
async def delete_organisation(body: DeleteIn, t: UserTenant) -> None:
    """Deletes the organisation with its servers, rules, incidents and
    metrics. Owner only; the name must be typed to confirm."""
    row = await t.db.get_one(TenantRow, t.tenant_id)
    if body.confirm_name.strip() != (row.display_name or row.email or ""):
        raise HTTPException(status_code=400, detail="Type the organisation's name to confirm")
    async with ServiceSession() as sdb, sdb.begin():
        await tenants.delete(sdb, t.tenant_id)


@router.get("/organisation/export")
async def export_organisation(t: UserTenant) -> JSONResponse:
    """Everything the organisation has here, as one JSON file (owner and
    admins). Secrets are masked; metric history is in the reports."""
    _require_manager(t)
    name = f"sentinel-export-{datetime.now(UTC):%Y%m%d}.json"
    return JSONResponse(
        await export.build(t.db, t.tenant_id),
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


@router.get("/members")
async def list_members(t: UserTenant) -> list[MemberOut]:
    rows = await t.db.scalars(
        select(TenantMember)
        .where(TenantMember.tenant_id == t.tenant_id)
        .order_by((TenantMember.role == "owner").desc(), TenantMember.invited_at)
    )
    return [_out(m, t) for m in rows]


@router.post("/members", status_code=status.HTTP_201_CREATED)
async def invite_member(body: MemberIn, t: UserTenant) -> MemberOut:
    """Emails an invitation (valid 7 days). The person signs in or signs up
    with that address to accept it."""
    _require_manager(t)
    email = body.email.lower()
    count = await t.db.scalar(
        select(func.count()).select_from(TenantMember).where(TenantMember.tenant_id == t.tenant_id)
    )
    if (count or 0) >= MAX_MEMBERS:
        raise HTTPException(status_code=409, detail=f"At most {MAX_MEMBERS} members")
    m = TenantMember(tenant_id=t.tenant_id, email=email, role=body.role)
    t.db.add(m)
    try:
        async with t.db.begin_nested():
            await t.db.flush()
    except IntegrityError:
        raise HTTPException(status_code=409, detail="Already a member or invited") from None
    await invitations.send(t.db, m.id, t.principal)
    await t.db.refresh(m)
    return _out(m, t)


async def _get(t: TenantContext, member_id: uuid.UUID) -> TenantMember:
    m = await t.db.scalar(
        select(TenantMember).where(
            TenantMember.id == member_id, TenantMember.tenant_id == t.tenant_id
        )
    )
    if m is None:
        raise HTTPException(status_code=404, detail="Member not found")
    return m


@router.post("/members/{member_id}/resend")
async def resend_invitation(member_id: uuid.UUID, t: UserTenant) -> MemberOut:
    _require_manager(t)
    m = await _get(t, member_id)
    await invitations.send(t.db, m.id, t.principal)
    await t.db.refresh(m)
    return _out(m, t)


@router.patch("/members/{member_id}")
async def change_role(member_id: uuid.UUID, body: MemberPatch, t: UserTenant) -> MemberOut:
    _require_manager(t)
    m = await _get(t, member_id)
    if m.role == "owner":
        raise HTTPException(status_code=400, detail="The owner's role can't be changed")
    m.role = body.role
    return _out(m, t)


@router.post("/members/{member_id}/make-owner")
async def make_owner(member_id: uuid.UUID, t: UserTenant) -> MemberOut:
    """Hands the organisation to a joined member; you become an admin."""
    if t.role != "owner":
        raise HTTPException(status_code=403, detail="Only the owner can hand over ownership")
    m = await _get(t, member_id)
    if m.user_id is None or m.joined_at is None:
        raise HTTPException(status_code=400, detail="They have to accept the invitation first")
    if m.role == "owner":
        return _out(m, t)
    me = await t.db.scalar(
        select(TenantMember).where(
            TenantMember.tenant_id == t.tenant_id, TenantMember.role == "owner"
        )
    )
    # One owner at a time (a unique index): step down first.
    if me is not None:
        me.role = "admin"
        await t.db.flush()
    m.role = "owner"
    await t.db.flush()
    return _out(m, t)


@router.delete("/members/{member_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(member_id: uuid.UUID, t: Tenant) -> None:
    """Owners and admins remove anyone but the owner; anyone may leave."""
    m = await _get(t, member_id)
    leaving = m.user_id is not None and str(m.user_id) == t.principal.user_id
    if m.role == "owner":
        raise HTTPException(status_code=400, detail="The owner can't be removed")
    if not leaving:
        _require_manager(t)
    await t.db.execute(
        text(
            "DELETE FROM notification_channels "
            "WHERE tenant_id = :t AND source = 'team' AND type = 'email' AND target = :e"
        ),
        {"t": t.tenant_id, "e": m.email},
    )
    await t.db.delete(m)
