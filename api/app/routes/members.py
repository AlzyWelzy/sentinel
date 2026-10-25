"""Team members: the account owner shares monitoring with other console users.

Roles: viewer (reads everything), operator (also acknowledges and resolves
incidents, schedules maintenance and runs allowed actions) and admin
(changes anything except members and API tokens). A member opens the shared
account by sending its id in X-Pulsegrid-Account; tenancy.py enforces the role.
"""

import uuid
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError

from app.models import Tenant as TenantRow
from app.models import TenantMember
from app.tenancy import ConsoleTenant, Tenant

router = APIRouter(prefix="/v1")

MAX_MEMBERS = 50
Role = Literal["viewer", "operator", "admin"]


class MemberIn(BaseModel):
    email: str = Field(max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    role: Role = "viewer"


class MemberPatch(BaseModel):
    role: Role


class MemberOut(BaseModel):
    id: uuid.UUID
    email: str
    role: str
    name: str | None
    joined: bool
    invited_at: datetime
    last_seen_at: datetime | None


class AccountOut(BaseModel):
    tenant_id: uuid.UUID
    name: str | None
    email: str | None
    role: str


def _out(m: TenantMember) -> MemberOut:
    return MemberOut(
        id=m.id,
        email=m.email,
        role=m.role,
        name=m.display_name,
        joined=m.joined_at is not None,
        invited_at=m.invited_at,
        last_seen_at=m.last_seen_at,
    )


@router.get("/me/accounts")
async def my_accounts(t: Tenant) -> list[AccountOut]:
    """Accounts other people have shared with you (for the account switcher)."""
    p = t.principal
    if p.api_token_id is not None:
        return []
    rows = await t.db.execute(
        text("SELECT * FROM pulsegrid_member_accounts(:s, :e, :m)"),
        {"s": p.source, "e": p.external_account_id, "m": p.email},
    )
    return [
        AccountOut(tenant_id=r.out_tenant_id, name=r.out_name, email=r.out_email, role=r.out_role)
        for r in rows
    ]


@router.get("/members")
async def list_members(t: ConsoleTenant) -> list[MemberOut]:
    rows = await t.db.scalars(
        select(TenantMember)
        .where(TenantMember.tenant_id == t.tenant_id)
        .order_by(TenantMember.invited_at)
    )
    return [_out(m) for m in rows]


@router.post("/members", status_code=status.HTTP_201_CREATED)
async def add_member(body: MemberIn, t: ConsoleTenant) -> MemberOut:
    email = body.email.lower()
    owner = await t.db.scalar(select(TenantRow.email).where(TenantRow.id == t.tenant_id))
    if owner and owner.lower() == email:
        raise HTTPException(status_code=400, detail="That's you: the owner already has full access")
    count = await t.db.scalar(
        select(func.count()).select_from(TenantMember).where(TenantMember.tenant_id == t.tenant_id)
    )
    if (count or 0) >= MAX_MEMBERS:
        raise HTTPException(status_code=409, detail=f"At most {MAX_MEMBERS} members")
    m = TenantMember(tenant_id=t.tenant_id, email=email, role=body.role)
    t.db.add(m)
    try:
        await t.db.flush()
    except IntegrityError:
        raise HTTPException(status_code=409, detail="Already a member") from None
    await t.db.refresh(m)
    return _out(m)


async def _get(t: ConsoleTenant, member_id: uuid.UUID) -> TenantMember:
    m = await t.db.scalar(
        select(TenantMember).where(
            TenantMember.id == member_id, TenantMember.tenant_id == t.tenant_id
        )
    )
    if m is None:
        raise HTTPException(status_code=404, detail="Member not found")
    return m


@router.patch("/members/{member_id}")
async def change_role(member_id: uuid.UUID, body: MemberPatch, t: ConsoleTenant) -> MemberOut:
    m = await _get(t, member_id)
    m.role = body.role
    return _out(m)


@router.delete("/members/{member_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(member_id: uuid.UUID, t: ConsoleTenant) -> None:
    await t.db.delete(await _get(t, member_id))
