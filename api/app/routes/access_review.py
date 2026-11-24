"""Access reviews: who can get into the organisation, how, and when someone
last confirmed that's right. Owners and admins see members (role, last
sign-in, two-factor), pending invitations and API tokens, and record a
review; the audit log keeps every one. A review older than 90 days is due.
"""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, text

from app.models import ApiToken, TenantMember
from app.models import Tenant as TenantRow
from app.tenancy import UserTenant, actor_of

router = APIRouter(prefix="/v1/access-review")

DUE_AFTER = timedelta(days=90)


class MemberAccess(BaseModel):
    email: str
    name: str | None
    role: str
    joined_at: datetime | None
    last_seen_at: datetime | None
    two_factor: bool
    pending: bool


class TokenAccess(BaseModel):
    name: str
    read_only: bool
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime | None


class AccessReviewOut(BaseModel):
    reviewed_at: datetime | None
    reviewed_by: str | None
    due: bool
    members: list[MemberAccess]
    tokens: list[TokenAccess]


def _manager(t) -> None:
    if t.role not in ("owner", "admin") or t.principal.impersonated:
        raise HTTPException(status_code=403, detail="Owners and admins review access")


@router.get("")
async def get_review(t: UserTenant) -> AccessReviewOut:
    _manager(t)
    tenant = await t.db.get(TenantRow, t.tenant_id)
    members = (
        await t.db.scalars(
            select(TenantMember)
            .where(TenantMember.tenant_id == t.tenant_id)
            .order_by(TenantMember.role, TenantMember.email)
        )
    ).all()
    tfa = set((await t.db.scalars(text("SELECT * FROM sentinel_members_with_2fa()"))).all())
    tokens = (
        await t.db.scalars(
            select(ApiToken)
            .where(ApiToken.tenant_id == t.tenant_id, ApiToken.revoked_at.is_(None))
            .order_by(ApiToken.created_at)
        )
    ).all()
    now = datetime.now(UTC)
    reviewed = tenant.access_reviewed_at if tenant else None
    return AccessReviewOut(
        reviewed_at=reviewed,
        reviewed_by=tenant.access_reviewed_by if tenant else None,
        due=reviewed is None or now - reviewed > DUE_AFTER,
        members=[
            MemberAccess(
                email=m.email,
                name=m.display_name,
                role=m.role,
                joined_at=m.joined_at,
                last_seen_at=m.last_seen_at,
                two_factor=m.user_id in tfa,
                pending=m.joined_at is None,
            )
            for m in members
        ],
        tokens=[
            TokenAccess(
                name=k.name,
                read_only=k.read_only,
                created_at=k.created_at,
                last_used_at=k.last_used_at,
                expires_at=k.expires_at,
            )
            for k in tokens
            if not k.expires_at or k.expires_at > now
        ],
    )


@router.post("", status_code=204)
async def record_review(t: UserTenant) -> None:
    """I've checked the list: everyone and every token here should have access."""
    _manager(t)
    tenant = await t.db.get(TenantRow, t.tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404)
    tenant.access_reviewed_at = datetime.now(UTC)
    tenant.access_reviewed_by = actor_of(t.principal)
