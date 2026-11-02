"""Invitations to an organisation.

An invitation is a tenant_members row without a user yet, holding the hash
of a single-use token that was emailed to the invited address. Accepting
needs a signed-in user whose (verified) email is that address; then the row
gets the user and the token is gone.
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import HTTPException
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import native
from app.auth.principal import Principal
from app.db import ServiceSession
from app.services import account_emails

INVITE_TTL = timedelta(days=7)
ROLE_LABELS = {"owner": "owner", "admin": "admin", "operator": "member", "viewer": "read-only"}


class InvitationOut(BaseModel):
    organisation: str
    email: str
    role: str
    invited_by: str | None
    expires_at: datetime


class Accepted(BaseModel):
    tenant_id: UUID
    role: str


def org_name(display_name: str | None, email: str | None) -> str:
    return display_name or (f"{email}'s organisation" if email else "an organisation")


async def send(db: AsyncSession, member_id: UUID, inviter: Principal) -> None:
    """(Re)issues the member row's token and emails it. Runs in the caller's
    tenant-scoped transaction; the email is queued with the service role."""
    token = native.new_opaque_token()
    row = (
        await db.execute(
            text(
                "UPDATE tenant_members SET invite_hash = :h, invite_expires_at = :x, "
                "invited_by = :by, invited_at = now() "
                "WHERE id = :m AND user_id IS NULL "
                "RETURNING email, role, "
                "(SELECT display_name FROM tenants WHERE id = tenant_id) AS org, "
                "(SELECT email FROM tenants WHERE id = tenant_id) AS org_email"
            ),
            {
                "h": native.hash_token(token),
                "x": datetime.now(UTC) + INVITE_TTL,
                "by": inviter.user_id,
                "m": member_id,
            },
        )
    ).one_or_none()
    if row is None:
        raise HTTPException(status_code=409, detail="That person has already joined")
    async with ServiceSession() as sdb, sdb.begin():
        await account_emails.invitation(
            sdb,
            row.email,
            inviter.name or inviter.email or "Someone",
            org_name(row.org, row.org_email),
            ROLE_LABELS.get(row.role, row.role),
            token,
        )


async def _pending(db: AsyncSession, token: str):
    return (
        await db.execute(
            text(
                "SELECT m.id, m.tenant_id, m.email, m.role, m.invite_expires_at, "
                "t.display_name, t.email AS org_email, t.status, u.name AS inviter, "
                "u.email AS inviter_email "
                "FROM tenant_members m JOIN tenants t ON t.id = m.tenant_id "
                "LEFT JOIN users u ON u.id = m.invited_by "
                "WHERE m.invite_hash = :h AND m.user_id IS NULL"
            ),
            {"h": native.hash_token(token)},
        )
    ).one_or_none()


def _gone() -> HTTPException:
    return HTTPException(status_code=404, detail="This invitation has expired or was already used")


async def preview(token: str) -> InvitationOut:
    async with ServiceSession() as db, db.begin():
        row = await _pending(db, token)
    if row is None or row.invite_expires_at <= datetime.now(UTC) or row.status != "active":
        raise _gone()
    return InvitationOut(
        organisation=org_name(row.display_name, row.org_email),
        email=row.email,
        role=ROLE_LABELS.get(row.role, row.role),
        invited_by=row.inviter or row.inviter_email,
        expires_at=row.invite_expires_at,
    )


async def accept(token: str, user: Principal) -> Accepted:
    async with ServiceSession() as db, db.begin():
        row = await _pending(db, token)
        if row is None or row.invite_expires_at <= datetime.now(UTC) or row.status != "active":
            raise _gone()
        if (user.email or "").lower() != row.email:
            raise HTTPException(
                status_code=403,
                detail=f"This invitation is for {row.email}. "
                "Sign in with that address to accept it.",
            )
        already = await db.scalar(
            text("SELECT role FROM tenant_members WHERE tenant_id = :t AND user_id = :u"),
            {"t": row.tenant_id, "u": user.user_id},
        )
        if already is not None:
            await db.execute(text("DELETE FROM tenant_members WHERE id = :m"), {"m": row.id})
            return Accepted(tenant_id=row.tenant_id, role=already)
        await db.execute(
            text(
                "UPDATE tenant_members SET user_id = :u, joined_at = now(), invite_hash = NULL, "
                "invite_expires_at = NULL, display_name = :n WHERE id = :m"
            ),
            {"u": user.user_id, "n": user.name, "m": row.id},
        )
        # The member's verified email becomes one of the organisation's
        # alert contacts (removed again when they leave); they pick which
        # rules notify it like any other contact.
        await db.execute(
            text(
                "INSERT INTO notification_channels "
                "(tenant_id, type, target, label, source, verified_at) "
                "VALUES (:t, 'email', :e, :l, 'team', now()) ON CONFLICT DO NOTHING"
            ),
            {"t": row.tenant_id, "e": row.email, "l": user.name or row.email},
        )
        return Accepted(tenant_id=row.tenant_id, role=row.role)
