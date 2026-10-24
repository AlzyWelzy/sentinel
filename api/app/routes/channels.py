"""Notification channels: where alerts go.

The console email is added (already verified) when the tenant is created.
Anything a user adds starts unverified and gets a 6-digit code; the alerter
only sends alerts to verified channels, so nobody can point alerts at an
inbox or phone they don't control.
"""

import re
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Literal
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select, update

from app.config import settings
from app.models import NotificationChannel, OutboundMessage
from app.services.secrets import hash_secret
from app.tenancy import Tenant, TenantContext

router = APIRouter(prefix="/v1/channels")

CODE_TTL = timedelta(minutes=30)
RESEND_AFTER = timedelta(seconds=60)
MAX_CODE_ATTEMPTS = 5

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_RE = re.compile(r"^\+[1-9]\d{6,14}$")  # E.164


class ChannelIn(BaseModel):
    type: Literal["email", "sms", "webhook"]
    target: str = Field(min_length=3, max_length=500)
    label: str | None = Field(default=None, max_length=100)

    @model_validator(mode="after")
    def _validate_target(self) -> "ChannelIn":
        self.target = self.target.strip()
        if self.type == "email" and not EMAIL_RE.match(self.target):
            raise ValueError("target must be an email address")
        if self.type == "sms" and not PHONE_RE.match(self.target):
            raise ValueError("target must be a phone number in E.164 format, e.g. +919876543210")
        if self.type == "webhook":
            url = urlparse(self.target)
            allowed = {"https"} if settings.ENVIRONMENT == "production" else {"https", "http"}
            if url.scheme not in allowed or not url.hostname:
                raise ValueError(f"target must be a {' or '.join(sorted(allowed))} URL")
        return self


class ChannelOut(BaseModel):
    id: uuid.UUID
    type: str
    target: str
    label: str | None
    source: str
    is_default: bool
    verified: bool
    created_at: datetime


class VerifyIn(BaseModel):
    code: str = Field(pattern=r"^\d{6}$")


def _out(c: NotificationChannel) -> ChannelOut:
    return ChannelOut(
        id=c.id,
        type=c.type,
        target=c.target,
        label=c.label,
        source=c.source,
        is_default=c.is_default,
        verified=c.verified_at is not None,
        created_at=c.created_at,
    )


def _code_hash(channel_id: uuid.UUID, code: str) -> str:
    # Salted with the channel id, so equal codes on two channels hash differently.
    return hash_secret(f"{channel_id}:{code}")


async def _get(t: TenantContext, channel_id: uuid.UUID) -> NotificationChannel:
    channel = await t.db.scalar(
        select(NotificationChannel).where(
            NotificationChannel.id == channel_id, NotificationChannel.tenant_id == t.tenant_id
        )
    )
    if channel is None:
        raise HTTPException(status_code=404, detail="Channel not found")
    return channel


async def _send_code(t: TenantContext, channel: NotificationChannel) -> None:
    now = datetime.now(UTC)
    if channel.verification_sent_at and now - channel.verification_sent_at < RESEND_AFTER:
        raise HTTPException(
            status_code=429, detail="A code was just sent; wait a minute before asking again"
        )
    code = f"{secrets.randbelow(1_000_000):06d}"
    channel.verification_code_hash = _code_hash(channel.id, code)
    channel.verification_sent_at = now
    channel.verification_attempts = 0
    t.db.add(
        OutboundMessage(
            tenant_id=t.tenant_id,
            channel_id=channel.id,
            kind="verification",
            payload={
                "subject": "[Pulsegrid] Your verification code",
                # {{code}} is filled in at send time; the dispatcher drops the
                # code from the stored payload once it's delivered.
                "text": (
                    "Your Pulsegrid verification code is {{code}}.\n\n"
                    "Enter it in the dashboard to start receiving alerts here. "
                    "It expires in 30 minutes. If you didn't ask for this, ignore this message."
                ),
                "code": code,
                "event": {"type": "verification", "channel_id": str(channel.id)},
            },
        )
    )


@router.get("")
async def list_channels(t: Tenant) -> list[ChannelOut]:
    rows = await t.db.scalars(
        select(NotificationChannel)
        .where(NotificationChannel.tenant_id == t.tenant_id)
        .order_by(NotificationChannel.created_at)
    )
    return [_out(c) for c in rows]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_channel(body: ChannelIn, t: Tenant) -> ChannelOut:
    exists = await t.db.scalar(
        select(NotificationChannel.id).where(
            NotificationChannel.tenant_id == t.tenant_id,
            NotificationChannel.type == body.type,
            NotificationChannel.target == body.target,
        )
    )
    if exists:
        raise HTTPException(status_code=409, detail="Channel already exists")
    channel = NotificationChannel(
        tenant_id=t.tenant_id,
        type=body.type,
        target=body.target,
        label=body.label,
        source="user",
        is_default=False,
    )
    t.db.add(channel)
    await t.db.flush()
    await _send_code(t, channel)
    await t.db.flush()
    await t.db.refresh(channel)
    return _out(channel)


@router.post("/{channel_id}/verification", status_code=status.HTTP_202_ACCEPTED)
async def resend_code(channel_id: uuid.UUID, t: Tenant) -> None:
    channel = await _get(t, channel_id)
    if channel.verified_at is not None:
        raise HTTPException(status_code=409, detail="Channel is already verified")
    await _send_code(t, channel)


@router.post("/{channel_id}/verify", response_model=ChannelOut)
async def verify(channel_id: uuid.UUID, body: VerifyIn, t: Tenant) -> ChannelOut | JSONResponse:
    channel = await _get(t, channel_id)
    if channel.verified_at is not None:
        return _out(channel)
    expired = (
        channel.verification_sent_at is None
        or datetime.now(UTC) - channel.verification_sent_at > CODE_TTL
    )
    if channel.verification_code_hash is None or expired:
        raise HTTPException(status_code=410, detail="Code expired; request a new one")
    if channel.verification_attempts >= MAX_CODE_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Too many attempts; request a new code")
    if not secrets.compare_digest(
        channel.verification_code_hash, _code_hash(channel.id, body.code)
    ):
        # Returned rather than raised: raising rolls the transaction back,
        # which would undo the attempt count and allow unlimited guesses.
        channel.verification_attempts += 1
        return JSONResponse(status_code=400, content={"detail": "Wrong code"})
    channel.verified_at = datetime.now(UTC)
    channel.verification_code_hash = None
    return _out(channel)


@router.post("/{channel_id}/test", status_code=status.HTTP_202_ACCEPTED)
async def send_test(channel_id: uuid.UUID, t: Tenant) -> None:
    channel = await _get(t, channel_id)
    if channel.verified_at is None:
        raise HTTPException(status_code=409, detail="Verify this channel first")
    t.db.add(
        OutboundMessage(
            tenant_id=t.tenant_id,
            channel_id=channel.id,
            kind="test",
            payload={
                "subject": "[Pulsegrid] Test notification",
                "text": "This is a test from Pulsegrid. Alerts for your servers will arrive here.",
                "event": {"type": "test", "channel_id": str(channel.id)},
            },
        )
    )


@router.post("/{channel_id}/default")
async def make_default(channel_id: uuid.UUID, t: Tenant) -> ChannelOut:
    channel = await _get(t, channel_id)
    if channel.verified_at is None:
        raise HTTPException(status_code=409, detail="Verify this channel first")
    await t.db.execute(
        update(NotificationChannel)
        .where(NotificationChannel.tenant_id == t.tenant_id, NotificationChannel.is_default)
        .values(is_default=False)
    )
    await t.db.flush()  # one-default-per-tenant index
    channel.is_default = True
    return _out(channel)


@router.delete("/{channel_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_channel(channel_id: uuid.UUID, t: Tenant) -> None:
    channel = await _get(t, channel_id)
    successor = await t.db.scalar(
        select(NotificationChannel)
        .where(
            NotificationChannel.tenant_id == t.tenant_id,
            NotificationChannel.id != channel.id,
            NotificationChannel.verified_at.is_not(None),
        )
        .order_by(NotificationChannel.created_at)
        .limit(1)
    )
    if successor is None:
        raise HTTPException(
            status_code=409, detail="Keep at least one verified notification channel"
        )
    was_default = channel.is_default
    await t.db.delete(channel)
    if was_default:
        await t.db.flush()  # the one-default-per-tenant index needs the old row gone first
        successor.is_default = True
