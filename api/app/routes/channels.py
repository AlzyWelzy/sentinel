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
from typing import Annotated, Literal
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select, update

from app.config import settings
from app.models import NotificationChannel, OutboundMessage
from app.services import oncall
from app.services.secrets import hash_secret
from app.tenancy import Tenant, TenantContext
from app.validation import normalize_tag

router = APIRouter(prefix="/v1/channels")

CODE_TTL = timedelta(minutes=30)
RESEND_AFTER = timedelta(seconds=60)
MAX_CODE_ATTEMPTS = 5

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_RE = re.compile(r"^\+[1-9]\d{6,14}$")  # E.164
# "<bot token>/<chat id>": a bot from @BotFather, and a numeric chat id or @channel.
TELEGRAM_RE = re.compile(r"^\d{5,}:[A-Za-z0-9_-]{30,}/(-?\d{1,20}|@[A-Za-z0-9_]{5,32})$")
PAGERDUTY_KEY_RE = re.compile(r"^[A-Za-z0-9]{32}$")

# Chat webhooks must point at the service itself: the URL is customer input,
# and the alerter would otherwise POST wherever it says.
CHAT_HOSTS = {
    "slack": ("hooks.slack.com",),
    "teams": (".webhook.office.com", ".logic.azure.com", ".powerplatform.com"),
    "discord": ("discord.com", "discordapp.com"),
}

ChannelType = Literal[
    "email", "sms", "voice", "webhook", "slack", "teams", "discord", "telegram", "pagerduty"
]
Severity = Literal["critical", "warning", "info"]

# Browsers' push services. The alerter POSTs to the subscription's endpoint,
# so it must be one of these, never an arbitrary URL.
PUSH_HOSTS = (
    "fcm.googleapis.com",
    "android.googleapis.com",
    "updates.push.services.mozilla.com",
    ".push.services.mozilla.com",
    "web.push.apple.com",
    ".push.apple.com",
    ".notify.windows.com",
)
PUSH_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{16,200}={0,2}$")
# Targets that are secrets (anyone with the URL or key can post as you) are
# masked whenever they're returned.
SECRET_TARGETS = {"webhook", "slack", "teams", "discord", "telegram", "pagerduty"}


def _host_allowed(host: str, allowed: tuple[str, ...]) -> bool:
    return any(host == a.lstrip(".") or (a.startswith(".") and host.endswith(a)) for a in allowed)


OnlyTag = Annotated[
    str | None,
    Field(
        default=None,
        min_length=1,
        max_length=64,
        description="only alerts for servers and devices with this tag (a customer's)",
    ),
]


class ChannelIn(BaseModel):
    type: ChannelType
    target: str = Field(min_length=3, max_length=500)
    label: str | None = Field(default=None, max_length=100)
    min_severity: Severity = "info"
    only_tag: OnlyTag = None

    @model_validator(mode="after")
    def _validate_target(self) -> "ChannelIn":
        if self.type not in settings.ENABLED_CHANNEL_TYPES:
            raise ValueError(
                f"{self.type} contacts aren't available; use one of: "
                f"{', '.join(t for t in settings.ENABLED_CHANNEL_TYPES if t != 'push')}"
            )
        self.target = self.target.strip()
        if self.type == "email" and not EMAIL_RE.match(self.target):
            raise ValueError("target must be an email address")
        if self.type in ("sms", "voice") and not PHONE_RE.match(self.target):
            raise ValueError("target must be a phone number in E.164 format, e.g. +919876543210")
        if self.type == "webhook":
            url = urlparse(self.target)
            allowed = {"https"} if settings.ENVIRONMENT == "production" else {"https", "http"}
            if url.scheme not in allowed or not url.hostname:
                raise ValueError(f"target must be a {' or '.join(sorted(allowed))} URL")
        if self.type in CHAT_HOSTS:
            url = urlparse(self.target)
            hosts = CHAT_HOSTS[self.type]
            if url.scheme != "https" or not url.hostname or not _host_allowed(url.hostname, hosts):
                raise ValueError(
                    f"target must be your {self.type.title()} webhook URL (https://{hosts[0].lstrip('.')}/...)"
                )
            if self.type == "discord" and not url.path.startswith("/api/webhooks/"):
                raise ValueError(
                    "target must be a Discord webhook URL (https://discord.com/api/webhooks/...)"
                )
        if self.type == "telegram" and not TELEGRAM_RE.match(self.target):
            raise ValueError(
                "target must be <bot token>/<chat id>, e.g. 123456:ABC.../-1001234567890"
            )
        if self.type == "pagerduty" and not PAGERDUTY_KEY_RE.match(self.target):
            raise ValueError(
                "target must be a PagerDuty Events API v2 integration key (32 characters)"
            )
        return self


def mask_target(type_: str, target: str) -> str:
    """Enough to recognise a channel, not enough to use it."""
    if type_ == "push":
        host = urlparse(target).hostname or ""
        return {
            "fcm.googleapis.com": "Chrome / Edge / Android",
            "updates.push.services.mozilla.com": "Firefox",
            "web.push.apple.com": "Safari / iPhone",
        }.get(host, "Browser") + " push"
    if type_ not in SECRET_TARGETS:
        return target
    if type_ == "telegram":
        return "chat " + target.split("/", 1)[-1]
    if type_ == "pagerduty":
        return "key …" + target[-4:]
    url = urlparse(target)
    return f"{url.scheme}://{url.hostname}/…{target[-4:]}"


class QuietHours(BaseModel):
    """Alerts wait until `end`; critical ones still go out unless told not to."""

    start: str = Field(pattern=r"^([01]\d|2[0-3]):[0-5]\d$", examples=["22:00"])
    end: str = Field(pattern=r"^([01]\d|2[0-3]):[0-5]\d$", examples=["07:00"])
    timezone: str = "UTC"
    critical_breaks_through: bool = True

    @model_validator(mode="after")
    def _check(self) -> "QuietHours":
        if oncall.zone(self.timezone).key != self.timezone:
            raise ValueError("unknown time zone (use a name like Asia/Kolkata)")
        if self.start == self.end:
            raise ValueError("quiet hours start and end at different times")
        return self


class ChannelOut(BaseModel):
    id: uuid.UUID
    type: str
    target: str
    label: str | None
    source: str
    is_default: bool
    verified: bool
    undeliverable: bool = False
    undeliverable_reason: str | None = None
    min_severity: str
    quiet_hours: QuietHours | None = None
    only_tag: str | None = None
    created_at: datetime


class ChannelPatch(BaseModel):
    label: str | None = Field(default=None, max_length=100)
    min_severity: Severity | None = None
    only_tag: OnlyTag = None
    quiet_hours: QuietHours | None = Field(default=None, description="null to turn them off")


class PushKeys(BaseModel):
    p256dh: str = Field(pattern=PUSH_KEY_RE.pattern)
    auth: str = Field(pattern=PUSH_KEY_RE.pattern)


class PushSubscriptionIn(BaseModel):
    """What the browser's PushManager.subscribe() returns (subscription.toJSON())."""

    endpoint: str = Field(min_length=10, max_length=1000)
    keys: PushKeys
    label: str | None = Field(default=None, max_length=100)
    min_severity: Severity = "info"

    @model_validator(mode="after")
    def _endpoint(self) -> "PushSubscriptionIn":
        url = urlparse(self.endpoint)
        if url.scheme != "https" or not url.hostname or not _host_allowed(url.hostname, PUSH_HOSTS):
            raise ValueError("endpoint isn't a known browser push service")
        return self


class PushConfigOut(BaseModel):
    enabled: bool
    public_key: str


class VerifyIn(BaseModel):
    code: str = Field(pattern=r"^\d{6}$")


def _out(c: NotificationChannel) -> ChannelOut:
    return ChannelOut(
        id=c.id,
        type=c.type,
        target=mask_target(c.type, c.target),
        label=c.label,
        source=c.source,
        is_default=c.is_default,
        verified=c.verified_at is not None,
        undeliverable=c.undeliverable_at is not None,
        undeliverable_reason=c.undeliverable_reason,
        min_severity=c.min_severity,
        quiet_hours=QuietHours(**c.quiet_hours) if c.quiet_hours else None,
        only_tag=c.only_tag,
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
                "subject": "[Sentinel] Your verification code",
                # {{code}} is filled in at send time; the dispatcher drops the
                # code from the stored payload once it's delivered.
                "text": (
                    "Your Sentinel verification code is {{code}}.\n\n"
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
        min_severity=body.min_severity,
        only_tag=_tag(body.only_tag),
    )
    t.db.add(channel)
    await t.db.flush()
    await _send_code(t, channel)
    await t.db.flush()
    await t.db.refresh(channel)
    return _out(channel)


@router.get("/push/config")
async def push_config(t: Tenant) -> PushConfigOut:
    """The VAPID public key the browser subscribes with."""
    return PushConfigOut(
        enabled=bool(settings.VAPID_PUBLIC_KEY) and "push" in settings.ENABLED_CHANNEL_TYPES,
        public_key=settings.VAPID_PUBLIC_KEY,
    )


@router.post("/push", status_code=status.HTTP_201_CREATED)
async def add_push_subscription(body: PushSubscriptionIn, t: Tenant) -> ChannelOut:
    """Register this browser for push notifications. The subscription is
    proof of control (only that browser can receive on it), so it's verified
    at once. Subscribing again from the same browser updates its keys."""
    if not settings.VAPID_PUBLIC_KEY or "push" not in settings.ENABLED_CHANNEL_TYPES:
        raise HTTPException(status_code=409, detail="Push notifications aren't set up")
    channel = await t.db.scalar(
        select(NotificationChannel).where(
            NotificationChannel.tenant_id == t.tenant_id,
            NotificationChannel.type == "push",
            NotificationChannel.target == body.endpoint,
        )
    )
    keys = {"p256dh": body.keys.p256dh, "auth": body.keys.auth}
    if channel is None:
        channel = NotificationChannel(
            tenant_id=t.tenant_id,
            type="push",
            target=body.endpoint,
            label=body.label,
            source="user",
            is_default=False,
            verified_at=datetime.now(UTC),
            config=keys,
            min_severity=body.min_severity,
        )
        t.db.add(channel)
    else:
        channel.config = keys
        channel.label = body.label or channel.label
        channel.min_severity = body.min_severity
    await t.db.flush()
    await t.db.refresh(channel)
    return _out(channel)


@router.patch("/{channel_id}")
async def update_channel(channel_id: uuid.UUID, body: ChannelPatch, t: Tenant) -> ChannelOut:
    channel = await _get(t, channel_id)
    if "label" in body.model_fields_set:
        channel.label = body.label
    if body.min_severity is not None:
        channel.min_severity = body.min_severity
    if "quiet_hours" in body.model_fields_set:
        channel.quiet_hours = body.quiet_hours.model_dump() if body.quiet_hours else None
    if "only_tag" in body.model_fields_set:
        channel.only_tag = _tag(body.only_tag)
    await t.db.flush()
    return _out(channel)


def _tag(v: str | None) -> str | None:
    """Tags are stored lower-case and trimmed (validation.normalize_tags)."""
    if v is None:
        return None
    try:
        return normalize_tag(v)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=f"only_tag: {e}") from None


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
    channel.undeliverable_at = None
    channel.undeliverable_reason = None
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
                "subject": "[Sentinel] Test notification",
                "text": "This is a test from Sentinel. Alerts for your servers will arrive here.",
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
    if channel.type == "push" and not channel.is_default:
        # A browser subscription isn't anyone's only contact: email stays.
        await t.db.delete(channel)
        return
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
