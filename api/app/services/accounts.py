"""Accounts: sign-up, email verification, sign-in, sessions, password reset
and two-factor codes.

Everything here runs as the service role (users and sessions aren't
tenant-scoped), in one transaction per call. Routes in routes/auth.py only
translate HTTP to these calls.

Security decisions:
- Responses never reveal whether an email has an account (sign-up and
  reset answer the same either way; sign-in checks a dummy hash).
- Failed sign-ins slow an account down (locked for 1, 2, 4 ... up to 60
  minutes after 5 failures) instead of locking it for good, so an attacker
  can't keep a user out; per-address limits in the routes stop spraying.
- Refresh tokens rotate on every use. Presenting one that was already
  rotated revokes its whole family, unless it was rotated in the last
  few seconds (two tabs refreshing at once).
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pyotp
from fastapi import HTTPException, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import native
from app.config import settings
from app.db import ServiceSession
from app.services import account_emails

VERIFY_TTL = timedelta(hours=24)
RESET_TTL = timedelta(hours=1)
LOCK_AFTER_FAILURES = 5
MAX_LOCK = timedelta(hours=1)
ROTATION_GRACE = timedelta(seconds=10)
TOTP_ISSUER = "Pulsegrid"


@dataclass(frozen=True)
class SignedIn:
    access_token: str
    refresh_token: str
    user: dict


def _now() -> datetime:
    return datetime.now(UTC)


def _unauthorized(detail: str, code: str = "invalid_credentials") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail={"code": code, "message": detail}
    )


def check_password_rules(password: str) -> None:
    if not native.MIN_PASSWORD_LENGTH <= len(password) <= native.MAX_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Use a password of {native.MIN_PASSWORD_LENGTH} to "
            f"{native.MAX_PASSWORD_LENGTH} characters",
        )


def user_out(row) -> dict:
    return {
        "id": str(row.id),
        "email": row.email,
        "name": row.name,
        "email_verified": row.email_verified_at is not None,
        "totp_enabled": row.totp_enabled_at is not None,
        "superadmin": bool(row.is_superadmin),
        "created_at": row.created_at.isoformat(),
    }


async def _user_by_email(db: AsyncSession, email: str):
    return (
        await db.execute(text("SELECT * FROM users WHERE email = :e"), {"e": email.lower()})
    ).one_or_none()


async def _user_by_id(db: AsyncSession, user_id: str | uuid.UUID):
    return (
        await db.execute(text("SELECT * FROM users WHERE id = :u"), {"u": user_id})
    ).one_or_none()


async def _new_link_token(
    db: AsyncSession, user_id: uuid.UUID, purpose: str, ttl: timedelta
) -> str:
    # One live link per purpose: a new one replaces any earlier.
    await db.execute(
        text(
            "UPDATE auth_tokens SET used_at = now() "
            "WHERE user_id = :u AND purpose = :p AND used_at IS NULL"
        ),
        {"u": user_id, "p": purpose},
    )
    token = native.new_opaque_token()
    await db.execute(
        text(
            "INSERT INTO auth_tokens (user_id, purpose, token_hash, expires_at) "
            "VALUES (:u, :p, :h, :x)"
        ),
        {"u": user_id, "p": purpose, "h": native.hash_token(token), "x": _now() + ttl},
    )
    return token


async def _use_link_token(db: AsyncSession, token: str, purpose: str):
    row = (
        await db.execute(
            text(
                "UPDATE auth_tokens SET used_at = now() "
                "WHERE token_hash = :h AND purpose = :p AND used_at IS NULL AND expires_at > now() "
                "RETURNING user_id"
            ),
            {"h": native.hash_token(token), "p": purpose},
        )
    ).one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This link has expired or was already used. Ask for a new one.",
        )
    return row.user_id


async def _sync_superadmin(db: AsyncSession, user) -> bool:
    """SUPERADMIN_EMAILS is the source of truth for verified accounts."""
    want = user.email_verified_at is not None and user.email in settings.superadmin_emails
    if want != user.is_superadmin:
        await db.execute(
            text("UPDATE users SET is_superadmin = :s WHERE id = :u"), {"s": want, "u": user.id}
        )
    return want


async def _start_session(db: AsyncSession, user, ip: str | None, ua: str | None) -> SignedIn:
    refresh = native.new_opaque_token()
    session_id = (
        await db.execute(
            text(
                "INSERT INTO user_sessions "
                "(user_id, family_id, refresh_hash, expires_at, ip, user_agent) "
                "VALUES (:u, gen_random_uuid(), :h, :x, :ip, :ua) RETURNING id"
            ),
            {
                "u": user.id,
                "h": native.hash_token(refresh),
                "x": _now() + timedelta(days=settings.REFRESH_TOKEN_TTL_DAYS),
                "ip": ip,
                "ua": (ua or "")[:300],
            },
        )
    ).scalar_one()
    superadmin = await _sync_superadmin(db, user)
    access = native.issue_access_token(
        str(user.id), str(session_id), user.email, user.name, superadmin=superadmin
    )
    out = user_out(user) | {"superadmin": superadmin}
    return SignedIn(access_token=access, refresh_token=refresh, user=out)


# ── Sign-up and verification ─────────────────────────────────────────────────


async def sign_up(email: str, password: str, name: str | None) -> None:
    """Creates the account and emails a verification link. An existing
    address gets a sign-in reminder instead, so the response is the same."""
    check_password_rules(password)
    email = email.strip().lower()
    async with ServiceSession() as db, db.begin():
        existing = await _user_by_email(db, email)
        if existing is not None:
            if existing.email_verified_at is None:
                token = await _new_link_token(db, existing.id, "verify", VERIFY_TTL)
                await account_emails.verify_email(db, email, existing.name, token)
            else:
                await account_emails.already_registered(db, email, existing.name)
            return
        user_id = (
            await db.execute(
                text(
                    "INSERT INTO users (email, name, password_hash) VALUES (:e, :n, :h) "
                    "ON CONFLICT (email) DO NOTHING RETURNING id"
                ),
                {
                    "e": email,
                    "n": (name or "").strip() or None,
                    "h": native.hash_password(password),
                },
            )
        ).scalar_one_or_none()
        if user_id is None:  # signed up a moment ago in another request
            return
        token = await _new_link_token(db, user_id, "verify", VERIFY_TTL)
        await account_emails.verify_email(db, email, name, token)


async def resend_verification(email: str) -> None:
    async with ServiceSession() as db, db.begin():
        user = await _user_by_email(db, email)
        if user is None or user.email_verified_at is not None:
            return
        token = await _new_link_token(db, user.id, "verify", VERIFY_TTL)
        await account_emails.verify_email(db, user.email, user.name, token)


async def verify_email(token: str, ip: str | None, ua: str | None) -> SignedIn:
    """Following the link proves the address and signs the user in."""
    async with ServiceSession() as db, db.begin():
        user_id = await _use_link_token(db, token, "verify")
        await db.execute(
            text(
                "UPDATE users SET email_verified_at = COALESCE(email_verified_at, now()), "
                "updated_at = now() WHERE id = :u"
            ),
            {"u": user_id},
        )
        user = await _user_by_id(db, user_id)
        if user.disabled_at is not None:
            raise _unauthorized("This account is disabled", "disabled")
        return await _start_session(db, user, ip, ua)


# ── Sign-in ───────────────────────────────────────────────────────────────────


async def sign_in(
    email: str, password: str, totp_code: str | None, ip: str | None, ua: str | None
) -> SignedIn:
    async with ServiceSession() as db, db.begin():
        user = await _user_by_email(db, email.strip())
        if user is not None and user.locked_until is not None and user.locked_until > _now():
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed attempts. Try again later or reset your password.",
                headers={"Retry-After": str(int((user.locked_until - _now()).total_seconds()) + 1)},
            )
        ok = native.check_password(user.password_hash if user else None, password)
        if user is None or not ok:
            if user is not None:
                await _failed(user)
            raise _unauthorized("Wrong email or password")
        if user.disabled_at is not None:
            raise _unauthorized("This account is disabled", "disabled")
        if user.email_verified_at is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"code": "email_unverified", "message": "Verify your email first"},
            )
        if user.totp_enabled_at is not None:
            if not totp_code:
                raise _unauthorized("Enter the code from your authenticator app", "totp_required")
            if not _totp_ok(user.totp_secret, totp_code):
                await _failed(user)
                raise _unauthorized("That code isn't right", "totp_invalid")
        params: dict = {"u": user.id}
        rehash = ""
        if native.password_needs_rehash(user.password_hash):
            rehash, params["h"] = ", password_hash = :h", native.hash_password(password)
        await db.execute(
            # rehash is one of two constant fragments, never user input.
            text(f"UPDATE users SET failed_logins = 0, locked_until = NULL{rehash} WHERE id = :u"),  # noqa: S608
            params,
        )
        return await _start_session(db, user, ip, ua)


async def _failed(user) -> None:
    failures = user.failed_logins + 1
    lock = None
    if failures >= LOCK_AFTER_FAILURES:
        lock = _now() + min(timedelta(minutes=2 ** (failures - LOCK_AFTER_FAILURES)), MAX_LOCK)
    # In its own transaction: the sign-in's rolls back when it fails.
    async with ServiceSession() as own, own.begin():
        await own.execute(
            text("UPDATE users SET failed_logins = :f, locked_until = :l WHERE id = :u"),
            {"f": failures, "l": lock, "u": user.id},
        )


def _totp_ok(stored: str | None, code: str) -> bool:
    if not stored:
        return False
    code = code.strip().replace(" ", "")
    return pyotp.TOTP(native.decrypt_secret(stored)).verify(code, valid_window=1)


# ── Sessions ──────────────────────────────────────────────────────────────────


async def refresh(token: str) -> SignedIn:
    reused_family = None
    async with ServiceSession() as db, db.begin():
        row = (
            await db.execute(
                text("SELECT * FROM user_sessions WHERE refresh_hash = :h FOR UPDATE"),
                {"h": native.hash_token(token)},
            )
        ).one_or_none()
        if row is None or row.revoked_at is not None or row.expires_at <= _now():
            raise _unauthorized("Signed out", "session_ended")
        if row.rotated_at is not None:
            # Within the grace two tabs refreshed at once: just refuse. Later,
            # an old token coming back means someone else has a copy.
            if _now() - row.rotated_at > ROTATION_GRACE:
                reused_family = row.family_id
        else:
            return await _rotate(db, row)
    if reused_family is not None:
        # After the row lock above is released.
        async with ServiceSession() as db, db.begin():
            await db.execute(
                text(
                    "UPDATE user_sessions SET revoked_at = now() "
                    "WHERE family_id = :f AND revoked_at IS NULL"
                ),
                {"f": reused_family},
            )
    raise _unauthorized("Signed out", "session_ended")


async def _rotate(db: AsyncSession, row) -> SignedIn:
    user = await _user_by_id(db, row.user_id)
    if user is None or user.disabled_at is not None:
        raise _unauthorized("Signed out", "session_ended")
    new = native.new_opaque_token()
    await db.execute(
        text("UPDATE user_sessions SET rotated_at = now() WHERE id = :id"), {"id": row.id}
    )
    session_id = (
        await db.execute(
            text(
                "INSERT INTO user_sessions "
                "(user_id, family_id, refresh_hash, expires_at, ip, user_agent, created_at) "
                "VALUES (:u, :f, :h, :x, :ip, :ua, :c) RETURNING id"
            ),
            {
                "u": row.user_id,
                "f": row.family_id,
                "h": native.hash_token(new),
                "x": row.expires_at,
                "ip": row.ip,
                "ua": row.user_agent,
                "c": row.created_at,
            },
        )
    ).scalar_one()
    superadmin = await _sync_superadmin(db, user)
    access = native.issue_access_token(
        str(user.id), str(session_id), user.email, user.name, superadmin=superadmin
    )
    return SignedIn(access, new, user_out(user) | {"superadmin": superadmin})


async def sign_out(token: str) -> None:
    async with ServiceSession() as db, db.begin():
        await db.execute(
            text(
                "UPDATE user_sessions SET revoked_at = now() WHERE revoked_at IS NULL "
                "AND family_id = "
                "(SELECT family_id FROM user_sessions WHERE refresh_hash = :h)"
            ),
            {"h": native.hash_token(token)},
        )


async def list_sessions(user_id: str, current_session: str | None) -> list[dict]:
    """One entry per signed-in browser (a family), with its latest use."""
    async with ServiceSession() as db, db.begin():
        rows = await db.execute(
            text(
                "SELECT DISTINCT ON (family_id) id, family_id, created_at, last_used_at, ip, "
                "user_agent FROM user_sessions "
                "WHERE user_id = :u AND revoked_at IS NULL AND expires_at > now() "
                "ORDER BY family_id, created_at DESC"
            ),
            {"u": user_id},
        )
        current_family = None
        if current_session:
            current_family = await db.scalar(
                text("SELECT family_id FROM user_sessions WHERE id = :s"), {"s": current_session}
            )
        return sorted(
            (
                {
                    "id": str(r.family_id),
                    "created_at": r.created_at.isoformat(),
                    "last_used_at": r.last_used_at.isoformat(),
                    "ip": r.ip,
                    "user_agent": r.user_agent,
                    "current": r.family_id == current_family,
                }
                for r in rows
                if r.id is not None
            ),
            key=lambda s: s["last_used_at"],
            reverse=True,
        )


async def revoke_session(user_id: str, family_id: uuid.UUID) -> None:
    async with ServiceSession() as db, db.begin():
        revoked = await db.scalars(
            text(
                "UPDATE user_sessions SET revoked_at = now() "
                "WHERE user_id = :u AND family_id = :f AND revoked_at IS NULL RETURNING id"
            ),
            {"u": user_id, "f": family_id},
        )
        if not revoked.all():
            raise HTTPException(status_code=404, detail="Session not found")


# ── Passwords ─────────────────────────────────────────────────────────────────


async def request_password_reset(email: str) -> None:
    async with ServiceSession() as db, db.begin():
        user = await _user_by_email(db, email.strip())
        if user is None or user.disabled_at is not None:
            return
        token = await _new_link_token(db, user.id, "reset", RESET_TTL)
        await account_emails.reset_password(db, user.email, user.name, token)


async def reset_password(token: str, password: str) -> None:
    """Sets the new password and signs every browser out. Following the
    link also proves the address."""
    check_password_rules(password)
    async with ServiceSession() as db, db.begin():
        user_id = await _use_link_token(db, token, "reset")
        await _set_password(db, user_id, password)
        await db.execute(
            text(
                "UPDATE users SET email_verified_at = COALESCE(email_verified_at, now()), "
                "failed_logins = 0, locked_until = NULL WHERE id = :u"
            ),
            {"u": user_id},
        )


async def change_password(user_id: str, current: str, new: str) -> None:
    check_password_rules(new)
    async with ServiceSession() as db, db.begin():
        user = await _user_by_id(db, user_id)
        if user is None or not native.check_password(user.password_hash, current):
            raise HTTPException(status_code=400, detail="Your current password isn't right")
        await _set_password(db, user.id, new)


async def _set_password(db: AsyncSession, user_id, password: str) -> None:
    await db.execute(
        text("UPDATE users SET password_hash = :h, updated_at = now() WHERE id = :u"),
        {"h": native.hash_password(password), "u": user_id},
    )
    await db.execute(
        text(
            "UPDATE user_sessions SET revoked_at = now() WHERE user_id = :u AND revoked_at IS NULL"
        ),
        {"u": user_id},
    )
    user = await _user_by_id(db, user_id)
    await account_emails.password_changed(db, user.email, user.name)


# ── Profile ───────────────────────────────────────────────────────────────────


async def get_user(user_id: str) -> dict:
    async with ServiceSession() as db, db.begin():
        user = await _user_by_id(db, user_id)
        if user is None:
            raise _unauthorized("Signed out", "session_ended")
        return user_out(user)


async def update_profile(user_id: str, name: str | None) -> dict:
    async with ServiceSession() as db, db.begin():
        await db.execute(
            text("UPDATE users SET name = :n, updated_at = now() WHERE id = :u"),
            {"n": (name or "").strip() or None, "u": user_id},
        )
        await db.execute(
            text("UPDATE tenant_members SET display_name = :n WHERE user_id = :u"),
            {"n": (name or "").strip() or None, "u": user_id},
        )
        return user_out(await _user_by_id(db, user_id))


# ── Two-factor (TOTP) ────────────────────────────────────────────────────────


async def totp_setup(user_id: str) -> dict:
    """A new secret, stored but not enabled until a code from it is confirmed."""
    secret = pyotp.random_base32()
    async with ServiceSession() as db, db.begin():
        user = await _user_by_id(db, user_id)
        if user.totp_enabled_at is not None:
            raise HTTPException(status_code=409, detail="Two-factor sign-in is already on")
        await db.execute(
            text("UPDATE users SET totp_secret = :s WHERE id = :u"),
            {"s": native.encrypt_secret(secret), "u": user_id},
        )
        uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name=TOTP_ISSUER)
        return {"secret": secret, "otpauth_uri": uri}


async def totp_enable(user_id: str, code: str) -> None:
    async with ServiceSession() as db, db.begin():
        user = await _user_by_id(db, user_id)
        if user.totp_enabled_at is not None:
            raise HTTPException(status_code=409, detail="Two-factor sign-in is already on")
        if not _totp_ok(user.totp_secret, code):
            raise HTTPException(status_code=400, detail="That code isn't right")
        await db.execute(
            text("UPDATE users SET totp_enabled_at = now() WHERE id = :u"), {"u": user_id}
        )


async def totp_disable(user_id: str, password: str, code: str) -> None:
    async with ServiceSession() as db, db.begin():
        user = await _user_by_id(db, user_id)
        if user.totp_enabled_at is None:
            return
        if not native.check_password(user.password_hash, password) or not _totp_ok(
            user.totp_secret, code
        ):
            raise HTTPException(status_code=400, detail="Password or code isn't right")
        await db.execute(
            text("UPDATE users SET totp_enabled_at = NULL, totp_secret = NULL WHERE id = :u"),
            {"u": user_id},
        )
