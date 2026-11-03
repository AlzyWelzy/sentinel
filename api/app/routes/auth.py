"""Sign-up, sign-in and the signed-in user's own settings.

The access token goes back in the response body (the web app keeps it in
memory); the refresh token only ever travels in an httpOnly, SameSite=Strict
cookie scoped to /auth. Endpoints that read that cookie also require the
X-Requested-With header, which a cross-site form can't send.
"""

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field

from app.auth.principal import Principal
from app.config import settings
from app.services import accounts, captcha, invitations, ratelimit
from app.tenancy import current_principal

router = APIRouter(prefix="/auth", tags=["auth"])

REFRESH_COOKIE = "pg_refresh"
CSRF_HEADER = "X-Requested-With"


def _cookie_path() -> str:
    return f"{settings.API_ROOT_PATH.rstrip('/')}/auth"


def _set_refresh(response: Response, token: str) -> None:
    response.set_cookie(
        REFRESH_COOKIE,
        token,
        max_age=settings.REFRESH_TOKEN_TTL_DAYS * 86400,
        path=_cookie_path(),
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="strict",
    )


def _clear_refresh(response: Response) -> None:
    response.delete_cookie(
        REFRESH_COOKIE, path=_cookie_path(), secure=settings.COOKIE_SECURE, httponly=True
    )


def _require_csrf_header(x_requested_with: str | None) -> None:
    if not x_requested_with:
        raise HTTPException(status_code=403, detail=f"Missing {CSRF_HEADER} header")


async def signed_in_user(
    principal: Annotated[Principal, Depends(current_principal)],
) -> Principal:
    """A person signed in as themselves: not an API token, not a superadmin
    working in someone else's organisation."""
    if principal.user_id is None or principal.api_token_id is not None:
        raise HTTPException(status_code=403, detail="Sign in to do this")
    if principal.impersonated:
        raise HTTPException(status_code=403, detail="Not while working in another organisation")
    return principal


User = Annotated[Principal, Depends(signed_in_user)]


class UserOut(BaseModel):
    id: uuid.UUID
    email: str
    name: str | None
    email_verified: bool
    totp_enabled: bool
    recovery_codes_left: int = 0
    superadmin: bool
    created_at: datetime


class SessionOut(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 (the scheme, not a secret)
    expires_in: int
    user: UserOut


def _signed_in(response: Response, s: accounts.SignedIn) -> SessionOut:
    _set_refresh(response, s.refresh_token)
    return SessionOut(
        access_token=s.access_token,
        expires_in=settings.ACCESS_TOKEN_TTL_SECONDS,
        user=UserOut(**s.user),
    )


class Accepted(BaseModel):
    ok: bool = True
    message: str


class SessionRow(BaseModel):
    id: uuid.UUID
    created_at: datetime
    last_used_at: datetime
    ip: str | None
    user_agent: str | None
    current: bool


class AuthConfig(BaseModel):
    signup_enabled: bool
    turnstile_site_key: str | None
    password_min_length: int


@router.get("/config")
async def auth_config() -> AuthConfig:
    return AuthConfig(
        signup_enabled=settings.SIGNUP_ENABLED,
        turnstile_site_key=settings.TURNSTILE_SITE_KEY if captcha.enabled() else None,
        password_min_length=accounts.native.MIN_PASSWORD_LENGTH,
    )


class SignUpIn(BaseModel):
    email: EmailStr
    password: str = Field(max_length=256)
    name: str | None = Field(default=None, max_length=100)
    captcha_token: str | None = None


@router.post("/signup", status_code=status.HTTP_202_ACCEPTED)
async def sign_up(body: SignUpIn, request: Request) -> Accepted:
    if not settings.SIGNUP_ENABLED:
        raise HTTPException(status_code=403, detail="Sign-up is closed")
    ip = ratelimit.client_ip(request)
    await ratelimit.hit("signup-ip", ip, 10, 3600)
    await ratelimit.hit("signup-email", body.email.lower(), 5, 3600)
    await captcha.require(body.captcha_token, ip)
    await accounts.sign_up(body.email, body.password, body.name)
    return Accepted(message="Check your email for a link to confirm your address.")


class TokenIn(BaseModel):
    token: str = Field(min_length=10, max_length=200)


@router.post("/verify")
async def verify(body: TokenIn, request: Request, response: Response) -> SessionOut:
    await ratelimit.hit("verify-ip", ratelimit.client_ip(request), 30, 600)
    s = await accounts.verify_email(
        body.token, ratelimit.client_ip(request), request.headers.get("user-agent")
    )
    return _signed_in(response, s)


class EmailIn(BaseModel):
    email: EmailStr
    captcha_token: str | None = None


@router.post("/verify/resend", status_code=status.HTTP_202_ACCEPTED)
async def resend(body: EmailIn, request: Request) -> Accepted:
    await ratelimit.hit("resend-ip", ratelimit.client_ip(request), 10, 3600)
    await ratelimit.hit("resend-email", body.email.lower(), 3, 3600)
    await accounts.resend_verification(body.email)
    return Accepted(message="If that address is waiting to be confirmed, a new link is on its way.")


class SignInIn(BaseModel):
    email: EmailStr
    password: str = Field(max_length=256)
    totp_code: str | None = Field(default=None, max_length=12)


@router.post("/login")
async def sign_in(body: SignInIn, request: Request, response: Response) -> SessionOut:
    ip = ratelimit.client_ip(request)
    await ratelimit.hit("login-ip", ip, 30, 600)
    await ratelimit.hit("login-email", body.email.lower(), 15, 600)
    s = await accounts.sign_in(
        body.email, body.password, body.totp_code, ip, request.headers.get("user-agent")
    )
    return _signed_in(response, s)


@router.post("/refresh")
async def refresh(
    request: Request,
    response: Response,
    pg_refresh: Annotated[str | None, Cookie()] = None,
    x_requested_with: Annotated[str | None, Header()] = None,
) -> SessionOut:
    _require_csrf_header(x_requested_with)
    await ratelimit.hit("refresh-ip", ratelimit.client_ip(request), 120, 60)
    if not pg_refresh:
        raise HTTPException(
            status_code=401, detail={"code": "session_ended", "message": "Signed out"}
        )
    try:
        s = await accounts.refresh(pg_refresh)
    except HTTPException:
        _clear_refresh(response)
        raise
    return _signed_in(response, s)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def sign_out(
    response: Response,
    pg_refresh: Annotated[str | None, Cookie()] = None,
    x_requested_with: Annotated[str | None, Header()] = None,
) -> None:
    _require_csrf_header(x_requested_with)
    if pg_refresh:
        await accounts.sign_out(pg_refresh)
    _clear_refresh(response)


@router.post("/password/forgot", status_code=status.HTTP_202_ACCEPTED)
async def forgot(body: EmailIn, request: Request) -> Accepted:
    ip = ratelimit.client_ip(request)
    await ratelimit.hit("forgot-ip", ip, 10, 3600)
    await ratelimit.hit("forgot-email", body.email.lower(), 3, 3600)
    await captcha.require(body.captcha_token, ip)
    await accounts.request_password_reset(body.email)
    return Accepted(message="If that address has an account, a reset link is on its way.")


class ResetIn(BaseModel):
    token: str = Field(min_length=10, max_length=200)
    password: str = Field(max_length=256)


@router.post("/password/reset", status_code=status.HTTP_204_NO_CONTENT)
async def reset(body: ResetIn, request: Request) -> None:
    await ratelimit.hit("reset-ip", ratelimit.client_ip(request), 20, 3600)
    await accounts.reset_password(body.token, body.password)


class ChangePasswordIn(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


@router.post("/password/change", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(body: ChangePasswordIn, user: User, response: Response) -> None:
    """Signs every browser out, this one too: the web app signs in again."""
    await ratelimit.hit("change-pw", str(user.user_id), 10, 3600)
    await accounts.change_password(str(user.user_id), body.current_password, body.new_password)
    _clear_refresh(response)


@router.get("/me")
async def me(user: User) -> UserOut:
    return UserOut(**await accounts.get_user(str(user.user_id)))


class ProfileIn(BaseModel):
    name: str | None = Field(default=None, max_length=100)


@router.patch("/me")
async def update_me(body: ProfileIn, user: User) -> UserOut:
    return UserOut(**await accounts.update_profile(str(user.user_id), body.name))


class DeleteAccountIn(BaseModel):
    password: str = Field(max_length=256)


@router.post("/me/delete", status_code=status.HTTP_204_NO_CONTENT)
async def delete_me(body: DeleteAccountIn, user: User, response: Response) -> None:
    """Deletes your account and the organisations only you are in."""
    await ratelimit.hit("delete-account", str(user.user_id), 5, 3600)
    await accounts.delete_account(str(user.user_id), body.password)
    _clear_refresh(response)


@router.get("/sessions")
async def sessions(user: User, request: Request) -> list[SessionRow]:
    rows = await accounts.list_sessions(str(user.user_id), request.state.session_id)
    return [SessionRow(**r) for r in rows]


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_session(session_id: uuid.UUID, user: User) -> None:
    await accounts.revoke_session(str(user.user_id), session_id)


class TotpSetupOut(BaseModel):
    secret: str
    otpauth_uri: str


@router.post("/totp/setup")
async def totp_setup(user: User) -> TotpSetupOut:
    return TotpSetupOut(**await accounts.totp_setup(str(user.user_id)))


class CodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=12)


class RecoveryCodesOut(BaseModel):
    recovery_codes: list[str] = Field(description="shown this once; each works once")


@router.post("/totp/enable")
async def totp_enable(body: CodeIn, user: User) -> RecoveryCodesOut:
    await ratelimit.hit("totp", str(user.user_id), 10, 600)
    return RecoveryCodesOut(recovery_codes=await accounts.totp_enable(str(user.user_id), body.code))


class TotpDisableIn(BaseModel):
    password: str = Field(max_length=256)
    code: str = Field(min_length=6, max_length=12)


@router.post("/totp/disable", status_code=status.HTTP_204_NO_CONTENT)
async def totp_disable(body: TotpDisableIn, user: User) -> None:
    await ratelimit.hit("totp", str(user.user_id), 10, 600)
    await accounts.totp_disable(str(user.user_id), body.password, body.code)


@router.post("/totp/recovery-codes")
async def totp_recovery_codes(body: TotpDisableIn, user: User) -> RecoveryCodesOut:
    """New recovery codes (password and a current code); the old ones stop working."""
    await ratelimit.hit("totp", str(user.user_id), 10, 600)
    codes = await accounts.totp_recovery_regenerate(str(user.user_id), body.password, body.code)
    return RecoveryCodesOut(recovery_codes=codes)


@router.get("/invitations/pending")
async def pending_invitations(user: User) -> list[invitations.PendingOut]:
    """Invitations sent to your verified email that you haven't answered."""
    return await invitations.pending_for(user)


@router.post("/invitations/pending/{member_id}/accept")
async def accept_pending_invitation(member_id: uuid.UUID, user: User) -> invitations.Accepted:
    return await invitations.accept_pending(member_id, user)


@router.get("/invitations/{token}")
async def invitation(token: str, request: Request) -> invitations.InvitationOut:
    """What an invitation is for, shown before signing in to accept it."""
    await ratelimit.hit("invite-ip", ratelimit.client_ip(request), 60, 600)
    return await invitations.preview(token)


@router.post("/invitations/{token}/accept")
async def accept_invitation(token: str, user: User) -> invitations.Accepted:
    return await invitations.accept(token, user)
