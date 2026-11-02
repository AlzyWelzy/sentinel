"""Emails about the account itself: verification, password reset, invitations.

They're queued in account_emails, in the caller's transaction, and the
alerter sends them through the same SMTP sender and retries as alerts. The
API never talks to a mail server itself.
"""

import html
import json
from urllib.parse import quote

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings

PRODUCT = "Sentinel"


def _link(path: str, token: str) -> str:
    return f"{settings.PUBLIC_APP_URL.rstrip('/')}{path}?token={quote(token)}"


def render(heading: str, paragraphs: list[str], button: tuple[str, str] | None) -> tuple[str, str]:
    """The plain-text and HTML bodies of one account email."""
    lines = [heading, "", *paragraphs]
    if button:
        lines += ["", f"{button[0]}: {button[1]}"]
    lines += ["", f"— {PRODUCT}"]
    body = "".join(
        '<p style="margin:0 0 14px;color:#374151;font-size:15px;line-height:1.55">'
        f"{html.escape(p)}</p>"
        for p in paragraphs
    )
    cta = ""
    if button:
        cta = (
            f'<p style="margin:22px 0"><a href="{html.escape(button[1], quote=True)}" '
            'style="background:#4f46e5;color:#ffffff;text-decoration:none;padding:11px 20px;'
            f'border-radius:8px;font-weight:600;font-size:15px;display:inline-block">'
            f"{html.escape(button[0])}</a></p>"
            '<p style="margin:0 0 14px;color:#6b7280;font-size:13px;line-height:1.5">'
            "If the button doesn't work, paste this into your browser:<br>"
            f'<span style="word-break:break-all">{html.escape(button[1])}</span></p>'
        )
    page = (
        '<!doctype html><html><body style="margin:0;background:#f4f5f7;padding:28px 12px;'
        'font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif">'
        '<table role="presentation" width="100%" cellspacing="0" cellpadding="0">'
        '<tr><td align="center">'
        '<table role="presentation" width="100%" style="max-width:520px;background:#ffffff;'
        'border-radius:12px;padding:28px" cellspacing="0" cellpadding="0"><tr><td>'
        '<div style="font-weight:700;font-size:16px;color:#4f46e5;margin-bottom:18px">'
        f"{PRODUCT}</div>"
        f'<h1 style="margin:0 0 16px;font-size:20px;color:#111827">{html.escape(heading)}</h1>'
        f"{body}{cta}"
        "</td></tr></table></td></tr></table></body></html>"
    )
    return "\n".join(lines), page


async def _queue(db: AsyncSession, to: str, kind: str, subject: str, txt: str, htm: str) -> None:
    await db.execute(
        text(
            "INSERT INTO account_emails (to_address, kind, payload) "
            "VALUES (:to, :k, CAST(:p AS jsonb))"
        ),
        {"to": to, "k": kind, "p": json.dumps({"subject": subject, "text": txt, "html": htm})},
    )


def _hello(name: str | None) -> str:
    return f"Hi {name}," if name else "Hi,"


async def verify_email(db: AsyncSession, to: str, name: str | None, token: str) -> None:
    txt, htm = render(
        "Confirm your email",
        [
            _hello(name),
            f"Confirm this address to finish creating your {PRODUCT} account. "
            "The link works for 24 hours.",
            "If you didn't sign up, ignore this email.",
        ],
        ("Confirm email", _link("/verify", token)),
    )
    await _queue(db, to, "verify_email", f"Confirm your {PRODUCT} email", txt, htm)


async def already_registered(db: AsyncSession, to: str, name: str | None) -> None:
    txt, htm = render(
        "You already have an account",
        [
            _hello(name),
            "Someone tried to sign up with this address, which already has an account.",
            "If that was you, sign in instead, or reset your password if you've forgotten it.",
        ],
        ("Sign in", f"{settings.PUBLIC_APP_URL.rstrip('/')}/login"),
    )
    await _queue(db, to, "verify_email", f"Your {PRODUCT} account", txt, htm)


async def reset_password(db: AsyncSession, to: str, name: str | None, token: str) -> None:
    txt, htm = render(
        "Reset your password",
        [
            _hello(name),
            "Use the link below to choose a new password. It works for an hour, once.",
            "If you didn't ask for this, ignore this email: your password stays the same.",
        ],
        ("Choose a new password", _link("/reset", token)),
    )
    await _queue(db, to, "reset_password", f"Reset your {PRODUCT} password", txt, htm)


async def password_changed(db: AsyncSession, to: str, name: str | None) -> None:
    txt, htm = render(
        "Your password was changed",
        [
            _hello(name),
            "The password for your account was just changed, and every browser was signed out.",
            "If this wasn't you, reset your password now.",
        ],
        ("Reset password", f"{settings.PUBLIC_APP_URL.rstrip('/')}/forgot"),
    )
    await _queue(db, to, "password_changed", f"Your {PRODUCT} password was changed", txt, htm)


async def invitation(
    db: AsyncSession, to: str, inviter: str, org: str, role: str, token: str
) -> None:
    txt, htm = render(
        f"Join {org} on {PRODUCT}",
        [
            f"{inviter} invited you to the {org} organisation as {role}.",
            "The invitation works for 7 days. You'll sign in or create an account with "
            "this email address to accept it.",
        ],
        ("Accept invitation", _link("/invite", token)),
    )
    await _queue(db, to, "invitation", f"{inviter} invited you to {org}", txt, htm)
