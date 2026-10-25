import time
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

from app.config import settings
from app.db import ServiceSession
from app.services import rollout

router = APIRouter()

_HERE = Path(__file__).parent.parent
_SH = (_HERE / "install.sh").read_text()
_PS1 = (_HERE / "install.ps1").read_text()


_stable: tuple[float, str] = (0.0, "")


async def _stable_version() -> str:
    """New installs start on the rollout's stable version; servers in the
    canary move to the candidate on their first update check."""
    global _stable
    if time.monotonic() - _stable[0] < 60 and _stable[1]:
        return _stable[1]
    try:
        async with ServiceSession() as db:
            version = (await rollout.current(db)).stable_version
    except Exception:  # noqa: BLE001 (the database being down mustn't break installs)
        version = settings.AGENT_VERSION
    _stable = (time.monotonic(), version)
    return version


async def _render(template: str) -> str:
    """The URLs inside come from config, so a domain move needs no new script."""
    return (
        template.replace("__DOWNLOAD_URL__", settings.PUBLIC_DOWNLOAD_URL)
        .replace("__INGEST_URL__", settings.PUBLIC_INGEST_URL)
        .replace("__AGENT_VERSION__", await _stable_version())
    )


@router.get("/install.sh", response_class=PlainTextResponse)
async def install_script() -> str:
    """Linux, FreeBSD, OpenBSD and NetBSD."""
    return await _render(_SH)


@router.get("/install.ps1", response_class=PlainTextResponse)
async def install_script_windows() -> str:
    return await _render(_PS1)
