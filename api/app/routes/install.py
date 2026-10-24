from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

from app.config import settings

router = APIRouter()

_HERE = Path(__file__).parent.parent
_SH = (_HERE / "install.sh").read_text()
_PS1 = (_HERE / "install.ps1").read_text()


def _render(template: str) -> str:
    """The URLs inside come from config, so a domain move needs no new script."""
    return (
        template.replace("__DOWNLOAD_URL__", settings.PUBLIC_DOWNLOAD_URL)
        .replace("__INGEST_URL__", settings.PUBLIC_INGEST_URL)
        .replace("__AGENT_VERSION__", settings.AGENT_VERSION)
    )


@router.get("/install.sh", response_class=PlainTextResponse)
async def install_script() -> str:
    """Linux, FreeBSD, OpenBSD and NetBSD."""
    return _render(_SH)


@router.get("/install.ps1", response_class=PlainTextResponse)
async def install_script_windows() -> str:
    return _render(_PS1)
