import asyncpg
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import DBAPIError

from app.config import settings
from app.routes import (
    ack,
    admin,
    alerts,
    apm,
    apps,
    audit,
    auth,
    channels,
    checks,
    dashboards,
    deliveries,
    fleet,
    fleetview,
    hostops,
    insights,
    install,
    logs,
    maintenance,
    members,
    oncall,
    reports,
    saved_views,
    statuspages,
    tokens,
    tools,
    v1,
)
from app.strictjson import FiniteJSON

app = FastAPI(title="Sentinel API", version="0.9.0", root_path=settings.API_ROOT_PATH)

app.add_middleware(FiniteJSON)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["*"],
    allow_headers=["Authorization", "Content-Type", "X-Sentinel-Account", "X-Requested-With"],
    allow_credentials=True,
)


@app.exception_handler(DBAPIError)
async def _unstorable_text(request: Request, exc: DBAPIError) -> JSONResponse:
    """Text Postgres can't store (a NUL character, anywhere in a body or a
    query) is the client's mistake: answer 422 instead of failing the request."""
    cause = getattr(exc.orig, "__cause__", None)
    if isinstance(
        cause, asyncpg.CharacterNotInRepertoireError | asyncpg.UntranslatableCharacterError
    ):
        return JSONResponse(
            status_code=422, content={"detail": "Text can't contain NUL characters"}
        )
    raise exc


app.include_router(auth.router)
app.include_router(tools.router)
app.include_router(fleetview.router)
app.include_router(fleet.router)
app.include_router(v1.router)
app.include_router(channels.router)
app.include_router(alerts.router)
app.include_router(checks.router)
app.include_router(hostops.router)
app.include_router(apps.router)
app.include_router(tokens.router)
app.include_router(members.router)
app.include_router(logs.router)
app.include_router(saved_views.router)
app.include_router(audit.router)
app.include_router(oncall.router)
app.include_router(deliveries.router)
app.include_router(dashboards.router)
app.include_router(apm.router)
app.include_router(statuspages.router)
app.include_router(statuspages.public)
app.include_router(reports.router)
app.include_router(insights.router)
app.include_router(maintenance.router)
app.include_router(ack.router)
app.include_router(install.router)
app.include_router(admin.router)


@app.get("/healthz", include_in_schema=False)
async def healthz() -> dict[str, str]:
    return {"status": "ok"}
