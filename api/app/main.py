from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

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

app = FastAPI(title="Sentinel API", version="0.9.0", root_path=settings.API_ROOT_PATH)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["*"],
    allow_headers=["Authorization", "Content-Type", "X-Sentinel-Account", "X-Requested-With"],
    allow_credentials=True,
)

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

# In production the binaries come from the CDN at PUBLIC_DOWNLOAD_URL; locally
# the API serves whatever `make agent` put in dist/.
if Path(settings.AGENT_DIST_DIR).is_dir():
    app.mount("/agent", StaticFiles(directory=settings.AGENT_DIST_DIR), name="agent")


@app.get("/healthz", include_in_schema=False)
async def healthz() -> dict[str, str]:
    return {"status": "ok"}
