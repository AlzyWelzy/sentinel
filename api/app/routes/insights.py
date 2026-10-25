"""Insights: noisy rules, response times, rightsizing and SLO error budgets."""

from dataclasses import asdict
from typing import Annotated, Any

from fastapi import APIRouter, Query

from app.services import insights
from app.tenancy import Tenant

router = APIRouter(prefix="/v1")


@router.get("/insights")
async def get_insights(t: Tenant, days: Annotated[int, Query(ge=1, le=90)] = 30) -> dict[str, Any]:
    return asdict(await insights.build(t.db, t.tenant_id, days))
