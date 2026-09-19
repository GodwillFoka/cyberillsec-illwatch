"""Endpoint de diagnostic — `GET /health` (critère de validation du jalon M1)."""

from typing import Annotated, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app.config import Settings, get_settings
from sentry.app.database import get_db

router = APIRouter(tags=["diagnostic"])


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    version: str
    environment: str
    database: Literal["connected", "unreachable"]


@router.get("/health", response_model=HealthResponse, summary="Vivacité et connexion base")
async def health(
    session: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> HealthResponse:
    """Vérifie que le process répond et que la base de données est joignable."""
    try:
        await session.execute(text("SELECT 1"))
        database: Literal["connected", "unreachable"] = "connected"
    except Exception:  # noqa: BLE001 - l'état dégradé est une réponse métier, pas une erreur HTTP
        database = "unreachable"

    return HealthResponse(
        status="ok" if database == "connected" else "degraded",
        version=settings.app_version,
        environment=settings.environment,
        database=database,
    )
