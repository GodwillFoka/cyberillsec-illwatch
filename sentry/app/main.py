"""Point d'entrée de l'application FastAPI SENTRY."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sentry.app.api.health import router as health_router
from sentry.app.api.v1.router import api_router
from sentry.app.config import get_settings
from sentry.app.database import dispose_engine


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Cycle de vie applicatif : validation de la configuration puis nettoyage."""
    get_settings()  # échoue tôt et bruyamment si la config est invalide (MOD-01)
    yield
    await dispose_engine()


def create_app() -> FastAPI:
    """Fabrique de l'application — testable et réutilisable."""
    settings = get_settings()

    app = FastAPI(
        title="SENTRY — Security Monitoring & Threat Intelligence Platform",
        description=(
            "CyberillSec, a CYBERILL initiative. "
            "Plateforme CTI open source : collecte de flux de menaces, suivi CVE "
            "enrichi EPSS/KEV, scoring de risque composite, gestion d'incidents "
            "et threat hunting."
        ),
        version=settings.app_version,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health_router)
    app.include_router(api_router, prefix=settings.api_v1_prefix)

    return app


app = create_app()
