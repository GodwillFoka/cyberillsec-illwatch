"""Point d'entrée de l'application FastAPI ILLWATCH."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware

from illwatch.app.api.health import router as health_router
from illwatch.app.api.v1.router import api_router
from illwatch.app.config import get_settings
from illwatch.app.database import dispose_engine
from illwatch.app.middleware import SecurityMiddleware, unhandled_error, validation_error
from illwatch.shared.logging import configure_logging


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Cycle de vie applicatif : validation de la configuration puis nettoyage."""
    settings = get_settings()  # échoue tôt et bruyamment si la config est invalide (MOD-01)
    configure_logging(settings.log_level)  # journal JSON : accès, audit, erreurs (M7)
    yield
    await dispose_engine()


def create_app() -> FastAPI:
    """Fabrique de l'application — testable et réutilisable."""
    settings = get_settings()

    app = FastAPI(
        title="ILLWATCH — Security Monitoring & Threat Intelligence Platform",
        description=(
            "CyberillSec, a CYBERILL initiative. "
            "Plateforme CTI open source : collecte de flux de menaces, suivi CVE "
            "enrichi EPSS/KEV, scoring de risque composite, gestion d'incidents "
            "et threat hunting."
        ),
        version=settings.app_version,
        docs_url="/docs" if settings.expose_docs else None,
        redoc_url="/redoc" if settings.expose_docs else None,
        openapi_url="/openapi.json" if settings.expose_docs else None,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Ajouté en dernier : enveloppe CORS, donc ses en-têtes et son identifiant de requête
    # couvrent aussi les réponses de pré-vérification et les erreurs.
    app.add_middleware(SecurityMiddleware, hsts=settings.send_hsts)
    app.add_exception_handler(Exception, unhandled_error)
    app.add_exception_handler(RequestValidationError, validation_error)  # type: ignore[arg-type]

    app.include_router(health_router)
    app.include_router(api_router, prefix=settings.api_v1_prefix)

    return app


app = create_app()
