"""M7 Production Hardening — en-têtes, identifiant de requête, erreurs, sondes, réglages."""

import os
from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app import database
from sentry.app.api.health import get_redis_probe
from sentry.app.config import Settings, get_settings
from sentry.app.database import get_db
from sentry.app.main import create_app
from sentry.app.middleware import SecurityMiddleware, request_id_from
from sentry.app.migrations import head_revision

STRONG_KEY = "k" * 48
PROD_REDIS = "redis://:Xk29-long-random@localhost:6379/0"
PROD_DB = "postgresql+asyncpg://sentry_app:Zq7-long-random@localhost:5432/sentry_test"


# --- En-têtes et identifiant de requête ------------------------------------------------------


async def test_entetes_de_securite_sur_l_api(client: AsyncClient) -> None:
    response = await client.get("/api/v1/incidents")
    headers = response.headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'"
    assert headers["cache-control"] == "no-store"
    assert "strict-transport-security" not in headers  # développement : pas de HSTS
    assert len(headers["x-request-id"]) == 32


async def test_documentation_sans_csp_stricte(client: AsyncClient) -> None:
    """Swagger UI charge ses ressources depuis un CDN : la CSP stricte ne s'y applique pas."""
    response = await client.get("/docs")
    assert response.status_code == 200
    assert "content-security-policy" not in response.headers
    assert response.headers["x-content-type-options"] == "nosniff"


async def test_identifiant_de_requete_repris_ou_remplace(client: AsyncClient) -> None:
    sure = await client.get("/health", headers={"X-Request-ID": "proxy-42.abc"})
    assert sure.headers["x-request-id"] == "proxy-42.abc"
    hostile = await client.get("/health", headers={"X-Request-ID": "x\r\nSet-Cookie: a=b"})
    assert hostile.headers["x-request-id"] != "x\r\nSet-Cookie: a=b"
    assert request_id_from("a" * 65) != "a" * 65
    assert request_id_from(None)


async def test_hsts_active_sur_demande() -> None:
    inner = FastAPI()

    @inner.get("/ping")
    async def ping() -> dict[str, str]:
        return {"ok": "oui"}

    app = SecurityMiddleware(inner, hsts=True)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as http:
        response = await http.get("/ping")
    assert response.headers["strict-transport-security"].startswith("max-age=31536000")


async def test_erreur_interne_sans_fuite(db_session: AsyncSession) -> None:
    app = create_app()

    @app.get("/boom")
    async def boom() -> None:
        raise RuntimeError("chaîne de connexion postgresql://secret@db")

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://t") as http:
        response = await http.get("/boom", headers={"X-Request-ID": "req-123"})
    assert response.status_code == 500
    assert response.json() == {"detail": "Erreur interne du serveur.", "request_id": "req-123"}
    assert "secret" not in response.text


# --- Sondes ------------------------------------------------------------------------------------


def _app_with(db_session: AsyncSession, redis_up: bool) -> FastAPI:
    app = create_app()

    async def _db() -> AsyncSession:
        return db_session

    async def _probe(_: str) -> bool:
        return redis_up

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_redis_probe] = lambda: _probe
    return app


async def test_ready_refuse_un_schema_non_migre(db_session: AsyncSession) -> None:
    app = _app_with(db_session, redis_up=True)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as http:
        response = await http.get("/ready")
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "not_ready"
    assert body["checks"] == {"database": "ok", "schema": "fail", "redis": "ok"}


async def test_ready_quand_schema_a_jour_redis_non_bloquant(db_session: AsyncSession) -> None:
    await db_session.execute(
        text("CREATE TABLE IF NOT EXISTS alembic_version (version_num VARCHAR(32))")
    )
    await db_session.execute(text("DELETE FROM alembic_version"))
    await db_session.execute(
        text("INSERT INTO alembic_version VALUES (:v)"), {"v": head_revision()}
    )
    app = _app_with(db_session, redis_up=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as http:
        response = await http.get("/ready")
        head = await http.head("/ready")
    assert response.status_code == 200, response.text
    assert response.json()["checks"] == {"database": "ok", "schema": "ok", "redis": "degraded"}
    assert head.status_code == 200


async def test_health_accepte_head(client: AsyncClient) -> None:
    assert (await client.head("/health")).status_code == 200


# --- Réglages de production ----------------------------------------------------------------------


@pytest.fixture
def production_env() -> Iterator[None]:
    saved = {
        k: os.environ.get(k) for k in ("ENVIRONMENT", "SECRET_KEY", "REDIS_URL", "DATABASE_URL")
    }
    os.environ["ENVIRONMENT"] = "production"
    os.environ["SECRET_KEY"] = STRONG_KEY
    os.environ["REDIS_URL"] = PROD_REDIS
    os.environ["DATABASE_URL"] = PROD_DB
    get_settings.cache_clear()
    try:
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        get_settings.cache_clear()
        # Le moteur global a pu être créé avec l'URL de production fictive : l'oublier, sinon
        # les tests suivants (CLI) se connecteraient avec cet identifiant.
        database._engine = None
        database._session_factory = None


@pytest.mark.usefixtures("production_env")
async def test_production_masque_la_documentation_et_active_hsts() -> None:
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as http:
        assert (await http.get("/docs")).status_code == 404
        assert (await http.get("/openapi.json")).status_code == 404
        response = await http.get("/api/v1/incidents")
    assert "strict-transport-security" in response.headers


def test_production_refuse_cors_ouvert() -> None:
    with pytest.raises(ValidationError, match="CORS_ORIGINS"):
        Settings(
            environment="production",
            secret_key=STRONG_KEY,
            redis_url=PROD_REDIS,
            database_url=PROD_DB,
            cors_origins=["*"],
        )
    prod = {
        "environment": "production",
        "secret_key": STRONG_KEY,
        "redis_url": PROD_REDIS,
        "database_url": PROD_DB,
    }
    assert Settings(**prod).expose_docs is False  # type: ignore[arg-type]
    assert Settings(environment="development").expose_docs is True
    assert Settings(**prod, docs_enabled=True).expose_docs  # type: ignore[arg-type]
