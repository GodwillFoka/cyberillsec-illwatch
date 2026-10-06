"""Fixtures asynchrones partagées.

Base de test : `DATABASE_URL` si elle est définie (PostgreSQL 16 en CI et en
local via Docker Compose), sinon SQLite en mémoire pour un retour rapide sans
infrastructure. Les tests marqués `postgres` ne s'exécutent que sur PostgreSQL.

Isolation : chaque test travaille dans une transaction annulée à la fin ; la
base n'est jamais polluée d'un test à l'autre.
"""

import asyncio
import os
from collections.abc import AsyncGenerator

import pytest

# Jamais de `.env` dans les tests : celui du poste de développement (DEBUG=true,
# MIGRATION_DATABASE_URL vers la base de travail…) faisait échouer des tests et, surtout,
# envoyait leurs migrations sur la base de travail. Positionné avant tout import de `sentry`.
os.environ["SENTRY_ENV_FILE"] = ""
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes-long")

from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    create_async_engine,
)
from sqlalchemy.pool import NullPool, StaticPool  # noqa: E402

from sentry.app.config import get_settings  # noqa: E402
from sentry.app.database import Base, get_db  # noqa: E402
from sentry.app.main import create_app  # noqa: E402
from sentry.app.models import AuditEvent  # noqa: E402
from sentry.app.throttle import LocalCounter, LoginThrottle, get_login_throttle  # noqa: E402
from sentry.modules.foundation.audit import AuditRecorder, get_audit_recorder  # noqa: E402

TEST_DATABASE_URL = os.environ["DATABASE_URL"]
IS_POSTGRES = TEST_DATABASE_URL.startswith("postgresql")
TEST_DATABASE_SUFFIX = "_test"


def _guard_against_non_test_database() -> None:
    """Refuse de lancer la suite sur une base qui n'est pas dédiée aux tests.

    Les tests de migration suppriment tout le schéma de la base visée (`drop_all`,
    `alembic downgrade base`). Pointés par erreur sur la base de travail, ils
    effaceraient les flux et les IOC collectés. Le nom doit donc finir par `_test`.
    """
    from sqlalchemy.engine import make_url

    # Alembic suit MIGRATION_DATABASE_URL quand elle est définie : elle doit, elle aussi,
    # viser une base de test, sinon les tests de migration montent et descendent le schéma
    # de la base de travail.
    urls = {"DATABASE_URL": TEST_DATABASE_URL if IS_POSTGRES else ""}
    urls["MIGRATION_DATABASE_URL"] = os.environ.get("MIGRATION_DATABASE_URL", "")
    for variable, url in urls.items():
        if not url.startswith("postgresql"):
            continue
        database = make_url(url).database or ""
        if not database.endswith(TEST_DATABASE_SUFFIX):
            pytest.exit(
                f"{variable} : base « {database} » refusée. La suite de tests détruit le "
                f"schéma de la base visée ; utilisez une base dédiée dont le nom finit par "
                f"« {TEST_DATABASE_SUFFIX} » (ex. …/sentry{TEST_DATABASE_SUFFIX}).",
                returncode=4,
            )


def pytest_configure(config: pytest.Config) -> None:
    _guard_against_non_test_database()
    config.addinivalue_line("markers", "postgres: nécessite une base PostgreSQL réelle")
    config.addinivalue_line(
        "markers", "live: interroge de vraies sources sur Internet (SENTRY_LIVE_TESTS=1)"
    )


LIVE = os.environ.get("SENTRY_LIVE_TESTS") == "1"


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    if not LIVE:
        skip_live = pytest.mark.skip(reason="tests réseau : SENTRY_LIVE_TESTS=1 pour les lancer")
        for item in items:
            if "live" in item.keywords:
                item.add_marker(skip_live)
    if IS_POSTGRES:
        return
    skip = pytest.mark.skip(reason="DATABASE_URL ne pointe pas vers PostgreSQL")
    for item in items:
        if "postgres" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(scope="session", autouse=True)
def _clear_settings_cache() -> None:
    get_settings.cache_clear()


@pytest.fixture(scope="session", autouse=True)
def _fresh_postgres_schema() -> None:
    """Repart d'un schéma neuf au début de chaque session PostgreSQL.

    `create_all` n'ajoute jamais de colonne à une table existante : une base de tests
    restée sur un ancien schéma ferait échouer la suite pour une raison sans rapport
    avec le code testé. Le garde-fou `_test` garantit qu'on ne vide qu'une base jetable.
    """
    if not IS_POSTGRES:
        return

    async def _reset() -> None:
        engine = make_test_engine()
        async with engine.begin() as conn:
            await drop_public_schema(conn)
            await conn.run_sync(Base.metadata.create_all)
        await engine.dispose()

    asyncio.run(_reset())


async def drop_public_schema(conn: AsyncConnection) -> None:
    """Vide entièrement le schéma `public` (tables, fonctions, déclencheurs).

    `Base.metadata.drop_all` ne supprime que les tables connues de la branche courante :
    après des tests lancés sur une branche plus récente (nouvelles tables liées à `users`),
    il échouait sur les dépendances et **toute** la suite tombait en erreur. Réservé à une
    base dont le nom finit par `_test` (garde-fou ci-dessus).
    """
    await conn.execute(text("DROP SCHEMA public CASCADE"))
    await conn.execute(text("CREATE SCHEMA public"))
    # USAGE seulement, comme le schéma public par défaut depuis PostgreSQL 15 : un GRANT ALL
    # donnerait CREATE à tous les rôles (le test du rôle applicatif, en M7, le détecte).
    await conn.execute(text("GRANT USAGE ON SCHEMA public TO PUBLIC"))


def make_test_engine() -> AsyncEngine:
    if IS_POSTGRES:
        return create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    # Connexion unique partagée : sinon chaque connexion SQLite mémoire verrait une base vide.
    return create_async_engine(
        TEST_DATABASE_URL,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )


@pytest.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Session transactionnelle : tout ce que le test écrit est annulé à la fin."""
    engine = make_test_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with engine.connect() as conn:
        outer = await conn.begin()
        session = AsyncSession(
            bind=conn, expire_on_commit=False, join_transaction_mode="create_savepoint"
        )
        try:
            yield session
        finally:
            await session.close()
            await outer.rollback()

    await engine.dispose()


@pytest.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Client HTTP asynchrone branché sur l'application avec base de test."""
    app = create_app()

    async def _override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    # Limiteur de connexion propre à chaque test : aucun compteur partagé entre tests.
    throttle = LoginThrottle(LocalCounter(), max_failures=5, window=900)
    app.dependency_overrides[get_login_throttle] = lambda: throttle

    # Journal d'audit écrit dans la transaction du test (annulée à la fin) au lieu d'une
    # session indépendante qui polluerait la base entre deux tests.
    async def _write_audit(event: AuditEvent) -> None:
        db_session.add(event)
        await db_session.flush()

    recorder = AuditRecorder(_write_audit)
    app.dependency_overrides[get_audit_recorder] = lambda: recorder

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as http_client:
        yield http_client

    app.dependency_overrides.clear()
