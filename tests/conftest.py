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

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes-long")

from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine  # noqa: E402
from sqlalchemy.pool import NullPool, StaticPool  # noqa: E402

from sentry.app.config import get_settings  # noqa: E402
from sentry.app.database import Base, get_db  # noqa: E402
from sentry.app.main import create_app  # noqa: E402

TEST_DATABASE_URL = os.environ["DATABASE_URL"]
IS_POSTGRES = TEST_DATABASE_URL.startswith("postgresql")
TEST_DATABASE_SUFFIX = "_test"


def _guard_against_non_test_database() -> None:
    """Refuse de lancer la suite sur une base qui n'est pas dédiée aux tests.

    Les tests de migration suppriment tout le schéma de la base visée (`drop_all`,
    `alembic downgrade base`). Pointés par erreur sur la base de travail, ils
    effaceraient les flux et les IOC collectés. Le nom doit donc finir par `_test`.
    """
    if not IS_POSTGRES:
        return
    from sqlalchemy.engine import make_url

    database = make_url(TEST_DATABASE_URL).database or ""
    if not database.endswith(TEST_DATABASE_SUFFIX):
        pytest.exit(
            f"Base « {database} » refusée : la suite de tests détruit le schéma de la base "
            f"visée. Utilisez une base dédiée dont le nom finit par « {TEST_DATABASE_SUFFIX} » "
            f"(ex. …/sentry{TEST_DATABASE_SUFFIX}).",
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
            await conn.run_sync(Base.metadata.drop_all)
            await conn.execute(text("DROP TABLE IF EXISTS alembic_version"))
            await conn.run_sync(Base.metadata.create_all)
        await engine.dispose()

    asyncio.run(_reset())


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

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as http_client:
        yield http_client

    app.dependency_overrides.clear()
