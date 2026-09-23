"""Fixtures asynchrones partagées.

Base de test : `DATABASE_URL` si elle est définie (PostgreSQL 16 en CI et en
local via Docker Compose), sinon SQLite en mémoire pour un retour rapide sans
infrastructure. Les tests marqués `postgres` ne s'exécutent que sur PostgreSQL.

Isolation : chaque test travaille dans une transaction annulée à la fin ; la
base n'est jamais polluée d'un test à l'autre.
"""

import os
from collections.abc import AsyncGenerator

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes-long")

from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine  # noqa: E402
from sqlalchemy.pool import NullPool, StaticPool  # noqa: E402

from sentry.app.config import get_settings  # noqa: E402
from sentry.app.database import Base, get_db  # noqa: E402
from sentry.app.main import create_app  # noqa: E402

TEST_DATABASE_URL = os.environ["DATABASE_URL"]
IS_POSTGRES = TEST_DATABASE_URL.startswith("postgresql")


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "postgres: nécessite une base PostgreSQL réelle")


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    if IS_POSTGRES:
        return
    skip = pytest.mark.skip(reason="DATABASE_URL ne pointe pas vers PostgreSQL")
    for item in items:
        if "postgres" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(scope="session", autouse=True)
def _clear_settings_cache() -> None:
    get_settings.cache_clear()


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
