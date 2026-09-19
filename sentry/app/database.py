"""Moteur et sessions asynchrones SQLAlchemy 2.0 — couche DATA ACCESS.

Aucune logique métier ici : uniquement la fabrique de moteur, la session
asynchrone et la dépendance FastAPI qui l'injecte.
"""

from collections.abc import AsyncGenerator
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import DateTime, func
from sqlalchemy.ext.asyncio import (
    AsyncAttrs,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from sentry.app.config import get_settings


class Base(AsyncAttrs, DeclarativeBase):
    """Classe de base déclarative de tous les modèles SENTRY."""

    type_annotation_map: dict[Any, Any] = {}


class TimestampMixin:
    """Colonnes d'horodatage communes."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class UUIDPrimaryKeyMixin:
    """Clé primaire UUID générée côté application (portable PostgreSQL/SQLite)."""

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)


_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    """Retourne (et crée à la demande) le moteur asynchrone global."""
    global _engine
    if _engine is None:
        settings = get_settings()
        kwargs: dict[str, Any] = {"echo": settings.database_echo, "future": True}
        # SQLite ne supporte pas le pooling configurable de la même manière.
        if not settings.database_url.startswith("sqlite"):
            kwargs["pool_size"] = settings.database_pool_size
            kwargs["pool_pre_ping"] = True
        _engine = create_async_engine(settings.database_url, **kwargs)
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Retourne la fabrique de sessions asynchrones."""
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(), class_=AsyncSession, expire_on_commit=False
        )
    return _session_factory


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dépendance FastAPI : fournit une session et la referme systématiquement."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def dispose_engine() -> None:
    """Libère le pool de connexions (arrêt applicatif, fin de tests)."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None
