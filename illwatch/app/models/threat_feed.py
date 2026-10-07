"""Modèles ThreatFeed, Indicator et IndicatorSource — flux, IOC et provenance.

Les contraintes CHECK reprennent à l'identique celles des migrations `a4973a3782e3`
et `1f3dafc3008c` (format OTX). Le modèle reste la source de vérité du schéma ; comme
`alembic check` ne compare pas le texte des CHECK, `test_schema_constraints` le fait.
Les bases créées par `Base.metadata.create_all` (tests SQLite) appliquent les mêmes règles.

`indicator_sources` (ADR-006) porte la provenance multi-sources des IOC.
"""

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from illwatch.app.database import Base, TimestampMixin, UUIDPrimaryKeyMixin
from illwatch.shared.enums import FeedStatus, FeedType, IndicatorType, Severity


def _in_enum(column: str, enum: type[StrEnum]) -> str:
    """Expression SQL `colonne IN (...)` générée depuis l'énumération Python :
    une seule source pour les valeurs autorisées."""
    values = ", ".join(f"'{member.value}'" for member in enum)
    return f"{column} IN ({values})"


class ThreatFeed(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Source de renseignement distante — RF-04."""

    __tablename__ = "threat_feeds"
    __table_args__ = (
        CheckConstraint(_in_enum("feed_type", FeedType), name="ck_threat_feeds_feed_type"),
        CheckConstraint(_in_enum("status", FeedStatus), name="ck_threat_feeds_status"),
    )

    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    url: Mapped[str] = mapped_column(String(500), nullable=False)
    feed_type: Mapped[str] = mapped_column(String(20), nullable=False)
    polling_interval: Mapped[int] = mapped_column(Integer, nullable=False, default=3600)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_successful_run: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default=FeedStatus.PENDING)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    indicators: Mapped[list["Indicator"]] = relationship(back_populates="feed")

    def __repr__(self) -> str:
        return f"<ThreatFeed {self.name} [{self.status}]>"


class Indicator(UUIDPrimaryKeyMixin, Base):
    """Indicateur de compromission dédupliqué — RF-07 / RF-08."""

    __tablename__ = "indicators"
    __table_args__ = (
        UniqueConstraint("type", "value", name="uq_indicator_type_value"),
        Index("idx_indicators_type_val", "type", "value"),
        Index("idx_indicators_last_seen", "last_seen"),
        CheckConstraint(_in_enum("type", IndicatorType), name="ck_indicators_type"),
        CheckConstraint(_in_enum("severity", Severity), name="ck_indicators_severity"),
    )

    feed_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("threat_feeds.id", ondelete="SET NULL"), nullable=True
    )
    type: Mapped[str] = mapped_column(String(20), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default=Severity.MEDIUM)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    hit_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Fin de validité opérationnelle : au-delà, l'IOC est « expiré » (plus utilisé pour la
    # détection) mais conservé pour l'historique et les investigations. NULL = sans expiration.
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    feed: Mapped[ThreatFeed | None] = relationship(back_populates="indicators")
    sources: Mapped[list["IndicatorSource"]] = relationship(
        back_populates="indicator",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="IndicatorSource.first_seen",
    )

    def __repr__(self) -> str:
        return f"<Indicator {self.type}:{self.value}>"


class IndicatorSource(Base):
    """Provenance multi-sources d'un IOC — ADR-006.

    Une ligne par couple (IOC, flux) : quand et combien de fois *ce* flux a rapporté
    *cet* IOC. `indicators.feed_id` reste la première source connue ; cette table dit
    toutes les autres. Un IOC confirmé par trois sources indépendantes n'a pas le même
    poids qu'un IOC isolé : c'est la donnée de base d'un futur score de confiance.
    """

    __tablename__ = "indicator_sources"
    __table_args__ = (Index("idx_indicator_sources_feed", "feed_id"),)

    indicator_id: Mapped[UUID] = mapped_column(
        ForeignKey("indicators.id", ondelete="CASCADE"), primary_key=True
    )
    feed_id: Mapped[UUID] = mapped_column(
        ForeignKey("threat_feeds.id", ondelete="CASCADE"), primary_key=True
    )
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    hit_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    indicator: Mapped[Indicator] = relationship(back_populates="sources")
    feed: Mapped[ThreatFeed] = relationship()

    def __repr__(self) -> str:
        return f"<IndicatorSource {self.indicator_id} ← {self.feed_id}>"
