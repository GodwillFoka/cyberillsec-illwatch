"""Modèles ThreatFeed et Indicator — tables `threat_feeds` et `indicators`."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentry.app.database import Base, TimestampMixin, UUIDPrimaryKeyMixin
from sentry.shared.enums import FeedStatus, Severity


class ThreatFeed(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Source de renseignement distante — RF-04."""

    __tablename__ = "threat_feeds"

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

    feed: Mapped[ThreatFeed | None] = relationship(back_populates="indicators")

    def __repr__(self) -> str:
        return f"<Indicator {self.type}:{self.value}>"
