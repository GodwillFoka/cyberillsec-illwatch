"""Inventaire d'actifs et évènements corrélés — M8, ADR-020 (incrément 3).

`assets` : ce que l'organisation exploite (produit cherché dans les CVE, adresses et domaines
cherchés dans les IOC) et sa criticité. `correlated_events` : un évènement par règle et par
couple (actif, CVE ou IOC), dédupliqué par `dedup_key` ; une nouvelle passe de corrélation
met à jour `last_seen` et le score au lieu de créer un doublon.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Numeric,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from illwatch.app.database import Base, TimestampMixin, UUIDPrimaryKeyMixin
from illwatch.app.models.threat_feed import _in_enum
from illwatch.shared.enums import CorrelationRule, RiskPriority, Severity


class Asset(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Actif de l'organisation (inventaire déclaratif)."""

    __tablename__ = "assets"
    __table_args__ = (
        CheckConstraint(_in_enum("criticality", Severity), name="ck_assets_criticality"),
    )

    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    product: Mapped[str] = mapped_column(String(120), nullable=False)
    vendor: Mapped[str | None] = mapped_column(String(120), nullable=True)
    version: Mapped[str | None] = mapped_column(String(60), nullable=True)
    criticality: Mapped[str] = mapped_column(String(10), nullable=False, default=Severity.MEDIUM)
    addresses: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    domains: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class CorrelatedEvent(UUIDPrimaryKeyMixin, Base):
    """Évènement corrélé : une règle a relié un actif à une CVE ou à un IOC."""

    __tablename__ = "correlated_events"
    __table_args__ = (
        CheckConstraint(_in_enum("rule_id", CorrelationRule), name="ck_correlated_events_rule"),
        CheckConstraint(_in_enum("priority", RiskPriority), name="ck_correlated_events_priority"),
        Index("ix_correlated_events_open", "acknowledged_at", "priority"),
    )

    rule_id: Mapped[str] = mapped_column(String(10), nullable=False)
    dedup_key: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    priority: Mapped[str] = mapped_column(String(20), nullable=False)
    score: Mapped[float] = mapped_column(Numeric(5, 2), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    asset_id: Mapped[UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    cve_id: Mapped[str | None] = mapped_column(
        ForeignKey("cves.id", ondelete="SET NULL"), nullable=True
    )
    indicator_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("indicators.id", ondelete="SET NULL"), nullable=True
    )
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    incident_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True
    )
