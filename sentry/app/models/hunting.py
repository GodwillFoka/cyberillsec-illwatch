"""Modèles du threat hunting — MOD-06, RF-27 et RF-28 (phase 6, ADR-009).

- `hunting_sessions` : une exécution du moteur (manuelle ou planifiée), son périmètre
  (observables soumis, inventaire d'actifs, règles), son statut et son bilan.
- `hunting_matches` : chaque correspondance, rattachée à la règle qui l'a produite et, quand
  c'est le cas, à l'IOC ou à la CVE en cause.
"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentry.app.database import Base, UUIDPrimaryKeyMixin
from sentry.app.models.threat_feed import _in_enum
from sentry.shared.enums import HuntStatus, HuntTrigger, Severity


class HuntingSession(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "hunting_sessions"
    __table_args__ = (
        Index("idx_hunting_sessions_started", "started_at"),
        CheckConstraint(_in_enum("status", HuntStatus), name="ck_hunting_sessions_status"),
        CheckConstraint(_in_enum("trigger", HuntTrigger), name="ck_hunting_sessions_trigger"),
    )

    trigger: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    author_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    rules: Mapped[str] = mapped_column(Text, nullable=False)  # identifiants séparés par « , »
    observables_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rejected_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    assets: Mapped[str | None] = mapped_column(Text, nullable=True)
    matches_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    errors: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    matches: Mapped[list["HuntingMatch"]] = relationship(
        cascade="all, delete-orphan", order_by="HuntingMatch.rule_id"
    )


class HuntingMatch(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "hunting_matches"
    __table_args__ = (
        Index("idx_hunting_matches_session", "session_id", "rule_id"),
        CheckConstraint(_in_enum("severity", Severity), name="ck_hunting_matches_severity"),
    )

    session_id: Mapped[UUID] = mapped_column(
        ForeignKey("hunting_sessions.id", ondelete="CASCADE"), nullable=False
    )
    rule_id: Mapped[str] = mapped_column(String(20), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    observable: Mapped[str] = mapped_column(Text, nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    indicator_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("indicators.id", ondelete="SET NULL"), nullable=True
    )
    cve_id: Mapped[str | None] = mapped_column(
        ForeignKey("cves.id", ondelete="SET NULL"), nullable=True
    )
