"""Modèles du moteur CVE — MOD-03 (phase 3, ADR-007).

- `cves` : vulnérabilité enrichie NVD + CISA KEV + FIRST EPSS, score composite (ADR-001)
  et priorité SOC dérivée, recalculés à chaque changement d'entrée.
- `cve_priority_history` : chaque changement de priorité, avec l'ancien et le nouveau score
  et la source qui l'a provoqué (preuve d'audit NIS 2 / DORA : « pourquoi ce patch en 24 h »).
- `cve_alerts` : franchissement du seuil `RISK_ALERT_THRESHOLD`, livraison webhook suivie.
- `collector_state` : curseurs des synchronisations (NVD incrémental, dernier import KEV…).
"""

from datetime import UTC, date, datetime
from uuid import UUID

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from sentry.app.database import Base, TimestampMixin, UUIDPrimaryKeyMixin
from sentry.app.models.threat_feed import _in_enum
from sentry.shared.enums import RiskPriority


def _utcnow() -> datetime:
    return datetime.now(UTC)


class CVE(TimestampMixin, Base):
    """Vulnérabilité enrichie NVD + KEV + EPSS avec score de risque composite."""

    __tablename__ = "cves"
    __table_args__ = (
        Index("idx_cves_risk_score", "composite_risk_score"),
        Index("idx_cves_priority", "priority"),
        Index("idx_cves_last_modified", "last_modified_date"),
        CheckConstraint(_in_enum("priority", RiskPriority), name="ck_cves_priority"),
    )

    id: Mapped[str] = mapped_column(String(30), primary_key=True)  # ex: CVE-2026-16812
    description: Mapped[str] = mapped_column(Text, nullable=False)
    cvss_score: Mapped[float | None] = mapped_column(Numeric(3, 1), nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(120), nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Numeric(5, 4), nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Numeric(5, 4), nullable=True)
    is_kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    kev_date_added: Mapped[date | None] = mapped_column(Date, nullable=True)
    kev_due_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    kev_required_action: Mapped[str | None] = mapped_column(Text, nullable=True)
    has_public_exploit: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    has_ransomware_campaign: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    composite_risk_score: Mapped[float] = mapped_column(Numeric(5, 2), nullable=False, default=0.0)
    priority: Mapped[str] = mapped_column(
        String(20), nullable=False, default=RiskPriority.P3_FAIBLE
    )
    published_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_modified_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    def __repr__(self) -> str:
        return f"<CVE {self.id} R={self.composite_risk_score}>"


class CVEPriorityChange(UUIDPrimaryKeyMixin, Base):
    """Historique immuable des changements de priorité d'une CVE."""

    __tablename__ = "cve_priority_history"
    __table_args__ = (Index("idx_cve_priority_history_cve", "cve_id", "changed_at"),)

    cve_id: Mapped[str] = mapped_column(ForeignKey("cves.id", ondelete="CASCADE"), nullable=False)
    old_priority: Mapped[str | None] = mapped_column(String(20), nullable=True)
    new_priority: Mapped[str] = mapped_column(String(20), nullable=False)
    old_score: Mapped[float | None] = mapped_column(Numeric(5, 2), nullable=True)
    new_score: Mapped[float] = mapped_column(Numeric(5, 2), nullable=False)
    reason: Mapped[str] = mapped_column(String(40), nullable=False)
    # Horodatage applicatif (microsecondes) : dans une même transaction, `now()` SQL est
    # constant et ne permettrait plus d'ordonner les changements successifs.
    changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now(), nullable=False
    )


class CVEAlert(UUIDPrimaryKeyMixin, Base):
    """Alerte : une CVE a franchi le seuil de risque (RF-16)."""

    __tablename__ = "cve_alerts"
    __table_args__ = (Index("idx_cve_alerts_created", "created_at"),)

    cve_id: Mapped[str] = mapped_column(ForeignKey("cves.id", ondelete="CASCADE"), nullable=False)
    score: Mapped[float] = mapped_column(Numeric(5, 2), nullable=False)
    previous_score: Mapped[float | None] = mapped_column(Numeric(5, 2), nullable=True)
    priority: Mapped[str] = mapped_column(String(20), nullable=False)
    reason: Mapped[str] = mapped_column(String(40), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now(), nullable=False
    )
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    delivery_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_delivery_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class CollectorState(Base):
    """Curseur et dernier succès d'une synchronisation (`nvd`, `kev`, `epss`, …)."""

    __tablename__ = "collector_state"

    name: Mapped[str] = mapped_column(String(40), primary_key=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cursor: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    items: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
