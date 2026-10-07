"""Modèles de la gestion d'incidents — MOD-04 (phase 4, ADR-008).

- `incidents` : incident de sécurité, sévérité (RF-17), statut piloté par la machine d'état
  NIST SP 800-61 (RF-18), éventuellement ouvert depuis une alerte CVE.
- `incident_events` : chronologie **immuable** (RF-19). Toute modification est refusée par
  l'ORM (`before_update` / `before_delete`) et, sur PostgreSQL, par un déclencheur posé par la
  migration `8a1c2e4f6b70` : même un accès SQL direct ne peut pas réécrire l'historique.
- `incident_indicators`, `incident_cves` : IOC et CVE associés (RF-20).
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Text, event
from sqlalchemy.orm import Mapped, mapped_column, relationship

from illwatch.app.database import Base, TimestampMixin, UUIDPrimaryKeyMixin
from illwatch.app.models.threat_feed import _in_enum
from illwatch.shared.enums import IncidentEventType, IncidentStatus, Severity


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Incident(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Incident de sécurité suivant la machine d'état à 6 étapes — RF-17 / RF-18."""

    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint(_in_enum("severity", Severity), name="ck_incidents_severity"),
        CheckConstraint(_in_enum("status", IncidentStatus), name="ck_incidents_status"),
        Index("idx_incidents_status_severity", "status", "severity"),
    )

    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default=IncidentStatus.NOUVEAU)
    assigned_to: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    source_alert_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("cve_alerts.id", ondelete="SET NULL"), nullable=True, unique=True
    )
    closure_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    events: Mapped[list["IncidentEvent"]] = relationship(
        back_populates="incident",
        order_by="(IncidentEvent.created_at, IncidentEvent.id)",
        passive_deletes="all",
    )
    indicators: Mapped[list["IncidentIndicator"]] = relationship(
        cascade="all, delete-orphan", order_by="IncidentIndicator.added_at"
    )
    cves: Mapped[list["IncidentCVE"]] = relationship(
        cascade="all, delete-orphan", order_by="IncidentCVE.added_at"
    )

    def __repr__(self) -> str:
        return f"<Incident {self.title} [{self.status}]>"


class IncidentEvent(UUIDPrimaryKeyMixin, Base):
    """Événement immuable de la chronologie d'un incident — RF-19."""

    __tablename__ = "incident_events"
    __table_args__ = (
        Index("idx_incident_events_timeline", "incident_id", "created_at"),
        CheckConstraint(
            _in_enum("event_type", IncidentEventType), name="ck_incident_events_event_type"
        ),
    )

    incident_id: Mapped[UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    author_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    from_status: Mapped[str | None] = mapped_column(String(30), nullable=True)
    to_status: Mapped[str | None] = mapped_column(String(30), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    incident: Mapped[Incident] = relationship(back_populates="events")

    def __repr__(self) -> str:
        return f"<IncidentEvent {self.event_type}>"


class ImmutableTimelineError(RuntimeError):
    """Tentative de modification ou de suppression d'un événement de chronologie."""


@event.listens_for(IncidentEvent, "before_update")
@event.listens_for(IncidentEvent, "before_delete")
def _refuse_rewrite(*_: Any) -> None:
    raise ImmutableTimelineError(
        "La chronologie d'un incident est immuable : ajoutez un événement, ne modifiez pas."
    )


class IncidentIndicator(Base):
    """IOC associé à un incident — RF-20."""

    __tablename__ = "incident_indicators"

    incident_id: Mapped[UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True
    )
    indicator_id: Mapped[UUID] = mapped_column(
        ForeignKey("indicators.id", ondelete="CASCADE"), primary_key=True
    )
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    added_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class IncidentCVE(Base):
    """CVE associée à un incident — RF-20."""

    __tablename__ = "incident_cves"

    incident_id: Mapped[UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True
    )
    cve_id: Mapped[str] = mapped_column(ForeignKey("cves.id", ondelete="CASCADE"), primary_key=True)
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    added_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
