"""Modèles Incident et IncidentEvent — tables `incidents` / `incident_events` (MOD-04)."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentry.app.database import Base, TimestampMixin, UUIDPrimaryKeyMixin
from sentry.shared.enums import IncidentStatus


class Incident(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Incident de sécurité suivant la machine d'état à 6 étapes — RF-17 / RF-18."""

    __tablename__ = "incidents"

    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default=IncidentStatus.NOUVEAU)
    assigned_to: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    closure_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    events: Mapped[list["IncidentEvent"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", order_by="IncidentEvent.created_at"
    )

    def __repr__(self) -> str:
        return f"<Incident {self.title} [{self.status}]>"


class IncidentEvent(UUIDPrimaryKeyMixin, Base):
    """Événement immuable de la chronologie d'un incident — RF-19."""

    __tablename__ = "incident_events"
    __table_args__ = (Index("idx_incident_events_timeline", "incident_id", "created_at"),)

    incident_id: Mapped[UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    author_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    incident: Mapped[Incident] = relationship(back_populates="events")

    def __repr__(self) -> str:
        return f"<IncidentEvent {self.event_type}>"
