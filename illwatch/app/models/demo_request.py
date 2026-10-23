"""Demandes de démonstration reçues du site de présentation (ADR-027, lot S4).

Minimisation : seules les données nécessaires pour recontacter la personne sont gardées.
Ni adresse IP, ni en-têtes, ni pays déduit ne sont enregistrés ; le consentement est daté.
Conservation bornée (`illwatch demo-requests purge`, 12 mois par défaut).
"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from illwatch.app.database import Base, UUIDPrimaryKeyMixin
from illwatch.app.models.threat_feed import _in_enum
from illwatch.shared.enums import DemoInterest, DemoRequestStatus


class DemoRequest(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "demo_requests"
    __table_args__ = (
        CheckConstraint(_in_enum("interest", DemoInterest), name="ck_demo_requests_interest"),
        CheckConstraint(_in_enum("status", DemoRequestStatus), name="ck_demo_requests_status"),
        Index("idx_demo_requests_created", "created_at"),
    )

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    email: Mapped[str] = mapped_column(String(254), nullable=False)
    organisation: Mapped[str] = mapped_column(String(160), nullable=False)
    job_title: Mapped[str | None] = mapped_column(String(120), nullable=True)
    country: Mapped[str | None] = mapped_column(String(2), nullable=True)
    interest: Mapped[str] = mapped_column(String(10), nullable=False)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    language: Mapped[str] = mapped_column(String(5), nullable=False)
    consent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(
        String(10), nullable=False, default=DemoRequestStatus.NEW.value
    )
    handled_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    handled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
