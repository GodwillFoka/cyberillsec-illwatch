"""Campagnes et leur infrastructure — M10, incrément 2 (ADR-024).

Une campagne regroupe l'infrastructure (IOC : adresses, domaines, URL, empreintes) d'une même
opération adverse et, si l'on sait, l'acteur ATT&CK qui la mène. Une détection qui touche un
IOC d'une campagne hérite de ce contexte : attribution par l'infrastructure, plus solide que
la seule mention d'un nom dans une description.
"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from illwatch.app.database import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Campaign(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "campaigns"

    name: Mapped[str] = mapped_column(String(160), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Identifiant ATT&CK (G…, S…) sans clé étrangère : le référentiel est remplacé à chaque
    # import, la campagne garde sa référence.
    actor_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    created_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class CampaignIndicator(Base):
    """IOC rattaché à une campagne (son infrastructure)."""

    __tablename__ = "campaign_indicators"
    __table_args__ = (Index("ix_campaign_indicators_indicator", "indicator_id"),)

    campaign_id: Mapped[UUID] = mapped_column(
        ForeignKey("campaigns.id", ondelete="CASCADE"), primary_key=True
    )
    indicator_id: Mapped[UUID] = mapped_column(
        ForeignKey("indicators.id", ondelete="CASCADE"), primary_key=True
    )
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
