"""Liste d'exclusion des IOC — M9 (ADR-022), tâche 3.6 du plan directeur.

Un IOC qualifié de faux positif par un analyste (« ce domaine est notre CDN ») est exclu :
il reste en base avec sa provenance (historique, enquêtes), mais n'est plus **actif** — ni
compté, ni chassé, ni corrélé. L'exclusion porte sur le couple (type, valeur normalisée) : une
nouvelle observation par une source ne la lève pas. Elle peut expirer (réexamen) et se
retire par un administrateur.
"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from illwatch.app.database import Base, UUIDPrimaryKeyMixin
from illwatch.app.models.threat_feed import _in_enum
from illwatch.shared.enums import IndicatorType


class Exclusion(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "exclusions"
    __table_args__ = (
        UniqueConstraint("indicator_type", "value", name="uq_exclusions_type_value"),
        CheckConstraint(_in_enum("indicator_type", IndicatorType), name="ck_exclusions_type"),
    )

    indicator_type: Mapped[str] = mapped_column(String(20), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    incident_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True
    )
