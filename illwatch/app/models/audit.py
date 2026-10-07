"""Journal d'audit de sécurité — M7 Production Hardening (ADR-011).

Une ligne par action sensible : connexion (réussie, échouée, bloquée), administration des
sources, soumission d'IOC, acquittement d'alerte, chasse, export de données, création de compte.

La table est **append-only**, comme la chronologie des incidents : l'ORM refuse toute
modification ou suppression, et la migration `e7b2c9d41f05` pose sur PostgreSQL des
déclencheurs qui refusent `UPDATE`, `DELETE` **et `TRUNCATE`**. L'acteur est conservé par
identifiant et par nom : la ligne reste lisible si le compte est supprimé.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import JSON, CheckConstraint, DateTime, ForeignKey, Index, String, event
from sqlalchemy.orm import Mapped, mapped_column

from illwatch.app.database import Base, UUIDPrimaryKeyMixin
from illwatch.app.models.threat_feed import _in_enum
from illwatch.shared.enums import AuditOutcome


def _utcnow() -> datetime:
    return datetime.now(UTC)


class AuditEvent(UUIDPrimaryKeyMixin, Base):
    """Action sensible horodatée, attribuée et non modifiable."""

    __tablename__ = "audit_events"
    __table_args__ = (
        CheckConstraint(_in_enum("outcome", AuditOutcome), name="ck_audit_events_outcome"),
        Index("idx_audit_events_occurred_at", "occurred_at"),
        Index("idx_audit_events_action", "action", "occurred_at"),
        Index("idx_audit_events_actor", "actor_id", "occurred_at"),
    )

    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    actor_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    actor_name: Mapped[str | None] = mapped_column(String(150), nullable=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    def __repr__(self) -> str:
        return f"<AuditEvent {self.action} {self.outcome}>"


class ImmutableAuditError(RuntimeError):
    """Tentative de modification ou de suppression d'une ligne du journal d'audit."""


@event.listens_for(AuditEvent, "before_update")
@event.listens_for(AuditEvent, "before_delete")
def _refuse_rewrite(*_: Any) -> None:
    raise ImmutableAuditError("Le journal d'audit est en ajout seul : aucune réécriture.")
