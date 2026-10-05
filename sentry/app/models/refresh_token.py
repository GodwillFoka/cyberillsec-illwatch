"""Jetons de rafraîchissement — M7 Production Hardening, lot 2 (ADR-012).

Le jeton d'accès (JWT, 15 min) n'est pas révocable ; le jeton de rafraîchissement l'est.
Il est **opaque** (256 bits aléatoires), seule son empreinte SHA-256 est stockée : une fuite
de la base ne donne aucun jeton utilisable. Chaque usage le remplace (rotation) ; tous les
jetons issus d'une même connexion partagent une `family_id`, ce qui permet de révoquer la
lignée entière si un jeton déjà remplacé est présenté à nouveau (vol probable).
"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column

from sentry.app.database import Base, UUIDPrimaryKeyMixin


class RefreshToken(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "refresh_tokens"
    __table_args__ = (
        Index("idx_refresh_tokens_user", "user_id", "revoked_at"),
        Index("idx_refresh_tokens_family", "family_id"),
        Index("idx_refresh_tokens_expires", "expires_at"),
    )

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    family_id: Mapped[UUID] = mapped_column(nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    replaced_by: Mapped[UUID | None] = mapped_column(nullable=True)
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)

    def __repr__(self) -> str:
        return f"<RefreshToken user={self.user_id} revoked={self.revoked_at is not None}>"
