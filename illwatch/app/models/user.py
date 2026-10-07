"""Modèle User — table `users` (§4.4 du Cahier des Charges)."""

from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column

from illwatch.app.database import Base, TimestampMixin, UUIDPrimaryKeyMixin
from illwatch.shared.enums import UserRole


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "users"

    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default=UserRole.ANALYST)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    def __repr__(self) -> str:
        return f"<User {self.username} ({self.role})>"
