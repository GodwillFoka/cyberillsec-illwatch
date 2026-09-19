"""Modèle CVE — table `cves` (MOD-03)."""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Numeric, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from sentry.app.database import Base, TimestampMixin


class CVE(TimestampMixin, Base):
    """Vulnérabilité enrichie NVD + KEV + EPSS avec score de risque composite."""

    __tablename__ = "cves"
    __table_args__ = (Index("idx_cves_risk_score", "composite_risk_score"),)

    id: Mapped[str] = mapped_column(String(30), primary_key=True)  # ex: CVE-2026-16812
    description: Mapped[str] = mapped_column(Text, nullable=False)
    cvss_score: Mapped[float | None] = mapped_column(Numeric(3, 1), nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(120), nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Numeric(5, 4), nullable=True)
    is_kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    has_public_exploit: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    has_ransomware_campaign: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    composite_risk_score: Mapped[float] = mapped_column(Numeric(5, 2), nullable=False, default=0.0)
    published_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_modified_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    def __repr__(self) -> str:
        return f"<CVE {self.id} R={self.composite_risk_score}>"
