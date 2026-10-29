"""Enrichissement hors ligne des adresses IP : M8, ADR-017 (incrément 2).

`ip_ranges` contient les plages de la base DB-IP Lite (pays, système autonome), importées
depuis un fichier téléchargé une fois par mois : aucune requête sortante au moment de
consulter un IOC. Les bornes sont stockées en clés hexadécimales de 32 caractères (IPv4
convertie en adresse IPv6 « ::ffff:a.b.c.d ») : la comparaison de chaînes de même longueur
suit l'ordre numérique, à l'identique sous PostgreSQL (collation « C ») et SQLite.

`enrichment_datasets` garde, pour chaque base, la source importée, son mois de publication,
le nombre de plages et la date d'import : ce que l'administrateur voit dans les paramètres.
"""

from datetime import datetime

from sqlalchemy import BigInteger, CheckConstraint, DateTime, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from illwatch.app.database import Base
from illwatch.shared.enums import EnrichmentDataset

KEY_LENGTH = 32

# Collation binaire sous PostgreSQL : l'ordre des clés ne dépend jamais de la locale.
_KEY = String(KEY_LENGTH).with_variant(String(KEY_LENGTH, collation="C"), "postgresql")
_DATASETS = ", ".join(f"'{d.value}'" for d in EnrichmentDataset)


class IpRange(Base):
    """Plage d'adresses et ce que la base en dit (pays ou système autonome)."""

    __tablename__ = "ip_ranges"
    __table_args__ = (
        CheckConstraint(f"dataset IN ({_DATASETS})", name="ck_ip_ranges_dataset"),
        CheckConstraint("start_key <= end_key", name="ck_ip_ranges_bounds"),
        Index("ix_ip_ranges_lookup", "dataset", "start_key"),
    )

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True
    )
    dataset: Mapped[str] = mapped_column(String(10), nullable=False)
    start_key: Mapped[str] = mapped_column(_KEY, nullable=False)
    end_key: Mapped[str] = mapped_column(_KEY, nullable=False)
    country: Mapped[str | None] = mapped_column(String(2), nullable=True)
    asn: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    as_org: Mapped[str | None] = mapped_column(String(255), nullable=True)


class EnrichmentDatasetInfo(Base):
    """État d'une base d'enrichissement importée."""

    __tablename__ = "enrichment_datasets"
    __table_args__ = (
        CheckConstraint(f"dataset IN ({_DATASETS})", name="ck_enrichment_datasets_dataset"),
    )

    dataset: Mapped[str] = mapped_column(String(10), primary_key=True)
    source: Mapped[str] = mapped_column(String(255), nullable=False)
    ranges: Mapped[int] = mapped_column(Integer, nullable=False)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
