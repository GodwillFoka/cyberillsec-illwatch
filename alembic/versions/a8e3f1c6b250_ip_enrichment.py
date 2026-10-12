"""ip enrichment

M8 Detection & Correlation, incrément 2 (ADR-017) : enrichissement hors ligne des adresses IP.
`ip_ranges` reçoit les plages DB-IP Lite (pays, système autonome) importées par
`illwatch enrich update` ; `enrichment_datasets` garde l'état de chaque base importée.
Tables vides à la création : rien n'est téléchargé par la migration.

Revision ID: a8e3f1c6b250
Revises: d2f7a9c4e318
Create Date: 2026-10-12 19:30:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "a8e3f1c6b250"
down_revision: str | None = "d2f7a9c4e318"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

KEY = sa.String(32).with_variant(sa.String(32, collation="C"), "postgresql")
DATASETS = "dataset IN ('country', 'asn')"


def upgrade() -> None:
    op.create_table(
        "ip_ranges",
        sa.Column(
            "id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            primary_key=True,
            autoincrement=True,
        ),
        sa.Column("dataset", sa.String(10), nullable=False),
        sa.Column("start_key", KEY, nullable=False),
        sa.Column("end_key", KEY, nullable=False),
        sa.Column("country", sa.String(2), nullable=True),
        sa.Column("asn", sa.BigInteger(), nullable=True),
        sa.Column("as_org", sa.String(255), nullable=True),
        sa.CheckConstraint(DATASETS, name="ck_ip_ranges_dataset"),
        sa.CheckConstraint("start_key <= end_key", name="ck_ip_ranges_bounds"),
    )
    op.create_index("ix_ip_ranges_lookup", "ip_ranges", ["dataset", "start_key"])
    op.create_table(
        "enrichment_datasets",
        sa.Column("dataset", sa.String(10), primary_key=True),
        sa.Column("source", sa.String(255), nullable=False),
        sa.Column("ranges", sa.Integer(), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(DATASETS, name="ck_enrichment_datasets_dataset"),
    )


def downgrade() -> None:
    op.drop_table("enrichment_datasets")
    op.drop_index("ix_ip_ranges_lookup", table_name="ip_ranges")
    op.drop_table("ip_ranges")
