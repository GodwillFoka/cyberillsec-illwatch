"""collection runs

ADR-016 (interface web) : journal des collectes, une ligne par collecte d'un flux, pour l'écran
de santé des sources (durée, nouveaux IOC, IOC déjà connus, rejets, erreurs).

Revision ID: b8e3f61a2c47
Revises: f41c7a9d2e86
Create Date: 2026-10-08 21:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b8e3f61a2c47"
down_revision: str | None = "f41c7a9d2e86"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_STATUSES = "'PENDING', 'HEALTHY', 'DEGRADED'"


def upgrade() -> None:
    op.create_table(
        "collection_runs",
        sa.Column("feed_id", sa.Uuid(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("succeeded", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("inserted", sa.Integer(), nullable=False),
        sa.Column("updated", sa.Integer(), nullable=False),
        sa.Column("rejected", sa.Integer(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("warning", sa.Text(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.CheckConstraint(f"status IN ({_STATUSES})", name="ck_collection_runs_status"),
        sa.ForeignKeyConstraint(
            ["feed_id"],
            ["threat_feeds.id"],
            name="collection_runs_feed_id_fkey",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="collection_runs_pkey"),
    )
    op.create_index(
        "idx_collection_runs_feed_started", "collection_runs", ["feed_id", "started_at"]
    )


def downgrade() -> None:
    op.drop_index("idx_collection_runs_feed_started", table_name="collection_runs")
    op.drop_table("collection_runs")
