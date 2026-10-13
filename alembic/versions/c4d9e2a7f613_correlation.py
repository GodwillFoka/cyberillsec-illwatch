"""correlation

M8 Detection & Correlation, incrément 3 (ADR-020) : inventaire d'actifs (`assets`) et
évènements corrélés (`correlated_events`). Tables vides à la création.

Revision ID: c4d9e2a7f613
Revises: a8e3f1c6b250
Create Date: 2026-10-13 18:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "c4d9e2a7f613"
down_revision: str | None = "a8e3f1c6b250"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "assets",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(120), nullable=False, unique=True),
        sa.Column("product", sa.String(120), nullable=False),
        sa.Column("vendor", sa.String(120), nullable=True),
        sa.Column("version", sa.String(60), nullable=True),
        sa.Column("criticality", sa.String(10), nullable=False),
        sa.Column("addresses", sa.JSON(), nullable=False),
        sa.Column("domains", sa.JSON(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "criticality IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')", name="ck_assets_criticality"
        ),
    )
    op.create_table(
        "correlated_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("rule_id", sa.String(10), nullable=False),
        sa.Column("dedup_key", sa.String(200), nullable=False, unique=True),
        sa.Column("priority", sa.String(20), nullable=False),
        sa.Column("score", sa.Numeric(5, 2), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column(
            "asset_id", sa.Uuid(), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column(
            "cve_id", sa.String(30), sa.ForeignKey("cves.id", ondelete="SET NULL"), nullable=True
        ),
        sa.Column(
            "indicator_id",
            sa.Uuid(),
            sa.ForeignKey("indicators.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "acknowledged_by",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "incident_id",
            sa.Uuid(),
            sa.ForeignKey("incidents.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.CheckConstraint(
            "rule_id IN ('CORR-01', 'CORR-02', 'CORR-03')", name="ck_correlated_events_rule"
        ),
        sa.CheckConstraint(
            "priority IN ('P0_CRITIQUE', 'P1_ELEVE', 'P2_MOYEN', 'P3_FAIBLE')",
            name="ck_correlated_events_priority",
        ),
    )
    op.create_index(
        "ix_correlated_events_open", "correlated_events", ["acknowledged_at", "priority"]
    )


def downgrade() -> None:
    op.drop_index("ix_correlated_events_open", table_name="correlated_events")
    op.drop_table("correlated_events")
    op.drop_table("assets")
