"""campaigns

M10, incrément 2 (ADR-024) : campagnes (infrastructure d'une opération adverse, acteur
ATT&CK) et rattachement des IOC.

Revision ID: e2c7a5b9d184
Revises: d4a8f2c6e019
Create Date: 2026-10-15 01:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "e2c7a5b9d184"
down_revision: str | None = "d4a8f2c6e019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "campaigns",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("actor_id", sa.String(16), nullable=True),
        sa.Column(
            "created_by",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "campaign_indicators",
        sa.Column(
            "campaign_id",
            sa.Uuid(),
            sa.ForeignKey("campaigns.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "indicator_id",
            sa.Uuid(),
            sa.ForeignKey("indicators.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("campaign_id", "indicator_id"),
    )
    op.create_index("ix_campaign_indicators_indicator", "campaign_indicators", ["indicator_id"])


def downgrade() -> None:
    op.drop_index("ix_campaign_indicators_indicator", table_name="campaign_indicators")
    op.drop_table("campaign_indicators")
    op.drop_table("campaigns")
