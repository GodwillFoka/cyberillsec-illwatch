"""attack

M10 CTI Intelligence Layer (ADR-023) : référentiel MITRE ATT&CK Enterprise (techniques,
groupes et logiciels, relations « utilise »), importé par `illwatch attack import`.

Revision ID: d4a8f2c6e019
Revises: c9f1a3e5b742
Create Date: 2026-10-14 08:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "d4a8f2c6e019"
down_revision: str | None = "c9f1a3e5b742"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "attack_techniques",
        sa.Column("id", sa.String(16), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("tactics", sa.JSON(), nullable=False),
        sa.Column("is_subtechnique", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "attack_actors",
        sa.Column("id", sa.String(16), nullable=False),
        sa.Column("kind", sa.String(10), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("aliases", sa.JSON(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "attack_uses",
        sa.Column(
            "actor_id",
            sa.String(16),
            sa.ForeignKey("attack_actors.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "technique_id",
            sa.String(16),
            sa.ForeignKey("attack_techniques.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("actor_id", "technique_id"),
    )
    op.create_index("ix_attack_uses_technique", "attack_uses", ["technique_id"])


def downgrade() -> None:
    op.drop_index("ix_attack_uses_technique", table_name="attack_uses")
    op.drop_table("attack_uses")
    op.drop_table("attack_actors")
    op.drop_table("attack_techniques")
