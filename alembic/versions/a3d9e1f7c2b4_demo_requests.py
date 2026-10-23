"""demo requests

ADR-027, lot S4 : demandes de démonstration reçues du site de présentation.

Revision ID: a3d9e1f7c2b4
Revises: e2c7a5b9d184
Create Date: 2026-10-23 20:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "a3d9e1f7c2b4"
down_revision: str | None = "e2c7a5b9d184"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "demo_requests",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("email", sa.String(254), nullable=False),
        sa.Column("organisation", sa.String(160), nullable=False),
        sa.Column("job_title", sa.String(120), nullable=True),
        sa.Column("country", sa.String(2), nullable=True),
        sa.Column("interest", sa.String(10), nullable=False),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("language", sa.String(5), nullable=False),
        sa.Column("consent_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(10), nullable=False),
        sa.Column(
            "handled_by",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("handled_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "interest IN ('DEMO', 'PILOT', 'SUPPORT', 'OTHER')", name="ck_demo_requests_interest"
        ),
        sa.CheckConstraint(
            "status IN ('NEW', 'CONTACTED', 'CLOSED')", name="ck_demo_requests_status"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_demo_requests_created", "demo_requests", ["created_at"])


def downgrade() -> None:
    op.drop_index("idx_demo_requests_created", table_name="demo_requests")
    op.drop_table("demo_requests")
