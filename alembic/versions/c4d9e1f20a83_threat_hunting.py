"""threat hunting

Threat hunting — phase 6 (ADR-009) : sessions de chasse et correspondances (RF-27, RF-28).

Revision ID: c4d9e1f20a83
Revises: 8a1c2e4f6b70
Create Date: 2026-10-03 02:53:07.705848
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "c4d9e1f20a83"
down_revision: str | None = "8a1c2e4f6b70"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "hunting_sessions",
        sa.Column("trigger", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("author_id", sa.Uuid(), nullable=True),
        sa.Column("rules", sa.Text(), nullable=False),
        sa.Column("observables_count", sa.Integer(), nullable=False),
        sa.Column("rejected_count", sa.Integer(), nullable=False),
        sa.Column("assets", sa.Text(), nullable=True),
        sa.Column("matches_count", sa.Integer(), nullable=False),
        sa.Column("errors", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.CheckConstraint(
            "status IN ('EN_COURS', 'TERMINEE', 'PARTIELLE', 'ECHEC')",
            name="ck_hunting_sessions_status",
        ),
        sa.CheckConstraint(
            "trigger IN ('MANUAL', 'SCHEDULED')", name="ck_hunting_sessions_trigger"
        ),
        sa.ForeignKeyConstraint(["author_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "idx_hunting_sessions_started", "hunting_sessions", ["started_at"], unique=False
    )
    op.create_table(
        "hunting_matches",
        sa.Column("session_id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.String(length=20), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("observable", sa.Text(), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("indicator_id", sa.Uuid(), nullable=True),
        sa.Column("cve_id", sa.String(length=30), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.CheckConstraint(
            "severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')", name="ck_hunting_matches_severity"
        ),
        sa.ForeignKeyConstraint(["cve_id"], ["cves.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["indicator_id"], ["indicators.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["session_id"], ["hunting_sessions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "idx_hunting_matches_session", "hunting_matches", ["session_id", "rule_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index("idx_hunting_matches_session", table_name="hunting_matches")
    op.drop_table("hunting_matches")
    op.drop_index("idx_hunting_sessions_started", table_name="hunting_sessions")
    op.drop_table("hunting_sessions")
