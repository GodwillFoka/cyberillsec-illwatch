"""refresh tokens

M7 lot 2 (ADR-012) : jetons de rafraîchissement opaques, rotatifs et révocables. Seule
l'empreinte SHA-256 est stockée ; `family_id` regroupe les jetons issus d'une même connexion
pour révoquer toute la lignée en cas de rejeu.

Revision ID: f41c7a9d2e86
Revises: e7b2c9d41f05
Create Date: 2026-10-04 05:52:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f41c7a9d2e86"
down_revision: str | None = "e7b2c9d41f05"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "refresh_tokens",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("family_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "issued_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_reason", sa.String(length=32), nullable=True),
        sa.Column("replaced_by", sa.Uuid(), nullable=True),
        sa.Column("ip", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.String(length=255), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="refresh_tokens_user_id_fkey", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="refresh_tokens_pkey"),
        sa.UniqueConstraint("token_hash", name="refresh_tokens_token_hash_key"),
    )
    op.create_index("idx_refresh_tokens_expires", "refresh_tokens", ["expires_at"])
    op.create_index("idx_refresh_tokens_family", "refresh_tokens", ["family_id"])
    op.create_index("idx_refresh_tokens_user", "refresh_tokens", ["user_id", "revoked_at"])


def downgrade() -> None:
    op.drop_index("idx_refresh_tokens_user", table_name="refresh_tokens")
    op.drop_index("idx_refresh_tokens_family", table_name="refresh_tokens")
    op.drop_index("idx_refresh_tokens_expires", table_name="refresh_tokens")
    op.drop_table("refresh_tokens")
