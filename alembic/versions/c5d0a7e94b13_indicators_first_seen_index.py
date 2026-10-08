"""indicators first_seen index

ADR-016 (interface web) : la série temporelle des nouveaux IOC agrège `indicators.first_seen`
sur 24 h à 30 jours. Sans index, chaque appel parcourait toute la table (plus de 500 000 lignes).

Revision ID: c5d0a7e94b13
Revises: b8e3f61a2c47
Create Date: 2026-10-08 22:00:00.000000
"""

from collections.abc import Sequence

from alembic import op

revision: str = "c5d0a7e94b13"
down_revision: str | None = "b8e3f61a2c47"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index("idx_indicators_first_seen", "indicators", ["first_seen"])


def downgrade() -> None:
    op.drop_index("idx_indicators_first_seen", table_name="indicators")
