"""cve affected versions

Corrélation par version (ADR-021) : produits et plages de versions vulnérables publiés par
la NVD (configurations CPE). Colonne vide à la création ; remplie par la synchronisation NVD
et par `illwatch cves refresh-affected`.

Revision ID: e5b8c1d4a907
Revises: c4d9e2a7f613
Create Date: 2026-10-13 22:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "e5b8c1d4a907"
down_revision: str | None = "c4d9e2a7f613"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("cves") as batch:
        batch.add_column(sa.Column("affected", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("cves") as batch:
        batch.drop_column("affected")
