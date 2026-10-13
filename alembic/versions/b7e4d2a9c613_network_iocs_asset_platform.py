"""network iocs and asset platform

- `ck_indicators_type` accepte `NETWORK` : plages CIDR (RedEye en publiait 1 640, rejetées
  jusqu'ici). Alembic ne compare pas le texte des contraintes CHECK : écrite à la main.
- `assets.platform` : système hôte de l'actif (« Debian 12 »), qui tranche les CVE que la NVD
  ne déclare vulnérables que sur certaines plateformes (ADR-021, verdict conditionnel).

Revision ID: b7e4d2a9c613
Revises: e5b8c1d4a907
Create Date: 2026-10-14 02:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "b7e4d2a9c613"
down_revision: str | None = "e5b8c1d4a907"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TYPES_BEFORE = (
    "type IN ('IPV4', 'IPV6', 'DOMAIN', 'URL', 'HASH_MD5', 'HASH_SHA1', 'HASH_SHA256', 'EMAIL')"
)
TYPES_AFTER = (
    "type IN ('IPV4', 'IPV6', 'DOMAIN', 'URL', 'HASH_MD5', 'HASH_SHA1', 'HASH_SHA256', "
    "'EMAIL', 'NETWORK')"
)


def upgrade() -> None:
    with op.batch_alter_table("indicators") as batch:
        batch.drop_constraint("ck_indicators_type", type_="check")
        batch.create_check_constraint("ck_indicators_type", TYPES_AFTER)
    with op.batch_alter_table("assets") as batch:
        batch.add_column(sa.Column("platform", sa.String(80), nullable=True))


def downgrade() -> None:
    networks = op.get_bind().scalar(
        sa.text("SELECT count(*) FROM indicators WHERE type = 'NETWORK'")
    )
    if networks:
        raise RuntimeError(
            f"{networks} plages CIDR existent : supprimez-les avant de revenir en arrière. "
            "Aucune donnée n'est supprimée implicitement."
        )
    with op.batch_alter_table("assets") as batch:
        batch.drop_column("platform")
    with op.batch_alter_table("indicators") as batch:
        batch.drop_constraint("ck_indicators_type", type_="check")
        batch.create_check_constraint("ck_indicators_type", TYPES_BEFORE)
