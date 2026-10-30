"""feed reliability

M8 Detection & Correlation (ADR-017) : fiabilité de chaque source (échelle de l'Amirauté, de A à F),
qui pondère le score de confiance de ses IOC. Valeur par défaut « C » (assez fiable) pour les
sources existantes ; les sources de référence déjà présentes reçoivent ici, une seule fois, la
cote du seed (abuse.ch et IPsum : B, OTX : D). Ensuite, seul l'administrateur la change :
`illwatch seed` ne réécrit jamais une cote.

Revision ID: d2f7a9c4e318
Revises: c5d0a7e94b13
Create Date: 2026-10-11 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "d2f7a9c4e318"
down_revision: str | None = "c5d0a7e94b13"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Noms exacts des sources de référence (illwatch/modules/foundation/seed.py, 11/10/2026).
REFERENCE_RATINGS = {
    "abuse.ch URLhaus \u2014 URL malveillantes récentes": "B",
    "abuse.ch Feodo Tracker \u2014 serveurs C2 botnet": "B",
    "IPsum \u2014 IP malveillantes (≥ 5 listes noires)": "B",
    "AlienVault OTX \u2014 pulses abonnés": "D",
}


def upgrade() -> None:
    with op.batch_alter_table("threat_feeds") as batch:
        batch.add_column(sa.Column("reliability", sa.String(1), nullable=False, server_default="C"))
        batch.create_check_constraint(
            "ck_threat_feeds_reliability", "reliability IN ('A', 'B', 'C', 'D', 'E', 'F')"
        )
    feeds = sa.table(
        "threat_feeds", sa.column("name", sa.String), sa.column("reliability", sa.String)
    )
    for name, cote in REFERENCE_RATINGS.items():
        op.execute(feeds.update().where(feeds.c.name == name).values(reliability=cote))


def downgrade() -> None:
    with op.batch_alter_table("threat_feeds") as batch:
        batch.drop_constraint("ck_threat_feeds_reliability", type_="check")
        batch.drop_column("reliability")
