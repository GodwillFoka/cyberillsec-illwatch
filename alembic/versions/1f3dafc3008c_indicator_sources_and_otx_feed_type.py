"""indicator sources and otx feed type

Provenance multi-sources des IOC (ADR-006) et format de flux OTX.

- Table `indicator_sources` : une ligne par couple (IOC, flux). Les IOC existants
  rattachés à un flux (`indicators.feed_id`) y sont recopiés : la provenance est
  complète dès la migration, sans attendre la prochaine collecte.
- `ck_threat_feeds_feed_type` accepte `OTX`. Alembic ne compare pas le texte des
  contraintes CHECK (`alembic check` ne l'aurait pas signalé) : écrite à la main.

Revision ID: 1f3dafc3008c
Revises: a4973a3782e3
Create Date: 2026-09-28 16:18:22.734924
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "1f3dafc3008c"
down_revision: str | None = "a4973a3782e3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

FEED_TYPES_BEFORE = "feed_type IN ('JSON', 'CSV', 'STIX')"
FEED_TYPES_AFTER = "feed_type IN ('JSON', 'CSV', 'STIX', 'OTX')"


def upgrade() -> None:
    op.create_table(
        "indicator_sources",
        sa.Column("indicator_id", sa.Uuid(), nullable=False),
        sa.Column("feed_id", sa.Uuid(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("hit_count", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["feed_id"], ["threat_feeds.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["indicator_id"], ["indicators.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("indicator_id", "feed_id"),
    )
    op.create_index("idx_indicator_sources_feed", "indicator_sources", ["feed_id"], unique=False)
    op.execute(
        "INSERT INTO indicator_sources (indicator_id, feed_id, first_seen, last_seen, hit_count) "
        "SELECT id, feed_id, first_seen, last_seen, hit_count FROM indicators "
        "WHERE feed_id IS NOT NULL"
    )

    op.drop_constraint("ck_threat_feeds_feed_type", "threat_feeds", type_="check")
    op.create_check_constraint("ck_threat_feeds_feed_type", "threat_feeds", FEED_TYPES_AFTER)


def downgrade() -> None:
    otx_feeds = op.get_bind().scalar(
        sa.text("SELECT count(*) FROM threat_feeds WHERE feed_type = 'OTX'")
    )
    if otx_feeds:
        raise RuntimeError(
            f"{otx_feeds} flux OTX existent : supprimez-les (sentry / API) avant de "
            "revenir en arrière. Aucune donnée n'est supprimée implicitement."
        )
    op.drop_constraint("ck_threat_feeds_feed_type", "threat_feeds", type_="check")
    op.create_check_constraint("ck_threat_feeds_feed_type", "threat_feeds", FEED_TYPES_BEFORE)

    op.drop_index("idx_indicator_sources_feed", table_name="indicator_sources")
    op.drop_table("indicator_sources")
