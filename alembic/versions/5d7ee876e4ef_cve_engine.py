"""cve engine

Moteur CVE — phase 3 (ADR-007) : priorité SOC stockée, champs KEV et EPSS complets,
historique des changements de priorité, alertes et curseurs de synchronisation.

La priorité des CVE déjà présentes est dérivée de leur score avec la grille de l'ADR-001
(80 / 60 / 40) : aucune ligne n'a de priorité vide ni incohérente avec son score.

Revision ID: 5d7ee876e4ef
Revises: 1f3dafc3008c
Create Date: 2026-09-29 08:45:17.147759
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "5d7ee876e4ef"
down_revision: str | None = "1f3dafc3008c"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PRIORITIES = "priority IN ('P0_CRITIQUE', 'P1_ELEVE', 'P2_MOYEN', 'P3_FAIBLE')"


def upgrade() -> None:
    op.create_table(
        "collector_state",
        sa.Column("name", sa.String(length=40), nullable=False),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cursor", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("items", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("name"),
    )
    op.create_table(
        "cve_alerts",
        sa.Column("cve_id", sa.String(length=30), nullable=False),
        sa.Column("score", sa.Numeric(precision=5, scale=2), nullable=False),
        sa.Column("previous_score", sa.Numeric(precision=5, scale=2), nullable=True),
        sa.Column("priority", sa.String(length=20), nullable=False),
        sa.Column("reason", sa.String(length=40), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("delivery_attempts", sa.Integer(), nullable=False),
        sa.Column("last_delivery_error", sa.Text(), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by", sa.Uuid(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["acknowledged_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["cve_id"], ["cves.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_cve_alerts_created", "cve_alerts", ["created_at"], unique=False)
    op.create_table(
        "cve_priority_history",
        sa.Column("cve_id", sa.String(length=30), nullable=False),
        sa.Column("old_priority", sa.String(length=20), nullable=True),
        sa.Column("new_priority", sa.String(length=20), nullable=False),
        sa.Column("old_score", sa.Numeric(precision=5, scale=2), nullable=True),
        sa.Column("new_score", sa.Numeric(precision=5, scale=2), nullable=False),
        sa.Column("reason", sa.String(length=40), nullable=False),
        sa.Column(
            "changed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["cve_id"], ["cves.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "idx_cve_priority_history_cve",
        "cve_priority_history",
        ["cve_id", "changed_at"],
        unique=False,
    )
    op.add_column("cves", sa.Column("epss_percentile", sa.Numeric(precision=5, scale=4)))
    op.add_column("cves", sa.Column("kev_date_added", sa.Date(), nullable=True))
    op.add_column("cves", sa.Column("kev_due_date", sa.Date(), nullable=True))
    op.add_column("cves", sa.Column("kev_required_action", sa.Text(), nullable=True))
    op.add_column("cves", sa.Column("priority", sa.String(length=20), nullable=True))
    op.execute(
        "UPDATE cves SET priority = CASE "
        "WHEN composite_risk_score >= 80 THEN 'P0_CRITIQUE' "
        "WHEN composite_risk_score >= 60 THEN 'P1_ELEVE' "
        "WHEN composite_risk_score >= 40 THEN 'P2_MOYEN' "
        "ELSE 'P3_FAIBLE' END"
    )
    op.alter_column("cves", "priority", nullable=False)
    op.create_check_constraint("ck_cves_priority", "cves", PRIORITIES)
    op.create_index("idx_cves_last_modified", "cves", ["last_modified_date"], unique=False)
    op.create_index("idx_cves_priority", "cves", ["priority"], unique=False)


def downgrade() -> None:
    op.drop_index("idx_cves_priority", table_name="cves")
    op.drop_index("idx_cves_last_modified", table_name="cves")
    op.drop_constraint("ck_cves_priority", "cves", type_="check")
    op.drop_column("cves", "priority")
    op.drop_column("cves", "kev_required_action")
    op.drop_column("cves", "kev_due_date")
    op.drop_column("cves", "kev_date_added")
    op.drop_column("cves", "epss_percentile")
    op.drop_index("idx_cve_priority_history_cve", table_name="cve_priority_history")
    op.drop_table("cve_priority_history")
    op.drop_index("idx_cve_alerts_created", table_name="cve_alerts")
    op.drop_table("cve_alerts")
    op.drop_table("collector_state")
