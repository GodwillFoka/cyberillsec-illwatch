"""incident management

Gestion d'incidents — phase 4 (ADR-008) : liens incident ↔ IOC / CVE (RF-20), auteur et
alerte d'origine, statuts de transition dans la chronologie, contraintes CHECK, et
**déclencheur PostgreSQL rendant `incident_events` immuable** (RF-19) : un UPDATE ou un
DELETE direct en SQL est refusé, pas seulement par l'application.

Revision ID: 8a1c2e4f6b70
Revises: 5d7ee876e4ef
Create Date: 2026-10-03 10:12:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "8a1c2e4f6b70"
down_revision: str | None = "5d7ee876e4ef"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SEVERITIES = "severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')"
STATUSES = (
    "status IN ('NOUVEAU', 'ANALYSE', 'CONFINEMENT', 'ERADICATION', 'RECUPERATION', 'CLOTURE')"
)
EVENT_TYPES = (
    "event_type IN ('CREATED', 'STATUS_CHANGE', 'ASSIGNED', 'COMMENT', 'IOC_ATTACHED', "
    "'CVE_ATTACHED', 'ACTION_TAKEN')"
)

IMMUTABLE_FUNCTION = """
CREATE OR REPLACE FUNCTION sentry_refuse_timeline_rewrite() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'incident_events est immuable (RF-19) : % refusé', TG_OP
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$ LANGUAGE plpgsql
"""
IMMUTABLE_TRIGGER = """
CREATE TRIGGER trg_incident_events_immutable
    BEFORE UPDATE OR DELETE ON incident_events
    FOR EACH ROW EXECUTE FUNCTION sentry_refuse_timeline_rewrite()
"""


def upgrade() -> None:
    op.create_table(
        "incident_cves",
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("cve_id", sa.String(length=30), nullable=False),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("added_by", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(["added_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["cve_id"], ["cves.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("incident_id", "cve_id"),
    )
    op.create_table(
        "incident_indicators",
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("indicator_id", sa.Uuid(), nullable=False),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("added_by", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(["added_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["indicator_id"], ["indicators.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("incident_id", "indicator_id"),
    )
    op.add_column("incident_events", sa.Column("from_status", sa.String(length=30)))
    op.add_column("incident_events", sa.Column("to_status", sa.String(length=30)))
    op.add_column("incidents", sa.Column("created_by", sa.Uuid(), nullable=True))
    op.add_column("incidents", sa.Column("source_alert_id", sa.Uuid(), nullable=True))
    op.create_index(
        "idx_incidents_status_severity", "incidents", ["status", "severity"], unique=False
    )
    op.create_unique_constraint("incidents_source_alert_id_key", "incidents", ["source_alert_id"])
    op.create_foreign_key(
        "incidents_source_alert_id_fkey",
        "incidents",
        "cve_alerts",
        ["source_alert_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        "incidents_created_by_fkey",
        "incidents",
        "users",
        ["created_by"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_check_constraint("ck_incidents_severity", "incidents", SEVERITIES)
    op.create_check_constraint("ck_incidents_status", "incidents", STATUSES)
    op.create_check_constraint("ck_incident_events_event_type", "incident_events", EVENT_TYPES)
    op.execute(IMMUTABLE_FUNCTION)
    op.execute(IMMUTABLE_TRIGGER)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_incident_events_immutable ON incident_events")
    op.execute("DROP FUNCTION IF EXISTS sentry_refuse_timeline_rewrite()")
    op.drop_constraint("ck_incident_events_event_type", "incident_events", type_="check")
    op.drop_constraint("ck_incidents_status", "incidents", type_="check")
    op.drop_constraint("ck_incidents_severity", "incidents", type_="check")
    op.drop_constraint("incidents_created_by_fkey", "incidents", type_="foreignkey")
    op.drop_constraint("incidents_source_alert_id_fkey", "incidents", type_="foreignkey")
    op.drop_constraint("incidents_source_alert_id_key", "incidents", type_="unique")
    op.drop_index("idx_incidents_status_severity", table_name="incidents")
    op.drop_column("incidents", "source_alert_id")
    op.drop_column("incidents", "created_by")
    op.drop_column("incident_events", "to_status")
    op.drop_column("incident_events", "from_status")
    op.drop_table("incident_indicators")
    op.drop_table("incident_cves")
