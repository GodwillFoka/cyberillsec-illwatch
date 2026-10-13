"""soc operations

M9 SOC Operations (ADR-022) :

- `incidents.tier` : niveau SOC (L1, L2, L3), L1 pour les incidents existants ;
- `incident_events.event_type` accepte `ESCALATED`, `HUNT_RUN`, `IOC_EXCLUDED` (contrainte CHECK
  réécrite à la main : Alembic ne compare pas son texte) ;
- `hunting_sessions` : version des règles appliquées et incident d'origine ;
- table `exclusions` : liste d'exclusion des IOC faux positifs (tâche 3.6).

Revision ID: c9f1a3e5b742
Revises: b7e4d2a9c613
Create Date: 2026-10-14 04:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "c9f1a3e5b742"
down_revision: str | None = "b7e4d2a9c613"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

EVENTS_BEFORE = (
    "event_type IN ('CREATED', 'STATUS_CHANGE', 'ASSIGNED', 'COMMENT', 'IOC_ATTACHED', "
    "'CVE_ATTACHED', 'ACTION_TAKEN')"
)
EVENTS_AFTER = (
    "event_type IN ('CREATED', 'STATUS_CHANGE', 'ASSIGNED', 'COMMENT', 'IOC_ATTACHED', "
    "'CVE_ATTACHED', 'ACTION_TAKEN', 'ESCALATED', 'HUNT_RUN', 'IOC_EXCLUDED')"
)
TRIGGERS_BEFORE = "trigger IN ('MANUAL', 'SCHEDULED')"
TRIGGERS_AFTER = "trigger IN ('MANUAL', 'SCHEDULED', 'INCIDENT')"
INDICATOR_TYPES = (
    "indicator_type IN ('IPV4', 'IPV6', 'DOMAIN', 'URL', 'HASH_MD5', 'HASH_SHA1', "
    "'HASH_SHA256', 'EMAIL', 'NETWORK')"
)


def upgrade() -> None:
    op.add_column("incidents", sa.Column("tier", sa.String(2), nullable=False, server_default="L1"))
    op.create_check_constraint("ck_incidents_tier", "incidents", "tier IN ('L1', 'L2', 'L3')")

    op.drop_constraint("ck_incident_events_event_type", "incident_events", type_="check")
    op.create_check_constraint("ck_incident_events_event_type", "incident_events", EVENTS_AFTER)

    op.add_column("hunting_sessions", sa.Column("rule_versions", sa.JSON(), nullable=True))
    op.add_column(
        "hunting_sessions",
        sa.Column(
            "incident_id",
            sa.Uuid(),
            sa.ForeignKey("incidents.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_hunting_sessions_incident_id", "hunting_sessions", ["incident_id"])
    op.drop_constraint("ck_hunting_sessions_trigger", "hunting_sessions", type_="check")
    op.create_check_constraint("ck_hunting_sessions_trigger", "hunting_sessions", TRIGGERS_AFTER)

    op.create_table(
        "exclusions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("indicator_type", sa.String(20), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column(
            "created_by",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "incident_id",
            sa.Uuid(),
            sa.ForeignKey("incidents.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("indicator_type", "value", name="uq_exclusions_type_value"),
        sa.CheckConstraint(INDICATOR_TYPES, name="ck_exclusions_type"),
    )


def downgrade() -> None:
    blocked = op.get_bind().scalar(
        sa.text(
            "SELECT count(*) FROM incident_events "
            "WHERE event_type IN ('ESCALATED', 'HUNT_RUN', 'IOC_EXCLUDED')"
        )
    )
    if blocked:
        raise RuntimeError(
            f"{blocked} évènements de chronologie M9 existent : la chronologie est immuable, "
            "le retour en arrière est refusé."
        )
    op.drop_table("exclusions")
    op.execute("UPDATE hunting_sessions SET trigger = 'MANUAL' WHERE trigger = 'INCIDENT'")
    op.drop_constraint("ck_hunting_sessions_trigger", "hunting_sessions", type_="check")
    op.create_check_constraint("ck_hunting_sessions_trigger", "hunting_sessions", TRIGGERS_BEFORE)
    op.drop_index("ix_hunting_sessions_incident_id", table_name="hunting_sessions")
    op.drop_column("hunting_sessions", "incident_id")
    op.drop_column("hunting_sessions", "rule_versions")
    op.drop_constraint("ck_incident_events_event_type", "incident_events", type_="check")
    op.create_check_constraint("ck_incident_events_event_type", "incident_events", EVENTS_BEFORE)
    op.drop_constraint("ck_incidents_tier", "incidents", type_="check")
    op.drop_column("incidents", "tier")
