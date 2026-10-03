"""production hardening

M7 — Production Hardening (ADR-011) :

- table `audit_events`, journal d'audit de sécurité en ajout seul ;
- fonction générique `sentry_refuse_rewrite()` et déclencheurs refusant `UPDATE`, `DELETE`
  **et `TRUNCATE`** sur `audit_events` et `incident_events`. L'audit du 03/10/2026 a montré
  qu'un déclencheur de ligne (posé en phase 4) ne voit pas `TRUNCATE` : la chronologie des
  incidents pouvait être vidée d'une seule instruction.

Limite assumée : le propriétaire des tables peut toujours supprimer un déclencheur. La
séparation des rôles PostgreSQL (propriétaire ≠ compte applicatif) est le lot 2 de M7.

Revision ID: e7b2c9d41f05
Revises: c4d9e1f20a83
Create Date: 2026-10-03 17:19:54.173142
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e7b2c9d41f05"
down_revision: str | None = "c4d9e1f20a83"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

REFUSE_FUNCTION = """
CREATE OR REPLACE FUNCTION sentry_refuse_rewrite() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION '% est immuable : % refusé', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$ LANGUAGE plpgsql
"""


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_id", sa.Uuid(), nullable=True),
        sa.Column("actor_name", sa.String(length=150), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("target_type", sa.String(length=32), nullable=True),
        sa.Column("target_id", sa.String(length=255), nullable=True),
        sa.Column("ip", sa.String(length=45), nullable=True),
        sa.Column("request_id", sa.String(length=64), nullable=True),
        sa.Column("detail", sa.JSON(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.CheckConstraint(
            "outcome IN ('SUCCESS', 'FAILURE', 'DENIED')", name="ck_audit_events_outcome"
        ),
        sa.ForeignKeyConstraint(
            ["actor_id"], ["users.id"], name="audit_events_actor_id_fkey", ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id", name="audit_events_pkey"),
    )
    op.create_index("idx_audit_events_action", "audit_events", ["action", "occurred_at"])
    op.create_index("idx_audit_events_actor", "audit_events", ["actor_id", "occurred_at"])
    op.create_index("idx_audit_events_occurred_at", "audit_events", ["occurred_at"])

    op.execute(REFUSE_FUNCTION)
    op.execute(
        "CREATE TRIGGER trg_audit_events_immutable BEFORE UPDATE OR DELETE ON audit_events "
        "FOR EACH ROW EXECUTE FUNCTION sentry_refuse_rewrite()"
    )
    for table in ("audit_events", "incident_events"):
        op.execute(
            f"CREATE TRIGGER trg_{table}_no_truncate BEFORE TRUNCATE ON {table} "
            "FOR EACH STATEMENT EXECUTE FUNCTION sentry_refuse_rewrite()"
        )


def downgrade() -> None:
    for table in ("audit_events", "incident_events"):
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_no_truncate ON {table}")
    op.execute("DROP TRIGGER IF EXISTS trg_audit_events_immutable ON audit_events")
    op.execute("DROP FUNCTION IF EXISTS sentry_refuse_rewrite()")
    op.drop_index("idx_audit_events_occurred_at", table_name="audit_events")
    op.drop_index("idx_audit_events_actor", table_name="audit_events")
    op.drop_index("idx_audit_events_action", table_name="audit_events")
    op.drop_table("audit_events")
