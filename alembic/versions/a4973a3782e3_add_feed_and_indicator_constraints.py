"""add feed and indicator constraints

Revision ID: a4973a3782e3
Revises: c36227f04410
Create Date: 2026-09-25 12:06:56.656591
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "a4973a3782e3"
down_revision: Union[str, None] = "c36227f04410"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add enum-like CHECK constraints and IOC expiration."""
    op.add_column(
        "indicators",
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )

    op.create_check_constraint(
        "ck_threat_feeds_feed_type",
        "threat_feeds",
        "feed_type IN ('JSON', 'CSV', 'STIX')",
    )

    op.create_check_constraint(
        "ck_threat_feeds_status",
        "threat_feeds",
        "status IN ('PENDING', 'HEALTHY', 'DEGRADED')",
    )

    op.create_check_constraint(
        "ck_indicators_type",
        "indicators",
        (
            "type IN ("
            "'IPV4', 'IPV6', 'DOMAIN', 'URL', "
            "'HASH_MD5', 'HASH_SHA1', 'HASH_SHA256', 'EMAIL'"
            ")"
        ),
    )

    op.create_check_constraint(
        "ck_indicators_severity",
        "indicators",
        "severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
    )


def downgrade() -> None:
    """Remove enum-like CHECK constraints and IOC expiration."""
    op.drop_constraint(
        "ck_indicators_severity",
        "indicators",
        type_="check",
    )

    op.drop_constraint(
        "ck_indicators_type",
        "indicators",
        type_="check",
    )

    op.drop_constraint(
        "ck_threat_feeds_status",
        "threat_feeds",
        type_="check",
    )

    op.drop_constraint(
        "ck_threat_feeds_feed_type",
        "threat_feeds",
        type_="check",
    )

    op.drop_column("indicators", "expires_at")