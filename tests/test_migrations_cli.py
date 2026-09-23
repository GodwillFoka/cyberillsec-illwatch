"""Tests de bout en bout sur PostgreSQL réel : migrations Alembic et commandes CLI.

Critère M1 : « PostgreSQL migre via Alembic sans erreur ». Ces tests ne tournent
que si `DATABASE_URL` pointe vers PostgreSQL (CI GitLab, ou Docker Compose en local).
Ils écrivent réellement en base : chaque test nettoie ce qu'il crée.
"""

import asyncio

import pytest
from alembic import command
from click.testing import CliRunner
from sqlalchemy import delete, text

from sentry.app import migrations
from sentry.app.database import Base, dispose_engine, get_engine
from sentry.app.models import ThreatFeed, User
from sentry.cli.main import cli
from sentry.modules.foundation.seed import REFERENCE_FEEDS

pytestmark = pytest.mark.postgres


async def _reset_schema() -> None:
    """Repart d'une base vierge (les autres tests créent les tables via `create_all`)."""
    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.execute(text("DROP TABLE IF EXISTS alembic_version"))
    await dispose_engine()


async def _current() -> str | None:
    try:
        return await migrations.current_revision()
    finally:
        await dispose_engine()


async def _cleanup(username: str) -> None:
    async with get_engine().begin() as conn:
        await conn.execute(delete(User).where(User.username == username))
        await conn.execute(
            delete(ThreatFeed).where(ThreatFeed.name.in_([f.name for f in REFERENCE_FEEDS]))
        )
    await dispose_engine()


def test_migrations_montent_descendent_et_collent_aux_modeles() -> None:
    asyncio.run(_reset_schema())

    migrations.upgrade("head")
    assert asyncio.run(_current()) == migrations.head_revision()

    # Aucune dérive entre modèles SQLAlchemy et migrations (lève si autogenerate trouve un écart).
    command.check(migrations.alembic_config())

    migrations.downgrade("base")
    assert asyncio.run(_current()) is None

    migrations.upgrade("head")
    assert asyncio.run(_current()) == migrations.head_revision()


def test_parcours_cli_complet() -> None:
    asyncio.run(_reset_schema())
    runner = CliRunner()
    username = "cli-admin"

    try:
        result = runner.invoke(cli, ["db", "init"])
        assert result.exit_code == 0, result.output

        result = runner.invoke(cli, ["db", "current"])
        assert result.exit_code == 0, result.output
        assert "en retard" not in result.output

        result = runner.invoke(
            cli,
            [
                "users",
                "create",
                "--username",
                username,
                "--email",
                "cli-admin@cyberill.test",
                "--role",
                "admin",
                "--password",
                "un-mot-de-passe-solide",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "ADMIN" in result.output

        result = runner.invoke(
            cli,
            [
                "users",
                "create",
                "--username",
                username,
                "--email",
                "autre@cyberill.test",
                "--password",
                "un-mot-de-passe-solide",
            ],
        )
        assert result.exit_code == 1
        assert "déjà utilisé" in result.output

        first = runner.invoke(cli, ["seed"])
        assert first.exit_code == 0, first.output
        assert first.output.count("+") == len(REFERENCE_FEEDS)

        second = runner.invoke(cli, ["seed"])
        assert second.exit_code == 0
        assert "déjà présentes" in second.output

        result = runner.invoke(cli, ["db", "check"])
        assert result.exit_code == 0
    finally:
        asyncio.run(_cleanup(username))
