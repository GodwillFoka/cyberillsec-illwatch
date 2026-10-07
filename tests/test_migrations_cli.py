"""Tests de bout en bout sur PostgreSQL réel : migrations Alembic et commandes CLI.

Critère M1 : « PostgreSQL migre via Alembic sans erreur ». Ces tests ne tournent
que si `DATABASE_URL` pointe vers PostgreSQL (CI GitLab, ou Docker Compose en local).
Ils écrivent réellement en base : chaque test nettoie ce qu'il crée.
"""

import asyncio

import pytest
from alembic import command
from click.testing import CliRunner
from conftest import drop_public_schema
from sqlalchemy import delete, text

from illwatch.app import migrations
from illwatch.app.database import Base, dispose_engine, get_engine
from illwatch.app.models import ThreatFeed, User
from illwatch.cli.main import cli
from illwatch.modules.foundation.seed import REFERENCE_FEEDS

pytestmark = pytest.mark.postgres


async def _reset_schema() -> None:
    """Repart d'une base vierge (les autres tests créent les tables via `create_all`)."""
    async with get_engine().begin() as conn:
        await drop_public_schema(conn)
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


def test_commande_status() -> None:
    asyncio.run(_reset_schema())
    runner = CliRunner()
    assert runner.invoke(cli, ["db", "init"]).exit_code == 0
    result = runner.invoke(cli, ["status"])
    assert result.exit_code == 0, result.output
    assert "à jour" in result.output
    assert "Jalon M2" in result.output and "non atteint" in result.output


async def _checks_in_db() -> dict[str, str]:
    async with get_engine().connect() as conn:
        rows = await conn.execute(
            text(
                "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE contype = 'c' AND conrelid::regclass::text "
                "IN ('indicators', 'threat_feeds', 'cves', 'incidents', 'incident_events', "
                "'hunting_sessions', 'hunting_matches')"
            )
        )
        found = {str(r[0]): str(r[1]) for r in rows.all()}
    await dispose_engine()
    return found


def test_contraintes_check_migrees_identiques_au_modele() -> None:
    """`alembic check` ignore le texte des CHECK : comparaison faite ici, après migration.

    C'est ce test qui signale une valeur d'énumération ajoutée au code (ex. `OTX`) sans
    la migration correspondante.
    """
    asyncio.run(_reset_schema())
    migrations.upgrade("head")
    in_db = asyncio.run(_checks_in_db())

    declared = {
        c.name: str(c.sqltext)
        for table in (
            "indicators",
            "threat_feeds",
            "cves",
            "incidents",
            "incident_events",
            "hunting_sessions",
            "hunting_matches",
        )
        for c in Base.metadata.tables[table].constraints
        if c.__class__.__name__ == "CheckConstraint"
    }
    assert set(declared) == set(in_db)
    for name, expression in declared.items():
        allowed = {v.strip(" '") for v in expression.split("(", 1)[1].rstrip(")").split(",")}
        quoted = {v.split("'")[1] for v in in_db[name].split("ARRAY[", 1)[-1].split(",")}
        assert allowed == quoted, (name, allowed, quoted)


async def _exec(*statements: str) -> list[tuple[object, ...]]:
    result: list[tuple[object, ...]] = []
    try:
        async with get_engine().begin() as conn:
            for statement in statements:
                cursor = await conn.execute(text(statement))
                if cursor.returns_rows:
                    result = [tuple(r) for r in cursor.all()]
    finally:  # même en cas d'erreur SQL : le moteur ne doit pas survivre à sa boucle
        await dispose_engine()
    return result


def test_migration_provenance_reprend_les_ioc_existants() -> None:
    """1f3dafc3008c recopie `indicators.feed_id` dans `indicator_sources`, et refuse de
    redescendre tant qu'un flux OTX existe (aucune suppression implicite)."""
    asyncio.run(_reset_schema())
    migrations.upgrade("a4973a3782e3")
    asyncio.run(
        _exec(
            "INSERT INTO threat_feeds (id, name, url, feed_type, polling_interval, is_active, "
            "status, created_at, updated_at) VALUES ('00000000-0000-0000-0000-00000000f001', "
            "'Feodo', 'https://f.example.org/x', 'CSV', 3600, true, 'HEALTHY', now(), now())",
            "INSERT INTO indicators (id, feed_id, type, value, severity, hit_count, first_seen, "
            "last_seen) VALUES ('00000000-0000-0000-0000-00000000e001', "
            "'00000000-0000-0000-0000-00000000f001', 'IPV4', '203.0.113.7', 'HIGH', 4, "
            "now() - interval '3 days', now())",
        )
    )

    migrations.upgrade("head")
    rows = asyncio.run(_exec("SELECT feed_id::text, hit_count FROM indicator_sources"))
    assert rows == [("00000000-0000-0000-0000-00000000f001", 4)]

    asyncio.run(
        _exec(
            "INSERT INTO threat_feeds (id, name, url, feed_type, polling_interval, is_active, "
            "status, created_at, updated_at) VALUES ('00000000-0000-0000-0000-00000000f002', "
            "'OTX', 'https://otx.alienvault.com/api/v1/pulses/subscribed', 'OTX', 3600, true, "
            "'PENDING', now(), now())"
        )
    )
    with pytest.raises(RuntimeError, match="flux OTX"):
        migrations.downgrade("a4973a3782e3")

    asyncio.run(_exec("DELETE FROM threat_feeds WHERE feed_type = 'OTX'"))
    migrations.downgrade("a4973a3782e3")
    asyncio.run(_reset_schema())


def test_chronologie_immuable_meme_en_sql_direct() -> None:
    """RF-19 + M7 : les déclencheurs refusent UPDATE, DELETE et TRUNCATE sur la chronologie
    des incidents et sur le journal d'audit."""

    asyncio.run(_reset_schema())
    migrations.upgrade("head")
    asyncio.run(
        _exec(
            "INSERT INTO incidents (id, title, description, severity, status, created_at, "
            "updated_at) VALUES ('00000000-0000-0000-0000-0000000000a1', 't', 'd', 'LOW', "
            "'NOUVEAU', now(), now())",
            "INSERT INTO incident_events (id, incident_id, event_type, message, created_at) "
            "VALUES ('00000000-0000-0000-0000-0000000000b1', "
            "'00000000-0000-0000-0000-0000000000a1', 'CREATED', 'ouvert', now())",
            "INSERT INTO audit_events (id, occurred_at, action, outcome) VALUES "
            "('00000000-0000-0000-0000-0000000000c1', now(), 'auth.login', 'SUCCESS')",
        )
    )
    try:
        _assert_immutable()
    finally:
        asyncio.run(_reset_schema())


def _assert_immutable() -> None:
    from sqlalchemy.exc import DBAPIError

    for statement in (
        "UPDATE incident_events SET message = 'falsifié'",
        "DELETE FROM incident_events",
        "TRUNCATE incident_events",  # M7 : un déclencheur de ligne ne voyait pas TRUNCATE
        "TRUNCATE incidents CASCADE",
        "UPDATE audit_events SET outcome = 'FAILURE'",
        "DELETE FROM audit_events",
        "TRUNCATE audit_events",
    ):
        with pytest.raises(DBAPIError, match="immuable"):
            asyncio.run(_exec(statement))
    rows = asyncio.run(_exec("SELECT message FROM incident_events"))
    assert rows == [("ouvert",)]
    assert asyncio.run(_exec("SELECT outcome FROM audit_events")) == [("SUCCESS",)]
    with pytest.raises(DBAPIError, match="ck_incidents_severity"):
        asyncio.run(
            _exec(
                "INSERT INTO incidents (id, title, description, severity, status, created_at, "
                "updated_at) VALUES (gen_random_uuid(), 't', 'd', 'URGENT', 'NOUVEAU', now(), "
                "now())"
            )
        )
