"""M7 — journal d'audit de sécurité et limitation des connexions par couple compte × IP."""

import logging
from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app.models import AuditEvent
from sentry.app.models.audit import ImmutableAuditError
from sentry.app.security import create_access_token
from sentry.app.throttle import USER_FACTOR, LocalCounter, LoginThrottle
from sentry.modules.foundation.audit import AuditContext, AuditRecorder, list_audit_events
from sentry.modules.foundation.users import create_user
from sentry.shared.enums import AuditOutcome, UserRole

PASSWORD = "mot-de-passe-robuste-2026"


async def _user(session: AsyncSession, role: UserRole) -> tuple[str, dict[str, str]]:
    name = f"{role.value.lower()}-{uuid4().hex[:6]}"
    user = await create_user(
        session, username=name, email=f"{name}@cyberill.test", password=PASSWORD, role=role
    )
    return name, {"Authorization": f"Bearer {create_access_token(user.id, user.role)}"}


async def _events(session: AsyncSession, action: str) -> list[AuditEvent]:
    rows = await session.execute(
        select(AuditEvent).where(AuditEvent.action == action).order_by(AuditEvent.occurred_at)
    )
    return list(rows.scalars())


async def test_connexions_consignees(client: AsyncClient, db_session: AsyncSession) -> None:
    name, _ = await _user(db_session, UserRole.ANALYST)
    ok = await client.post(
        "/api/v1/auth/token",
        data={"username": name, "password": PASSWORD},
        headers={"X-Request-ID": "login-1"},
    )
    assert ok.status_code == 200
    await client.post("/api/v1/auth/token", data={"username": name, "password": "faux"})
    await client.post(
        "/api/v1/auth/token", data={"username": "mot-de-passe-tape-ici", "password": "x"}
    )

    events = await _events(db_session, "auth.login")
    assert [(e.outcome, e.actor_name) for e in events] == [
        (AuditOutcome.SUCCESS, name),
        (AuditOutcome.FAILURE, name),
        (AuditOutcome.FAILURE, "(inconnu)"),  # identifiant inconnu jamais recopié
    ]
    assert events[0].request_id == "login-1"
    assert events[0].actor_id is not None and events[1].target_type == "user"
    assert all("mot-de-passe-tape-ici" not in str(e.detail) for e in events)


async def test_blocage_consigne(client: AsyncClient, db_session: AsyncSession) -> None:
    name, _ = await _user(db_session, UserRole.VIEWER)
    for _ in range(6):
        await client.post("/api/v1/auth/token", data={"username": name, "password": "faux"})
    outcomes = [e.outcome for e in await _events(db_session, "auth.login")]
    assert outcomes == [AuditOutcome.FAILURE] * 5 + [AuditOutcome.DENIED]


async def test_refus_de_droits_consigne(client: AsyncClient, db_session: AsyncSession) -> None:
    name, viewer = await _user(db_session, UserRole.VIEWER)
    response = await client.post(
        "/api/v1/incidents",
        json={"title": "t", "description": "d", "severity": "LOW"},
        headers=viewer,
    )
    assert response.status_code == 403
    (event,) = await _events(db_session, "authz.denied")
    assert event.actor_name == name and event.outcome == AuditOutcome.DENIED
    assert event.detail == {"method": "POST", "path": "/api/v1/incidents", "role": "VIEWER"}


async def test_administration_et_export_consignes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, admin = await _user(db_session, UserRole.ADMIN)
    created = await client.post(
        "/api/v1/feeds",
        json={"name": "Flux audité", "url": "https://example.org/f.json", "feed_type": "JSON"},
        headers=admin,
    )
    assert created.status_code == 201
    feed_id = created.json()["id"]
    await client.patch(f"/api/v1/feeds/{feed_id}", json={"is_active": False}, headers=admin)
    await client.delete(f"/api/v1/feeds/{feed_id}", headers=admin)
    ssrf = await client.post(
        "/api/v1/feeds",
        json={"name": "ssrf", "url": "https://169.254.169.254/latest/", "feed_type": "JSON"},
        headers=admin,
    )
    assert ssrf.status_code == 422
    await client.get("/api/v1/dashboard/export?dataset=iocs&format=csv", headers=admin)

    rows, total = await list_audit_events(db_session, action="feed.")
    # Le 422 de l'URL interne vient de la validation du schéma, avant la route : seules les
    # actions ayant franchi la validation sont consignées (ADR-011, limite assumée).
    assert total == 3
    assert sorted(r.action for r in rows) == ["feed.create", "feed.delete", "feed.update"]
    update = next(r for r in rows if r.action == "feed.update")
    assert update.detail == {"is_active": "False"}
    (export,) = await _events(db_session, "data.export")
    assert export.target_id == "iocs" and export.detail == {"format": "csv"}


async def test_consultation_reservee_aux_admins(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, admin = await _user(db_session, UserRole.ADMIN)
    _, analyst = await _user(db_session, UserRole.ANALYST)
    assert (await client.get("/api/v1/audit", headers=analyst)).status_code == 403
    page = await client.get(
        "/api/v1/audit", params={"action": "authz.", "outcome": "DENIED"}, headers=admin
    )
    assert page.status_code == 200
    body = page.json()
    assert body["total"] == 1  # le refus de l'analyste, lui-même consigné
    assert body["items"][0]["detail"]["path"] == "/api/v1/audit"


async def test_journal_en_ajout_seul(db_session: AsyncSession) -> None:
    recorder = AuditRecorder(lambda e: _add(db_session, e))
    await recorder.record("test.action", context=AuditContext(ip="203.0.113.7"))
    (event,) = await _events(db_session, "test.action")
    event.outcome = AuditOutcome.FAILURE
    with pytest.raises(ImmutableAuditError):
        await db_session.flush()
    await db_session.rollback()


async def _add(session: AsyncSession, event: AuditEvent) -> None:
    session.add(event)
    await session.flush()


async def test_ecriture_en_echec_n_interrompt_pas(caplog: pytest.LogCaptureFixture) -> None:
    async def _broken(_: AuditEvent) -> None:
        raise ConnectionError("base indisponible")

    logger = logging.getLogger("sentry.audit")
    logger.addHandler(caplog.handler)
    try:
        await AuditRecorder(_broken).record("auth.login", detail={"long": "x" * 2000})
    finally:
        logger.removeHandler(caplog.handler)
    assert any(r.getMessage() == "audit.write_failed" for r in caplog.records)


async def test_detail_tronque() -> None:
    captured: list[AuditEvent] = []

    async def _keep(event: AuditEvent) -> None:
        captured.append(event)

    await AuditRecorder(_keep).record("x", detail={"long": "a" * 2000, "n": 3, "obj": [1, 2]})
    assert captured[0].detail == {"long": "a" * 500, "n": 3, "obj": "[1, 2]"}


# --- Limitation par couple compte × IP -----------------------------------------------------------


async def test_attaquant_bloque_titulaire_epargne() -> None:
    throttle = LoginThrottle(LocalCounter(), max_failures=5, window=900)
    for _ in range(5):
        await throttle.failure("alice", "198.51.100.66")
    assert await throttle.blocked("alice", "198.51.100.66")  # l'attaquant
    assert not await throttle.blocked("alice", "192.0.2.10")  # la titulaire, ailleurs


async def test_force_brute_distribuee_bloque_le_compte() -> None:
    throttle = LoginThrottle(LocalCounter(), max_failures=2, window=900)
    for n in range(2 * USER_FACTOR):
        await throttle.failure("bob", f"203.0.113.{n}")
    assert await throttle.blocked("bob", "192.0.2.200")


async def test_succes_remet_a_zero_compte_et_couple() -> None:
    throttle = LoginThrottle(LocalCounter(), max_failures=2, window=900)
    await throttle.failure("carol", "192.0.2.1")
    await throttle.success("carol", "192.0.2.1")
    await throttle.failure("carol", "192.0.2.1")
    assert not await throttle.blocked("carol", "192.0.2.1")


# --- CLI -------------------------------------------------------------------------------------


@pytest.mark.postgres
def test_cli_creation_de_compte_et_consultation() -> None:
    from click.testing import CliRunner

    from sentry.cli.main import cli

    runner = CliRunner()
    name = f"cli-{uuid4().hex[:6]}"
    created = runner.invoke(
        cli,
        [
            "users",
            "create",
            "--username",
            name,
            "--email",
            f"{name}@cyberill.test",
            "--role",
            "viewer",
            "--password",
            PASSWORD,
        ],
    )
    assert created.exit_code == 0, created.output
    listed = runner.invoke(cli, ["audit", "list", "--action", "user.", "--limit", "500"])
    assert listed.exit_code == 0, listed.output
    assert "user.create" in listed.output and "cli:" in listed.output
