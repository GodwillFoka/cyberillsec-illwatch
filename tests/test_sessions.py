"""M7 lot 2 — sessions révocables, rotation de clé, rôles PostgreSQL, secrets de connexion."""

import asyncio
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest
from click.testing import CliRunner
from httpx import AsyncClient
from pydantic import SecretStr, ValidationError
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from illwatch.app.config import Settings
from illwatch.app.models import AuditEvent, RefreshToken
from illwatch.app.security import (
    InvalidTokenError,
    create_access_token,
    decode_access_token,
    key_id,
)
from illwatch.modules.foundation.sessions import (
    InvalidRefreshTokenError,
    issue_refresh_token,
    rotate_refresh_token,
)
from illwatch.modules.foundation.users import create_user
from illwatch.shared.enums import AuditOutcome, UserRole
from illwatch.shared.urls import mask_url_password

PASSWORD = "mot-de-passe-robuste-2026"
KEY_A = "a" * 40
KEY_B = "b" * 40


async def _login(client: AsyncClient, session: AsyncSession) -> tuple[str, dict[str, object]]:
    name = f"sess-{uuid4().hex[:6]}"
    await create_user(
        session,
        username=name,
        email=f"{name}@cyberill.test",
        password=PASSWORD,
        role=UserRole.ANALYST,
    )
    response = await client.post(
        "/api/v1/auth/token", data={"username": name, "password": PASSWORD}
    )
    assert response.status_code == 200
    return name, response.json()


# --- Jetons de rafraîchissement ------------------------------------------------------------------


async def test_connexion_renvoie_un_jeton_de_rafraichissement(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, body = await _login(client, db_session)
    assert body["expires_in"] == 15 * 60
    assert body["refresh_expires_in"] == 7 * 86400
    stored = (await db_session.execute(select(RefreshToken))).scalars().all()
    assert len(stored) == 1
    assert stored[0].token_hash != body["refresh_token"]  # seule l'empreinte est stockée


async def test_rotation_puis_rejeu_revoque_la_lignee(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, body = await _login(client, db_session)
    first = body["refresh_token"]
    rotated = await client.post("/api/v1/auth/refresh", json={"refresh_token": first})
    assert rotated.status_code == 200
    second = rotated.json()["refresh_token"]
    assert second != first
    assert (
        await client.get("/api/v1/users/me", headers=_bearer(rotated.json()))
    ).status_code == 200

    replay = await client.post("/api/v1/auth/refresh", json={"refresh_token": first})
    assert replay.status_code == 401  # R1 déjà échangé : vol présumé
    # La lignée entière est révoquée : R2, pourtant jamais utilisé, ne sert plus.
    assert (
        await client.post("/api/v1/auth/refresh", json={"refresh_token": second})
    ).status_code == 401
    reasons = {t.revoked_reason for t in (await db_session.execute(select(RefreshToken))).scalars()}
    assert reasons == {"rotated", "reuse_detected"}
    denied = await db_session.execute(
        select(AuditEvent).where(
            AuditEvent.action == "auth.refresh", AuditEvent.outcome == AuditOutcome.DENIED
        )
    )
    assert denied.scalar_one().detail["reason"] == "reuse_detected"  # type: ignore[index]


async def test_deconnexion(client: AsyncClient, db_session: AsyncSession) -> None:
    _, body = await _login(client, db_session)
    token = body["refresh_token"]
    assert (
        await client.post("/api/v1/auth/logout", json={"refresh_token": token})
    ).status_code == 204
    assert (
        await client.post("/api/v1/auth/refresh", json={"refresh_token": token})
    ).status_code == 401
    # Jeton inconnu : 204 aussi, sans révéler s'il existait.
    unknown = await client.post("/api/v1/auth/logout", json={"refresh_token": "x" * 43})
    assert unknown.status_code == 204


async def test_jeton_expire_ou_compte_inactif(db_session: AsyncSession) -> None:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    user = await create_user(
        db_session,
        username=f"exp-{uuid4().hex[:6]}",
        email=f"{uuid4().hex[:6]}@x.test",
        password=PASSWORD,
    )
    issued, _ = await issue_refresh_token(db_session, user, settings=settings)
    later = datetime.now(UTC) + timedelta(days=8)
    with pytest.raises(InvalidRefreshTokenError, match="expiré"):
        await rotate_refresh_token(db_session, issued.token, settings=settings, now=later)

    issued, _ = await issue_refresh_token(db_session, user, settings=settings)
    user.is_active = False
    await db_session.flush()
    with pytest.raises(InvalidRefreshTokenError, match="inactif"):
        await rotate_refresh_token(db_session, issued.token, settings=settings)


def _bearer(body: dict[str, object]) -> dict[str, str]:
    return {"Authorization": f"Bearer {body['access_token']}"}


# --- Rotation de la clé de signature ----------------------------------------------------------


def test_rotation_de_cle() -> None:
    uid = uuid4()
    old = Settings(_env_file=None, secret_key=KEY_A)  # type: ignore[call-arg]
    token = create_access_token(uid, "ANALYST", settings=old)
    assert jwt.get_unverified_header(token)["kid"] == key_id(KEY_A)

    rotated = Settings(  # type: ignore[call-arg]
        _env_file=None, secret_key=KEY_B, secret_key_previous=SecretStr(KEY_A)
    )
    assert decode_access_token(token, settings=rotated).user_id == uid  # encore accepté
    assert jwt.get_unverified_header(create_access_token(uid, "X", settings=rotated))["kid"] == (
        key_id(KEY_B)
    )
    retired = Settings(_env_file=None, secret_key=KEY_B)  # type: ignore[call-arg]
    with pytest.raises(InvalidTokenError, match="inconnue"):
        decode_access_token(token, settings=retired)


def test_cle_precedente_vide_ignoree() -> None:
    """`SECRET_KEY_PREVIOUS=` vide (valeur de .env.example) vaut « non défini » : aucune
    autre clé que la courante n'est acceptée. (PyJWT refuse en outre toute clé HMAC vide.)"""
    settings = Settings(_env_file=None, secret_key=KEY_A, secret_key_previous="")  # type: ignore[call-arg, arg-type]
    assert settings.secret_key_previous is None
    now = datetime.now(UTC)
    forged = jwt.encode(
        {"sub": str(uuid4()), "type": "access", "iat": now, "exp": now + timedelta(minutes=5)},
        KEY_B,
        algorithm="HS256",
        headers={"kid": key_id(KEY_B)},
    )
    with pytest.raises(InvalidTokenError, match="inconnue"):
        decode_access_token(forged, settings=settings)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, secret_key_previous="court")  # type: ignore[call-arg, arg-type]


def test_jeton_anterieur_sans_kid_accepte_avec_la_cle_courante() -> None:
    settings = Settings(_env_file=None, secret_key=KEY_A)  # type: ignore[call-arg]
    legacy = jwt.encode(
        {
            "sub": str(uuid4()),
            "type": "access",
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(minutes=5),
            "role": "VIEWER",
        },
        KEY_A,
        algorithm="HS256",
    )
    assert decode_access_token(legacy, settings=settings).role == "VIEWER"


# --- Secrets de connexion -----------------------------------------------------------------------


def test_url_masquee() -> None:
    assert mask_url_password("postgresql+asyncpg://illwatch:s3cret@db:5432/illwatch") == (
        "postgresql+asyncpg://illwatch:••••••@db:5432/illwatch"
    )
    assert mask_url_password("redis://:pw@redis:6379/0") == "redis://:••••••@redis:6379/0"
    assert mask_url_password("redis://localhost:6379/0") == "redis://localhost:6379/0"


def test_production_exige_un_mot_de_passe_redis() -> None:
    base = {
        "environment": "production",
        "secret_key": KEY_A,
        "database_url": "postgresql+asyncpg://app:Zq7-long-random@db:5432/illwatch",
    }
    with pytest.raises(ValidationError, match="REDIS_URL"):
        Settings(_env_file=None, redis_url="redis://redis:6379/0", **base)  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="REDIS_URL"):
        Settings(_env_file=None, redis_url="redis://:illwatch-dev-redis@r:6379/0", **base)  # type: ignore[arg-type]
    Settings(_env_file=None, redis_url="redis://:Xk29-long-random@r:6379/0", **base)  # type: ignore[arg-type]


@pytest.mark.postgres
def test_cli_config_ne_montre_pas_les_mots_de_passe(monkeypatch: pytest.MonkeyPatch) -> None:
    from illwatch.app.config import get_settings
    from illwatch.cli.main import cli

    monkeypatch.setenv("REDIS_URL", "redis://:tres-secret-redis@localhost:6379/9")
    get_settings.cache_clear()
    try:
        output = CliRunner().invoke(cli, ["config"], terminal_width=200).output
    finally:
        get_settings.cache_clear()
    assert "tres-secret-redis" not in output
    password = os.environ["DATABASE_URL"].split("://", 1)[1].split("@")[0].partition(":")[2]
    assert not password or f":{password}@" not in output


# --- Rôle PostgreSQL applicatif -----------------------------------------------------------------

APP_ROLE = "illwatch_app_test"
APP_PASSWORD = "app:Pass-2026!"  # « : » volontaire : jamais interprété comme paramètre


async def _as_app(statement: str) -> object:
    url = os.environ["DATABASE_URL"]
    scheme, rest = url.split("://", 1)
    host_and_db = rest.split("@", 1)[1]
    engine = create_async_engine(
        f"{scheme}://{APP_ROLE}:app%3APass-2026%21@{host_and_db}", poolclass=NullPool
    )
    try:
        async with engine.begin() as conn:
            result = await conn.execute(text(statement))
            return result.first() if result.returns_rows else None
    finally:
        await engine.dispose()


async def _owner(statement: str) -> None:
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            await conn.execute(text(statement))
    finally:
        await engine.dispose()


@pytest.mark.postgres
def test_role_applicatif_sans_droit_de_structure() -> None:
    from sqlalchemy.exc import DBAPIError

    from illwatch.app.db_roles import AppRoleError, grant_app_role

    settings = Settings(_env_file=None, database_url=os.environ["DATABASE_URL"])  # type: ignore[call-arg]
    if _role_exists():  # reste d'une exécution interrompue
        asyncio.run(_owner(f"DROP OWNED BY {APP_ROLE}"))
        asyncio.run(_owner(f"DROP ROLE {APP_ROLE}"))
    try:
        report = asyncio.run(grant_app_role(settings, APP_ROLE, create_password=APP_PASSWORD))
        assert report.privileges["audit_events"] == ["INSERT", "SELECT"]
        assert report.privileges["incident_events"] == ["INSERT", "SELECT"]
        assert report.privileges["indicators"] == ["DELETE", "INSERT", "SELECT", "UPDATE"]
        # Idempotent : un second passage (après une migration) ne change rien.
        assert asyncio.run(grant_app_role(settings, APP_ROLE)).privileges == report.privileges

        assert asyncio.run(_as_app("SELECT count(*) FROM indicators")) is not None
        for statement, error in (
            ("UPDATE audit_events SET outcome = 'FAILURE'", "permission denied"),
            ("DELETE FROM incident_events", "permission denied"),
            ("TRUNCATE incident_events", "permission denied"),
            ("ALTER TABLE indicators ADD COLUMN x int", "must be owner"),
            ("DROP TABLE refresh_tokens", "must be owner"),
            ("CREATE TABLE pirate (x int)", "permission denied"),
        ):
            with pytest.raises(DBAPIError, match=error):
                asyncio.run(_as_app(statement))

        with pytest.raises(AppRoleError, match="superutilisateur"):
            asyncio.run(grant_app_role(settings, "illwatch"))
        with pytest.raises(AppRoleError, match="refusé"):
            asyncio.run(grant_app_role(settings, 'x"; DROP TABLE users; --'))
    finally:
        asyncio.run(_owner(f"DROP OWNED BY {APP_ROLE}"))
        asyncio.run(_owner(f"DROP ROLE IF EXISTS {APP_ROLE}"))


def _role_exists() -> bool:
    async def _check() -> bool:
        engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
        try:
            async with engine.connect() as conn:
                row = await conn.execute(
                    text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": APP_ROLE}
                )
                return row.first() is not None
        finally:
            await engine.dispose()

    return asyncio.run(_check())


# --- CLI : désactivation et révocation ----------------------------------------------------------


@pytest.mark.postgres
def test_cli_desactivation_revoque_les_sessions() -> None:
    from illwatch.cli.main import cli

    runner = CliRunner()
    name = f"cli-sess-{uuid4().hex[:6]}"
    created = runner.invoke(
        cli,
        [
            "users",
            "create",
            "--username",
            name,
            "--email",
            f"{name}@x.test",
            "--password",
            PASSWORD,
        ],
    )
    assert created.exit_code == 0, created.output
    disabled = runner.invoke(cli, ["users", "disable", name])
    assert disabled.exit_code == 0 and "désactivé" in disabled.output
    revoked = runner.invoke(cli, ["users", "revoke-sessions", name])
    assert revoked.exit_code == 0 and "0 session(s)" in revoked.output
    enabled = runner.invoke(cli, ["users", "enable", name])
    assert enabled.exit_code == 0 and "réactivé" in enabled.output
    assert runner.invoke(cli, ["users", "disable", "inconnu-xyz"]).exit_code == 1
    assert _audit_actions(name) >= {"user.disable", "user.enable", "user.revoke_sessions"}


# --- Réinitialisation de mot de passe (clone neuf du 06/10) ---------------------------------------


async def test_set_password_remplace_le_mot_de_passe(db_session: AsyncSession) -> None:
    from illwatch.app.security import WeakPasswordError
    from illwatch.modules.foundation.users import authenticate, set_password

    name = f"pwd-{uuid4().hex[:6]}"
    user = await create_user(db_session, username=name, email=f"{name}@x.test", password=PASSWORD)
    with pytest.raises(WeakPasswordError):
        await set_password(db_session, user, "court")
    await set_password(db_session, user, "un-autre-mot-de-passe-solide")
    assert await authenticate(db_session, name, "un-autre-mot-de-passe-solide") is not None
    assert await authenticate(db_session, name, PASSWORD) is None


@pytest.mark.postgres
def test_cli_reinitialisation_du_mot_de_passe() -> None:
    from illwatch.cli.main import cli

    runner = CliRunner()
    name = f"cli-pwd-{uuid4().hex[:6]}"
    args = ["users", "create", "--username", name, "--email", f"{name}@x.test"]
    created = runner.invoke(cli, [*args, "--password", PASSWORD])
    assert created.exit_code == 0, created.output

    weak = runner.invoke(cli, ["users", "set-password", name, "--password", "court"])
    assert weak.exit_code == 1 and "12 caractères" in weak.output
    reset = runner.invoke(
        cli, ["users", "set-password", name, "--password", "un-autre-mot-de-passe-solide"]
    )
    assert reset.exit_code == 0 and "réinitialisé" in reset.output, reset.output
    unknown = runner.invoke(cli, ["users", "set-password", "inconnu-xyz", "--password", PASSWORD])
    assert unknown.exit_code == 1
    assert "user.password_reset" in _audit_actions(name)


def _audit_actions(username: str) -> set[str]:
    async def _load() -> set[str]:
        engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
        try:
            async with engine.connect() as conn:
                rows = await conn.execute(
                    text("SELECT action FROM audit_events WHERE detail->>'username' = :u"),
                    {"u": username},
                )
                return {str(r[0]) for r in rows}
        finally:
            await engine.dispose()

    return asyncio.run(_load())


def test_mot_de_passe_encode_dans_l_url_de_migration(monkeypatch: pytest.MonkeyPatch) -> None:
    """Un « % » d'URL (mot de passe encodé) cassait Alembic : ConfigParser l'interpolait."""
    from illwatch.app import migrations
    from illwatch.app.config import get_settings

    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://app:p%3Aw%21@db:5432/illwatch_test")
    get_settings.cache_clear()
    try:
        assert migrations.head_revision()
        url = migrations.alembic_config().get_main_option("sqlalchemy.url")
        assert url == "postgresql+asyncpg://app:p%3Aw%21@db:5432/illwatch_test"
    finally:
        get_settings.cache_clear()


async def test_purge_des_sessions_perimees(db_session: AsyncSession) -> None:
    from illwatch.modules.foundation.sessions import purge_refresh_tokens, revoke_user_sessions

    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    user = await create_user(
        db_session,
        username=f"purge-{uuid4().hex[:6]}",
        email=f"{uuid4().hex[:6]}@x.test",
        password=PASSWORD,
    )
    old = datetime.now(UTC) - timedelta(days=60)
    await issue_refresh_token(db_session, user, settings=settings, now=old)  # expiré il y a 53 j
    await issue_refresh_token(db_session, user, settings=settings)  # actif : conservé
    revoked, _ = await issue_refresh_token(db_session, user, settings=settings)
    await revoke_user_sessions(db_session, user.id, now=datetime.now(UTC))  # révoqué récemment
    assert await purge_refresh_tokens(db_session) == 1
    remaining = (await db_session.execute(select(RefreshToken))).scalars().all()
    assert len(remaining) == 2 and revoked.token  # le récent reste, pour enquête
