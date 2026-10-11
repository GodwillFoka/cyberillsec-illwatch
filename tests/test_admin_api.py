"""Écran Administration : comptes (`/users`) et paramètres (`/settings`), ADMIN uniquement."""

from uuid import UUID, uuid4

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.config import Settings
from illwatch.app.models import AuditEvent, User
from illwatch.app.security import create_access_token
from illwatch.modules.foundation.sessions import issue_refresh_token
from illwatch.modules.foundation.users import create_user
from illwatch.shared.enums import UserRole

PASSWORD = "mot-de-passe-robuste-2026"


async def _account(session: AsyncSession, role: UserRole) -> tuple[dict[str, str], User]:
    name = f"{role.value.lower()}-{uuid4().hex[:8]}"
    user = await create_user(
        session, username=name, email=f"{name}@cyberill.test", password=PASSWORD, role=role
    )
    return {"Authorization": f"Bearer {create_access_token(user.id, user.role)}"}, user


async def _actions(session: AsyncSession) -> list[str]:
    return list((await session.scalars(select(AuditEvent.action))).all())


async def test_reserve_aux_administrateurs(client: AsyncClient, db_session: AsyncSession) -> None:
    analyst, _ = await _account(db_session, UserRole.ANALYST)
    for method, url in [("GET", "/api/v1/users"), ("GET", "/api/v1/settings")]:
        assert (await client.request(method, url, headers=analyst)).status_code == 403
    assert (await client.get("/api/v1/users")).status_code == 401


async def test_cycle_de_vie_d_un_compte(client: AsyncClient, db_session: AsyncSession) -> None:
    admin, _ = await _account(db_session, UserRole.ADMIN)

    weak = {"username": "nouvel", "email": "nouvel@cyberill.test", "password": "court"}
    assert (await client.post("/api/v1/users", json=weak, headers=admin)).status_code == 422
    body = {**weak, "password": PASSWORD, "role": "ANALYST"}
    created = await client.post("/api/v1/users", json=body, headers=admin)
    assert created.status_code == 201, created.text
    account = created.json()
    assert account["role"] == "ANALYST" and account["is_active"] and "password" not in account
    assert (await client.post("/api/v1/users", json=body, headers=admin)).status_code == 409

    user_id = UUID(account["id"])
    target = await db_session.get(User, user_id)
    assert target is not None
    await issue_refresh_token(db_session, target, settings=Settings(secret_key="k" * 64))
    listed = (await client.get("/api/v1/users", headers=admin)).json()
    assert next(a for a in listed if a["id"] == account["id"])["active_sessions"] == 1

    promoted = await client.patch(
        f"/api/v1/users/{user_id}", json={"role": "VIEWER"}, headers=admin
    )
    assert promoted.status_code == 200 and promoted.json()["role"] == "VIEWER"
    assert promoted.json()["active_sessions"] == 0  # changement de rôle : sessions révoquées

    disabled = await client.patch(
        f"/api/v1/users/{user_id}", json={"is_active": False}, headers=admin
    )
    assert disabled.status_code == 200 and disabled.json()["is_active"] is False

    reset = await client.post(
        f"/api/v1/users/{user_id}/password", json={"password": PASSWORD + "!"}, headers=admin
    )
    assert reset.status_code == 200
    revoke = await client.post(f"/api/v1/users/{user_id}/revoke-sessions", headers=admin)
    assert revoke.status_code == 200 and revoke.json() == {"revoked": 0}

    assert (
        await client.patch(f"/api/v1/users/{uuid4()}", json={"role": "VIEWER"}, headers=admin)
    ).status_code == 404
    assert (
        await client.patch(f"/api/v1/users/{user_id}", json={}, headers=admin)
    ).status_code == 422

    actions = await _actions(db_session)
    for expected in ("user.create", "user.role", "user.disable", "user.password_reset"):
        assert expected in actions, expected


async def test_jamais_sans_administrateur(client: AsyncClient, db_session: AsyncSession) -> None:
    admin, me = await _account(db_session, UserRole.ADMIN)
    # Soi-même : ni désactivation, ni perte du rôle.
    for change in ({"is_active": False}, {"role": "ANALYST"}):
        refused = await client.patch(f"/api/v1/users/{me.id}", json=change, headers=admin)
        assert refused.status_code == 409, change
    # Un autre administrateur peut être rétrogradé tant qu'il en reste un actif.
    _, other = await _account(db_session, UserRole.ADMIN)
    ok = await client.patch(f"/api/v1/users/{other.id}", json={"role": "ANALYST"}, headers=admin)
    assert ok.status_code == 200


async def test_parametres_sans_secret(client: AsyncClient, db_session: AsyncSession) -> None:
    admin, _ = await _account(db_session, UserRole.ADMIN)
    body = (await client.get("/api/v1/settings", headers=admin)).json()
    assert body["remediation_sla_hours"]["P0_CRITIQUE"] == 24
    assert set(body["secrets_configured"]) >= {"nvd_api_key", "otx_api_key"}
    assert all(isinstance(v, bool) for v in body["secrets_configured"].values())
    text = str(body).lower()
    assert 'secret_key"' not in text and "password" not in text
