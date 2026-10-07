"""Tests d'intégration de l'authentification : /auth/token, /users/me, contrôle des rôles."""

from collections.abc import AsyncGenerator

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.api.deps import require_roles
from illwatch.app.database import get_db
from illwatch.app.models import User
from illwatch.app.security import WeakPasswordError, create_access_token
from illwatch.modules.foundation.users import UserAlreadyExistsError, authenticate, create_user
from illwatch.shared.enums import UserRole

PASSWORD = "mot-de-passe-robuste-2026"
TOKEN_URL = "/api/v1/auth/token"


async def _user(session: AsyncSession, **kw: object) -> User:
    params: dict[str, object] = {
        "username": "analyste",
        "email": "analyste@cyberill.test",
        "password": PASSWORD,
    }
    params.update(kw)
    return await create_user(session, **params)  # type: ignore[arg-type]


async def _login(client: AsyncClient, username: str, password: str) -> str:
    response = await client.post(TOKEN_URL, data={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return str(response.json()["access_token"])


# --- Service ------------------------------------------------------------------


async def test_creation_normalise_et_hache(db_session: AsyncSession) -> None:
    user = await _user(db_session, username="  Analyste ", email="ANALYSTE@Cyberill.test")
    assert user.username == "analyste"
    assert user.email == "analyste@cyberill.test"
    assert user.hashed_password != PASSWORD


async def test_doublon_refuse_sans_tenir_compte_de_la_casse(db_session: AsyncSession) -> None:
    await _user(db_session)
    with pytest.raises(UserAlreadyExistsError):
        await _user(db_session, username="ANALYSTE", email="autre@cyberill.test")


async def test_mot_de_passe_faible_refuse(db_session: AsyncSession) -> None:
    with pytest.raises(WeakPasswordError):
        await _user(db_session, password="court")


async def test_authenticate(db_session: AsyncSession) -> None:
    await _user(db_session)
    assert await authenticate(db_session, "ANALYSTE", PASSWORD) is not None
    assert await authenticate(db_session, "analyste", "mauvais") is None
    assert await authenticate(db_session, "inconnu", PASSWORD) is None


# --- API ----------------------------------------------------------------------


async def test_connexion_puis_profil(client: AsyncClient, db_session: AsyncSession) -> None:
    await _user(db_session)
    response = await client.post(TOKEN_URL, data={"username": "analyste", "password": PASSWORD})
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] > 0

    me = await client.get(
        "/api/v1/users/me", headers={"Authorization": f"Bearer {body['access_token']}"}
    )
    assert me.status_code == 200
    profile = me.json()
    assert profile["username"] == "analyste"
    assert profile["role"] == "ANALYST"
    assert "hashed_password" not in profile


@pytest.mark.parametrize(
    ("username", "password"), [("analyste", "mauvais-mot-de-passe"), ("inconnu", PASSWORD)]
)
async def test_identifiants_invalides_meme_reponse(
    client: AsyncClient, db_session: AsyncSession, username: str, password: str
) -> None:
    """Même code et même message : on ne révèle pas quels identifiants existent."""
    await _user(db_session)
    response = await client.post(TOKEN_URL, data={"username": username, "password": password})
    assert response.status_code == 401
    assert response.json()["detail"] == "Identifiants invalides."


async def test_compte_desactive_ne_peut_pas_se_connecter(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user = await _user(db_session)
    user.is_active = False
    await db_session.flush()
    response = await client.post(TOKEN_URL, data={"username": "analyste", "password": PASSWORD})
    assert response.status_code == 401


async def test_jeton_d_un_compte_desactive_refuse(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user = await _user(db_session)
    token = await _login(client, "analyste", PASSWORD)
    user.is_active = False
    await db_session.flush()
    me = await client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 401


async def test_profil_sans_jeton_refuse(client: AsyncClient) -> None:
    response = await client.get("/api/v1/users/me")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


async def test_profil_avec_jeton_invalide_refuse(client: AsyncClient) -> None:
    response = await client.get(
        "/api/v1/users/me", headers={"Authorization": "Bearer pas.un.jeton"}
    )
    assert response.status_code == 401


# --- Contrôle des rôles -------------------------------------------------------


async def test_require_roles(db_session: AsyncSession) -> None:
    app = FastAPI()

    @app.get("/admin-only")
    async def admin_only(user: User = Depends(require_roles(UserRole.ADMIN))) -> dict[str, str]:
        return {"ok": user.username}

    async def _override() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    app.dependency_overrides[get_db] = _override

    analyst = await _user(db_session)
    admin = await _user(
        db_session, username="chef", email="chef@cyberill.test", role=UserRole.ADMIN
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        denied = await c.get(
            "/admin-only",
            headers={"Authorization": f"Bearer {create_access_token(analyst.id, analyst.role)}"},
        )
        allowed = await c.get(
            "/admin-only",
            headers={"Authorization": f"Bearer {create_access_token(admin.id, admin.role)}"},
        )

    assert denied.status_code == 403
    assert allowed.status_code == 200
    assert allowed.json() == {"ok": "chef"}
