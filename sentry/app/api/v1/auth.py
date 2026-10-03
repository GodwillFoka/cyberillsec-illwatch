"""Routes d'authentification — `/api/v1/auth` et `/api/v1/users/me` (MOD-01)."""

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, ConfigDict

from sentry.app.api.deps import CurrentUser, DbSession
from sentry.app.config import get_settings
from sentry.app.security import create_access_token
from sentry.app.throttle import LoginThrottle, get_login_throttle
from sentry.modules.foundation.users import authenticate

router = APIRouter(tags=["authentification"])


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 - type OAuth2, pas un secret
    expires_in: int


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime


@router.post("/auth/token", response_model=TokenResponse, summary="Obtenir un jeton d'accès")
async def login(
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: DbSession,
    request: Request,
    throttle: Annotated[LoginThrottle, Depends(get_login_throttle)],
) -> TokenResponse:
    """Échange identifiant + mot de passe contre un jeton Bearer (flux OAuth2 password).

    Après `LOGIN_MAX_FAILURES` échecs sur un identifiant (ou 4 fois plus depuis une même
    adresse) pendant `LOGIN_WINDOW_SECONDS`, les tentatives sont refusées en 429, avant même
    la vérification du mot de passe : l'attaquant n'obtient plus aucune information.
    """
    ip = request.client.host if request.client else "inconnue"
    if await throttle.blocked(form.username, ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Trop de tentatives de connexion : réessayez plus tard.",
            headers={"Retry-After": str(throttle.window)},
        )
    user = await authenticate(session, form.username, form.password)
    if user is None or not user.is_active:
        await throttle.failure(form.username, ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identifiants invalides.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    await throttle.success(form.username)
    settings = get_settings()
    return TokenResponse(
        access_token=create_access_token(user.id, user.role),
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.get("/users/me", response_model=UserRead, summary="Profil de l'utilisateur connecté")
async def read_me(user: CurrentUser) -> UserRead:
    return UserRead.model_validate(user)
