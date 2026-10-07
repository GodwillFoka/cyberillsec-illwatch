"""Routes d'authentification — `/api/v1/auth` et `/api/v1/users/me` (MOD-01, M7 lot 2).

- `POST /auth/token` : identifiant + mot de passe → jeton d'accès (15 min) + jeton de
  rafraîchissement opaque (7 j), révocable ;
- `POST /auth/refresh` : rotation du jeton de rafraîchissement (un jeton remplacé et rejoué
  révoque toute sa lignée) ;
- `POST /auth/logout` : révocation de la lignée.
"""

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, ConfigDict, Field

from illwatch.app.api.deps import CurrentUser, DbSession
from illwatch.app.config import get_settings
from illwatch.app.security import create_access_token
from illwatch.app.throttle import LoginThrottle, get_login_throttle
from illwatch.modules.foundation.audit import AuditContext, AuditRecorder, get_audit_recorder
from illwatch.modules.foundation.sessions import (
    InvalidRefreshTokenError,
    RefreshTokenReuseError,
    issue_refresh_token,
    logout,
    rotate_refresh_token,
)
from illwatch.modules.foundation.users import authenticate, get_user_by_username
from illwatch.shared.enums import AuditOutcome

router = APIRouter(tags=["authentification"])


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 - type OAuth2, pas un secret
    expires_in: int
    refresh_token: str
    refresh_expires_in: int


class RefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    refresh_token: str = Field(min_length=20, max_length=200)


_REFRESH_ERROR = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Jeton de rafraîchissement invalide : reconnectez-vous.",
    headers={"WWW-Authenticate": "Bearer"},
)


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
    audit: Annotated[AuditRecorder, Depends(get_audit_recorder)],
) -> TokenResponse:
    """Échange identifiant + mot de passe contre un jeton Bearer (flux OAuth2 password).

    Pendant `LOGIN_WINDOW_SECONDS`, les tentatives sont refusées en 429 — avant même la
    vérification du mot de passe — après `LOGIN_MAX_FAILURES` échecs d'une adresse sur un
    compte, 10 fois plus sur un compte toutes adresses confondues, ou 4 fois plus d'une adresse
    tous comptes confondus (`illwatch.app.throttle`).

    Chaque tentative est consignée au journal d'audit (`auth.login`). L'identifiant saisi n'y
    figure que s'il correspond à un compte existant : un mot de passe tapé par erreur dans le
    champ identifiant ne doit pas finir en clair dans le journal.
    """
    ip = request.client.host if request.client else "inconnue"
    context = AuditContext.from_request(request)
    known = await get_user_by_username(session, form.username.strip())
    name = known.username if known is not None else "(inconnu)"
    target_id = known.id if known is not None else None
    if await throttle.blocked(form.username, ip):
        await audit.record(
            "auth.login",
            AuditOutcome.DENIED,
            actor_name=name,
            context=context,
            detail={"reason": "throttled"},
            target_type="user",
            target_id=target_id,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Trop de tentatives de connexion : réessayez plus tard.",
            headers={"Retry-After": str(throttle.window)},
        )
    user = await authenticate(session, form.username, form.password)
    if user is None or not user.is_active:
        await throttle.failure(form.username, ip)
        await audit.record(
            "auth.login",
            AuditOutcome.FAILURE,
            actor_name=name,
            context=context,
            detail={"reason": "inactive" if user is not None else "invalid_credentials"},
            target_type="user",
            target_id=target_id,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identifiants invalides.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    await throttle.success(form.username, ip)
    await audit.record("auth.login", actor=user, context=context)
    settings = get_settings()
    refresh, _ = await issue_refresh_token(
        session,
        user,
        settings=settings,
        ip=ip,
        user_agent=request.headers.get("user-agent"),
    )
    return TokenResponse(
        access_token=create_access_token(user.id, user.role),
        expires_in=settings.access_token_expire_minutes * 60,
        refresh_token=refresh.token,
        refresh_expires_in=refresh.expires_in,
    )


@router.post("/auth/refresh", response_model=TokenResponse, summary="Renouveler le jeton d'accès")
async def refresh(
    payload: RefreshRequest,
    session: DbSession,
    request: Request,
    audit: Annotated[AuditRecorder, Depends(get_audit_recorder)],
) -> TokenResponse:
    """Échange un jeton de rafraîchissement contre une nouvelle paire (rotation).

    Un jeton déjà échangé et présenté à nouveau signe un vol : toute la lignée issue de la
    connexion d'origine est révoquée, l'utilisateur légitime devra se reconnecter, et
    l'évènement est consigné (`auth.refresh` DENIED, `reuse_detected`).
    """
    context = AuditContext.from_request(request)
    settings = get_settings()
    try:
        user, issued = await rotate_refresh_token(
            session,
            payload.refresh_token,
            settings=settings,
            ip=context.ip,
            user_agent=request.headers.get("user-agent"),
        )
    except RefreshTokenReuseError as exc:
        await session.commit()  # la révocation de la famille doit survivre au 401
        await audit.record(
            "auth.refresh",
            AuditOutcome.DENIED,
            actor_id=exc.user_id,
            context=context,
            detail={"reason": "reuse_detected", "family_id": str(exc.family_id)},
        )
        raise _REFRESH_ERROR from None
    except InvalidRefreshTokenError as exc:
        await session.commit()
        await audit.record(
            "auth.refresh",
            AuditOutcome.FAILURE,
            actor_name="(inconnu)",
            context=context,
            detail={"reason": str(exc)},
        )
        raise _REFRESH_ERROR from None
    await audit.record(
        "auth.refresh", actor=user, context=context, detail={"family_id": str(issued.family_id)}
    )
    return TokenResponse(
        access_token=create_access_token(user.id, user.role),
        expires_in=settings.access_token_expire_minutes * 60,
        refresh_token=issued.token,
        refresh_expires_in=issued.expires_in,
    )


@router.post(
    "/auth/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Révoquer la session (jeton de rafraîchissement)",
)
async def sign_out(
    payload: RefreshRequest,
    session: DbSession,
    request: Request,
    audit: Annotated[AuditRecorder, Depends(get_audit_recorder)],
) -> Response:
    """Révoque la lignée du jeton présenté. Toujours 204 : ne révèle pas si le jeton existait.

    Le jeton d'accès en cours reste valide jusqu'à son expiration (15 min au plus) ; pour une
    coupure immédiate, un administrateur désactive le compte (`illwatch users disable`).
    """
    user_id = await logout(session, payload.refresh_token)
    if user_id is not None:
        await audit.record(
            "auth.logout", actor_id=user_id, context=AuditContext.from_request(request)
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/users/me", response_model=UserRead, summary="Profil de l'utilisateur connecté")
async def read_me(user: CurrentUser) -> UserRead:
    return UserRead.model_validate(user)
