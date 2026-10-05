"""Dépendances FastAPI transverses : session base de données et utilisateur authentifié."""

from collections.abc import Awaitable, Callable
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app.config import get_settings
from sentry.app.database import get_db
from sentry.app.models import User
from sentry.app.security import InvalidTokenError, decode_access_token
from sentry.modules.foundation.audit import AuditContext, AuditRecorder, get_audit_recorder
from sentry.shared.enums import AuditOutcome, UserRole

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{get_settings().api_v1_prefix}/auth/token")

DbSession = Annotated[AsyncSession, Depends(get_db)]

_CREDENTIALS_ERROR = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Authentification requise ou jeton invalide.",
    headers={"WWW-Authenticate": "Bearer"},
)


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    session: DbSession,
) -> User:
    """Résout l'utilisateur porteur du jeton. Le rôle est relu en base, jamais cru sur parole."""
    try:
        payload = decode_access_token(token)
    except InvalidTokenError:
        raise _CREDENTIALS_ERROR from None

    user = await session.get(User, payload.user_id)
    if user is None or not user.is_active:
        raise _CREDENTIALS_ERROR
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


class BoundAudit:
    """Enregistreur d'audit lié à la requête courante (adresse IP, identifiant de requête)."""

    def __init__(self, recorder: AuditRecorder, context: AuditContext) -> None:
        self.recorder = recorder
        self.context = context

    async def record(
        self, action: str, outcome: AuditOutcome = AuditOutcome.SUCCESS, **kwargs: Any
    ) -> None:
        await self.recorder.record(action, outcome, context=self.context, **kwargs)


def get_bound_audit(
    request: Request, recorder: Annotated[AuditRecorder, Depends(get_audit_recorder)]
) -> BoundAudit:
    return BoundAudit(recorder, AuditContext.from_request(request))


Audit = Annotated[BoundAudit, Depends(get_bound_audit)]


def require_roles(*roles: UserRole) -> Callable[..., Awaitable[User]]:
    """Fabrique une dépendance qui restreint une route à certains rôles.

    Un refus est consigné au journal d'audit (`authz.denied`) : des 403 répétés signalent un
    compte qui sonde ses limites, ou un jeton volé utilisé hors de son périmètre.
    """
    allowed = {str(r) for r in roles}

    async def _checker(user: CurrentUser, request: Request, audit: Audit) -> User:
        if user.role not in allowed:
            await audit.record(
                "authz.denied",
                AuditOutcome.DENIED,
                actor=user,
                detail={"method": request.method, "path": request.url.path, "role": user.role},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Droits insuffisants."
            )
        return user

    return _checker
