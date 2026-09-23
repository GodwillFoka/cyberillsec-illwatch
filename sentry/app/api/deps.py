"""Dépendances FastAPI transverses : session base de données et utilisateur authentifié."""

from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app.config import get_settings
from sentry.app.database import get_db
from sentry.app.models import User
from sentry.app.security import InvalidTokenError, decode_access_token
from sentry.shared.enums import UserRole

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


def require_roles(*roles: UserRole) -> Callable[[User], Awaitable[User]]:
    """Fabrique une dépendance qui restreint une route à certains rôles."""
    allowed = {str(r) for r in roles}

    async def _checker(user: CurrentUser) -> User:
        if user.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Droits insuffisants."
            )
        return user

    return _checker
