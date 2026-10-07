"""Service de gestion des comptes utilisateurs — logique métier pure, sans HTTP ni CLI."""

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import User
from illwatch.app.security import hash_password, validate_password_policy, verify_password
from illwatch.shared.enums import UserRole


class UserAlreadyExistsError(ValueError):
    """Nom d'utilisateur ou e-mail déjà enregistré."""


async def get_user_by_username(session: AsyncSession, username: str) -> User | None:
    result = await session.execute(
        select(User).where(func.lower(User.username) == username.strip().lower())
    )
    return result.scalar_one_or_none()


async def create_user(
    session: AsyncSession,
    *,
    username: str,
    email: str,
    password: str,
    role: UserRole = UserRole.ANALYST,
) -> User:
    """Crée un compte après validation de la politique de mot de passe et de l'unicité.

    Raises:
        WeakPasswordError: mot de passe trop court.
        UserAlreadyExistsError: identifiant ou e-mail déjà pris.
    """
    validate_password_policy(password)
    normalized_username = username.strip().lower()
    normalized_email = email.strip().lower()

    existing = await session.execute(
        select(User.id).where(
            or_(
                func.lower(User.username) == normalized_username,
                func.lower(User.email) == normalized_email,
            )
        )
    )
    if existing.first() is not None:
        raise UserAlreadyExistsError("Nom d'utilisateur ou e-mail déjà utilisé.")

    user = User(
        username=normalized_username,
        email=normalized_email,
        hashed_password=hash_password(password),
        role=role,
    )
    session.add(user)
    await session.flush()
    return user


async def set_password(session: AsyncSession, user: User, password: str) -> None:
    """Remplace le mot de passe d'un compte, après validation de la politique.

    Raises:
        WeakPasswordError: mot de passe trop court.
    """
    validate_password_policy(password)
    user.hashed_password = hash_password(password)
    await session.flush()


async def authenticate(session: AsyncSession, username: str, password: str) -> User | None:
    """Retourne l'utilisateur si les identifiants sont valides, sinon `None`.

    Le temps de réponse est homogène que le compte existe ou non (voir `verify_password`).
    """
    user = await get_user_by_username(session, username)
    if not verify_password(password, user.hashed_password if user else None):
        return None
    return user
