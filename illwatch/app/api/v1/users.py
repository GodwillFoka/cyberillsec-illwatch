"""Administration des comptes — `/api/v1/users` (ADMIN), écran Administration (ADR-016).

Mêmes opérations que `illwatch users …`, avec les mêmes effets : création sous politique de
mot de passe, désactivation et réinitialisation qui révoquent les sessions, tout consigné au
journal d'audit. Garde-fou : ILLWATCH garde toujours au moins un administrateur actif, et un
administrateur ne peut ni se désactiver ni se retirer son propre rôle (pas de verrouillage
accidentel de l'instance).
"""

from datetime import UTC, datetime
from typing import Annotated, Self
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import func, select

from illwatch.app.api.deps import Audit, DbSession, require_roles
from illwatch.app.models import RefreshToken, User
from illwatch.app.security import MIN_PASSWORD_LENGTH, WeakPasswordError
from illwatch.modules.foundation.sessions import revoke_user_sessions
from illwatch.modules.foundation.users import UserAlreadyExistsError, create_user, set_password
from illwatch.shared.enums import UserRole

router = APIRouter(prefix="/users", tags=["administration"])

AdminUser = Annotated[User, Depends(require_roles(UserRole.ADMIN))]


class AccountRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    username: str
    email: str
    role: UserRole
    is_active: bool
    created_at: datetime
    active_sessions: int = Field(description="Sessions ouvertes (jetons de rafraîchissement).")


class AccountCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9._-]+$")
    email: str = Field(max_length=255, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    role: UserRole = UserRole.ANALYST
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=256)


class AccountUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: UserRole | None = None
    is_active: bool | None = None

    @model_validator(mode="after")
    def _something(self) -> Self:
        if self.role is None and self.is_active is None:
            raise ValueError("Aucun champ à modifier (role, is_active).")
        return self


class PasswordReset(BaseModel):
    model_config = ConfigDict(extra="forbid")

    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=256)


class SessionsRevoked(BaseModel):
    revoked: int


async def _session_counts(session: DbSession) -> dict[UUID, int]:
    rows = await session.execute(
        select(RefreshToken.user_id, func.count())
        .where(RefreshToken.revoked_at.is_(None), RefreshToken.expires_at > datetime.now(UTC))
        .group_by(RefreshToken.user_id)
    )
    return dict(rows.tuples().all())


def _read(user: User, counts: dict[UUID, int]) -> AccountRead:
    return AccountRead.model_validate(
        {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "is_active": user.is_active,
            "created_at": user.created_at,
            "active_sessions": counts.get(user.id, 0),
        }
    )


async def _target(session: DbSession, user_id: UUID) -> User:
    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"Compte {user_id} introuvable.")
    return user


async def _other_active_admins(session: DbSession, user_id: UUID) -> int:
    return int(
        await session.scalar(
            select(func.count())
            .select_from(User)
            .where(User.role == UserRole.ADMIN, User.is_active.is_(True), User.id != user_id)
        )
        or 0
    )


@router.get("", response_model=list[AccountRead], summary="Comptes (ADMIN)")
async def list_accounts(session: DbSession, _: AdminUser) -> list[AccountRead]:
    users = (await session.scalars(select(User).order_by(User.username))).all()
    counts = await _session_counts(session)
    return [_read(u, counts) for u in users]


@router.post(
    "",
    response_model=AccountRead,
    status_code=status.HTTP_201_CREATED,
    summary="Créer un compte (ADMIN)",
)
async def create_account(
    payload: AccountCreate, session: DbSession, admin: AdminUser, audit: Audit
) -> AccountRead:
    try:
        user = await create_user(
            session,
            username=payload.username,
            email=payload.email,
            password=payload.password,
            role=payload.role,
        )
    except UserAlreadyExistsError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from None
    except WeakPasswordError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from None
    await audit.record(
        "user.create",
        actor=admin,
        target_type="user",
        target_id=user.id,
        detail={"username": user.username, "role": str(user.role)},
    )
    return _read(user, {})


@router.patch("/{user_id}", response_model=AccountRead, summary="Rôle ou activation (ADMIN)")
async def update_account(
    user_id: UUID, payload: AccountUpdate, session: DbSession, admin: AdminUser, audit: Audit
) -> AccountRead:
    user = await _target(session, user_id)
    losing_admin = user.role == UserRole.ADMIN and (
        (payload.role is not None and payload.role != UserRole.ADMIN) or payload.is_active is False
    )
    if losing_admin and user.id == admin.id:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="Un administrateur ne peut ni se désactiver ni se retirer son rôle.",
        )
    if losing_admin and await _other_active_admins(session, user.id) == 0:
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail="Dernier administrateur actif : opération refusée."
        )
    changes: dict[str, object] = {}
    if payload.role is not None and payload.role != user.role:
        changes["role"] = {"from": str(user.role), "to": str(payload.role)}
        user.role = payload.role
    revoked = 0
    if payload.is_active is not None and payload.is_active != user.is_active:
        changes["is_active"] = payload.is_active
        user.is_active = payload.is_active
    # Désactivation ou changement de rôle : les sessions ouvertes portent l'ancien rôle.
    if changes and (user.is_active is False or "role" in changes):
        revoked = await revoke_user_sessions(
            session, user.id, "account_disabled" if user.is_active is False else "role_changed"
        )
    await session.flush()
    if changes:
        action = (
            "user.disable"
            if changes.get("is_active") is False
            else "user.enable"
            if changes.get("is_active") is True
            else "user.role"
        )
        await audit.record(
            action,
            actor=admin,
            target_type="user",
            target_id=user.id,
            detail={"username": user.username, **changes, "sessions_revoked": revoked},
        )
    return _read(user, await _session_counts(session))


@router.post(
    "/{user_id}/password",
    response_model=SessionsRevoked,
    summary="Réinitialiser le mot de passe (ADMIN) — révoque les sessions",
)
async def reset_password(
    user_id: UUID, payload: PasswordReset, session: DbSession, admin: AdminUser, audit: Audit
) -> SessionsRevoked:
    user = await _target(session, user_id)
    try:
        await set_password(session, user, payload.password)
    except WeakPasswordError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from None
    revoked = await revoke_user_sessions(session, user.id, "password_reset")
    await audit.record(
        "user.password_reset",
        actor=admin,
        target_type="user",
        target_id=user.id,
        detail={"username": user.username, "sessions_revoked": revoked},
    )
    return SessionsRevoked(revoked=revoked)


@router.post(
    "/{user_id}/revoke-sessions",
    response_model=SessionsRevoked,
    summary="Révoquer toutes les sessions d'un compte (ADMIN)",
)
async def revoke_sessions(
    user_id: UUID, session: DbSession, admin: AdminUser, audit: Audit
) -> SessionsRevoked:
    user = await _target(session, user_id)
    revoked = await revoke_user_sessions(session, user.id, "admin")
    await audit.record(
        "user.revoke_sessions",
        actor=admin,
        target_type="user",
        target_id=user.id,
        detail={"username": user.username, "sessions_revoked": revoked},
    )
    return SessionsRevoked(revoked=revoked)
