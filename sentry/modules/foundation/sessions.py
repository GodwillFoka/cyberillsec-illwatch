"""Sessions utilisateur : jetons de rafraîchissement rotatifs et révocables (M7 lot 2, ADR-012).

    connexion ──▶ jeton d'accès (15 min) + jeton de rafraîchissement R1 (famille F)
    R1 ──refresh──▶ accès + R2   (R1 révoqué « rotated », remplacé par R2)
    R1 rejoué ────▶ refus + révocation de toute la famille F (« reuse_detected »)
    logout(R2) ───▶ famille F révoquée (« logout »)
    admin ────────▶ toutes les familles d'un compte révoquées (« admin »), compte désactivable

Un compte désactivé perd l'accès **immédiatement** : son rôle et son statut sont relus en base
à chaque requête (`get_current_user`), et ses jetons de rafraîchissement sont révoqués.
"""

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import delete, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app.config import Settings
from sentry.app.models import RefreshToken, User

TOKEN_BYTES = 32


class InvalidRefreshTokenError(Exception):
    """Jeton inconnu, expiré, révoqué ou rattaché à un compte inactif."""


class RefreshTokenReuseError(InvalidRefreshTokenError):
    """Jeton déjà remplacé présenté à nouveau : la famille entière vient d'être révoquée."""

    def __init__(self, user_id: UUID, family_id: UUID) -> None:
        super().__init__("Jeton de rafraîchissement réutilisé.")
        self.user_id = user_id
        self.family_id = family_id


@dataclass(frozen=True, slots=True)
class IssuedRefresh:
    token: str  # valeur en clair, renvoyée une seule fois au client
    expires_in: int
    family_id: UUID


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


async def issue_refresh_token(
    session: AsyncSession,
    user: User,
    *,
    settings: Settings,
    family_id: UUID | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    now: datetime | None = None,
) -> tuple[IssuedRefresh, RefreshToken]:
    moment = now or datetime.now(UTC)
    token = secrets.token_urlsafe(TOKEN_BYTES)
    lifetime = timedelta(days=settings.refresh_token_expire_days)
    row = RefreshToken(
        id=uuid4(),
        user_id=user.id,
        family_id=family_id or uuid4(),
        token_hash=_hash(token),
        issued_at=moment,
        expires_at=moment + lifetime,
        ip=ip[:45] if ip else None,
        user_agent=user_agent[:255] if user_agent else None,
    )
    session.add(row)
    await session.flush()
    return IssuedRefresh(token, int(lifetime.total_seconds()), row.family_id), row


async def revoke_family(
    session: AsyncSession, family_id: UUID, reason: str, *, now: datetime | None = None
) -> int:
    result = await session.execute(
        update(RefreshToken)
        .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=now or datetime.now(UTC), revoked_reason=reason)
    )
    return int(getattr(result, "rowcount", 0) or 0)


async def revoke_user_sessions(
    session: AsyncSession, user_id: UUID, reason: str = "admin", *, now: datetime | None = None
) -> int:
    """Révoque tous les jetons de rafraîchissement actifs d'un compte."""
    result = await session.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=now or datetime.now(UTC), revoked_reason=reason)
    )
    return int(getattr(result, "rowcount", 0) or 0)


async def rotate_refresh_token(
    session: AsyncSession,
    token: str,
    *,
    settings: Settings,
    ip: str | None = None,
    user_agent: str | None = None,
    now: datetime | None = None,
) -> tuple[User, IssuedRefresh]:
    """Échange un jeton valide contre un nouveau, dans la même famille.

    Raises:
        RefreshTokenReuseError: jeton déjà remplacé (famille révoquée, à valider en base).
        InvalidRefreshTokenError: jeton inconnu, expiré, révoqué ou compte inactif.
    """
    moment = now or datetime.now(UTC)
    row = (
        await session.execute(
            select(RefreshToken)
            .where(RefreshToken.token_hash == _hash(token))
            .with_for_update()  # deux rafraîchissements simultanés : le second voit la révocation
        )
    ).scalar_one_or_none()
    if row is None:
        raise InvalidRefreshTokenError("Jeton de rafraîchissement inconnu.")
    if row.revoked_at is not None:
        if row.revoked_reason == "rotated":
            await revoke_family(session, row.family_id, "reuse_detected", now=moment)
            raise RefreshTokenReuseError(row.user_id, row.family_id)
        raise InvalidRefreshTokenError("Jeton de rafraîchissement révoqué.")
    if _utc(row.expires_at) <= moment:
        raise InvalidRefreshTokenError("Jeton de rafraîchissement expiré.")
    user = await session.get(User, row.user_id)
    if user is None or not user.is_active:
        await revoke_family(session, row.family_id, "inactive_user", now=moment)
        raise InvalidRefreshTokenError("Compte inactif.")
    issued, new_row = await issue_refresh_token(
        session,
        user,
        settings=settings,
        family_id=row.family_id,
        ip=ip,
        user_agent=user_agent,
        now=moment,
    )
    row.revoked_at = moment
    row.revoked_reason = "rotated"
    row.replaced_by = new_row.id
    await session.flush()
    return user, issued


async def logout(session: AsyncSession, token: str, *, now: datetime | None = None) -> UUID | None:
    """Révoque la famille du jeton présenté. Renvoie l'identifiant du compte, ou `None`."""
    row = (
        await session.execute(select(RefreshToken).where(RefreshToken.token_hash == _hash(token)))
    ).scalar_one_or_none()
    if row is None:
        return None
    await revoke_family(session, row.family_id, "logout", now=now)
    return row.user_id


async def purge_refresh_tokens(
    session: AsyncSession, *, now: datetime | None = None, retention_days: int = 30
) -> int:
    """Supprime les jetons expirés ou révoqués depuis plus de `retention_days` jours.

    La rétention garde de quoi enquêter sur un rejeu récent (familles, adresses IP) ; au-delà,
    le journal d'audit (`auth.refresh`, `auth.logout`) reste la trace durable.
    """
    limit = (now or datetime.now(UTC)) - timedelta(days=retention_days)
    result = await session.execute(
        delete(RefreshToken).where(
            or_(RefreshToken.expires_at < limit, RefreshToken.revoked_at < limit)
        )
    )
    return int(getattr(result, "rowcount", 0) or 0)
