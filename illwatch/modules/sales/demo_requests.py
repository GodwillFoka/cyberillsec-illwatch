"""Demandes de démonstration : enregistrement, consultation, suivi, purge (ADR-027, lot S4).

Le formulaire est public : les entrées sont bornées et validées, le débit est limité par
adresse IP (compteur Redis, adresse jamais enregistrée en base) et globalement par jour, et un
champ piège invisible écarte les robots les plus simples sans rien enregistrer.
"""

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import DemoRequest
from illwatch.shared.enums import DemoInterest, DemoRequestStatus

PER_IP_LIMIT = 5  # demandes par adresse et par heure
PER_IP_WINDOW = 3600
DAILY_LIMIT = 200  # au-delà, la table ne grossit plus (inondation)
RETENTION_DAYS = 365


class DemoRequestNotFoundError(LookupError):
    """Aucune demande ne porte cet identifiant."""


def _now() -> datetime:
    return datetime.now(UTC)


async def received_today(session: AsyncSession, *, now: datetime | None = None) -> int:
    since = (now or _now()) - timedelta(days=1)
    total = await session.scalar(
        select(func.count()).select_from(DemoRequest).where(DemoRequest.created_at >= since)
    )
    return int(total or 0)


async def create_request(
    session: AsyncSession,
    *,
    name: str,
    email: str,
    organisation: str,
    interest: DemoInterest,
    language: str,
    job_title: str | None = None,
    country: str | None = None,
    message: str | None = None,
    now: datetime | None = None,
) -> DemoRequest:
    moment = now or _now()
    request = DemoRequest(
        name=name.strip(),
        email=email.strip().lower(),
        organisation=organisation.strip(),
        job_title=(job_title or "").strip() or None,
        country=(country or "").strip().upper() or None,
        interest=interest.value,
        message=(message or "").strip() or None,
        language=language,
        consent_at=moment,
        created_at=moment,
        status=DemoRequestStatus.NEW.value,
    )
    session.add(request)
    await session.flush()
    return request


async def list_requests(
    session: AsyncSession,
    *,
    status: DemoRequestStatus | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[Sequence[DemoRequest], int]:
    query = select(DemoRequest)
    if status is not None:
        query = query.where(DemoRequest.status == status.value)
    total = await session.scalar(select(func.count()).select_from(query.subquery()))
    rows = (
        await session.scalars(
            query.order_by(DemoRequest.created_at.desc()).limit(limit).offset(offset)
        )
    ).all()
    return rows, int(total or 0)


async def set_status(
    session: AsyncSession,
    request_id: UUID,
    status: DemoRequestStatus,
    *,
    user_id: UUID | None,
    now: datetime | None = None,
) -> DemoRequest:
    request = await session.get(DemoRequest, request_id)
    if request is None:
        raise DemoRequestNotFoundError(f"Demande {request_id} introuvable.")
    request.status = status.value
    request.handled_by = user_id
    request.handled_at = now or _now()
    await session.flush()
    return request


async def purge(
    session: AsyncSession, *, older_than_days: int = RETENTION_DAYS, now: datetime | None = None
) -> int:
    """Supprime les demandes plus anciennes que la durée de conservation."""
    limit = (now or _now()) - timedelta(days=older_than_days)
    result = await session.execute(delete(DemoRequest).where(DemoRequest.created_at < limit))
    return int(getattr(result, "rowcount", 0) or 0)
