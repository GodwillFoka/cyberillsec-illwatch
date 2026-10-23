"""Liste d'exclusion des IOC faux positifs — M9 (ADR-022), tâche 3.6.

Exclure, c'est dire « cette valeur n'est pas malveillante ici » (CDN de l'organisation,
résolveur public, faux positif d'une source). L'IOC reste en base avec sa provenance, mais
`is_active_clause` l'écarte : il n'est plus compté, chassé ni corrélé. Une nouvelle observation
par une source ne lève pas l'exclusion ; son retrait est réservé à un administrateur.
"""

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import Exclusion, Incident, IncidentEvent
from illwatch.modules.threat_feeds.validators import InvalidIndicatorError, normalize_indicator
from illwatch.shared.enums import IncidentEventType, IncidentStatus
from illwatch.shared.server_text import tr

MAX_REASON_LENGTH = 2000
MAX_DAYS = 3650


class ExclusionError(ValueError):
    """Saisie refusée (message destiné à l'analyste)."""


class ExclusionExistsError(ExclusionError):
    pass


class ExclusionNotFoundError(LookupError):
    pass


def _now() -> datetime:
    return datetime.now(UTC)


async def find_exclusion(
    session: AsyncSession, indicator_type: str, value: str, now: datetime | None = None
) -> Exclusion | None:
    """Exclusion en vigueur pour ce couple (type, valeur normalisée), ou None."""
    moment = now or _now()
    exclusion = await session.scalar(
        select(Exclusion).where(
            Exclusion.indicator_type == str(indicator_type), Exclusion.value == value
        )
    )
    if exclusion is None:
        return None
    expires = exclusion.expires_at
    if (
        expires is not None
        and (expires if expires.tzinfo else expires.replace(tzinfo=UTC)) <= moment
    ):
        return None
    return exclusion


async def create_exclusion(
    session: AsyncSession,
    *,
    value: str,
    reason: str,
    author_id: UUID | None,
    incident_id: UUID | None = None,
    days: int | None = None,
    now: datetime | None = None,
) -> Exclusion:
    """Exclut une valeur (normalisée comme un IOC). Rattachée à un incident, l'exclusion est
    consignée dans sa chronologie (évènement IOC_EXCLUDED)."""
    text = " ".join((reason or "").split())[:MAX_REASON_LENGTH]
    if len(text) < 5:
        raise ExclusionError("Motif obligatoire (5 caractères au moins) : pourquoi est-ce sûr ?")
    if days is not None and not 1 <= days <= MAX_DAYS:
        raise ExclusionError(f"Durée entre 1 et {MAX_DAYS} jours, ou sans expiration.")
    try:
        ioc_type, normalized = normalize_indicator(value)
    except InvalidIndicatorError as exc:
        raise ExclusionError(str(exc)) from exc
    moment = now or _now()
    existing = await session.scalar(
        select(Exclusion).where(
            Exclusion.indicator_type == ioc_type.value, Exclusion.value == normalized
        )
    )
    if existing is not None:
        expires = existing.expires_at
        if expires is None or (expires if expires.tzinfo else expires.replace(tzinfo=UTC)) > moment:
            raise ExclusionExistsError(f"{normalized} est déjà exclu.")
        await session.delete(existing)  # exclusion échue : remplacée
        await session.flush()
    incident: Incident | None = None
    if incident_id is not None:
        incident = await session.get(Incident, incident_id)
        if incident is None:
            raise ExclusionError(f"Incident {incident_id} introuvable.")
    exclusion = Exclusion(
        indicator_type=ioc_type.value,
        value=normalized,
        reason=text,
        created_by=author_id,
        created_at=moment,
        expires_at=moment + timedelta(days=days) if days else None,
        incident_id=incident_id,
    )
    session.add(exclusion)
    if incident is not None and incident.status != IncidentStatus.CLOTURE:
        session.add(
            IncidentEvent(
                incident_id=incident.id,
                author_id=author_id,
                event_type=IncidentEventType.IOC_EXCLUDED,
                message=tr(
                    f"Faux positif : {normalized} mis en liste d'exclusion. Motif : {text}",
                    f"False positive: {normalized} added to the exclusion list. Reason: {text}",
                ),
                created_at=moment,
            )
        )
    try:
        await session.flush()
    except IntegrityError:
        raise ExclusionExistsError(f"{normalized} est déjà exclu.") from None
    return exclusion


async def list_exclusions(session: AsyncSession, *, limit: int = 200) -> Sequence[Exclusion]:
    return (
        await session.scalars(
            select(Exclusion).order_by(Exclusion.created_at.desc(), Exclusion.id).limit(limit)
        )
    ).all()


async def delete_exclusion(session: AsyncSession, exclusion_id: UUID) -> Exclusion:
    exclusion = await session.get(Exclusion, exclusion_id)
    if exclusion is None:
        raise ExclusionNotFoundError(str(exclusion_id))
    await session.delete(exclusion)
    await session.flush()
    return exclusion
