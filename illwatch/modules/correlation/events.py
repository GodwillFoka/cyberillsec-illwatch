"""Évènements corrélés : lecture, acquittement, ouverture d'incident — M8, ADR-020."""

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import ColumnElement, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import Asset, CorrelatedEvent, Incident
from illwatch.modules.correlation.engine import ACK_PRIORITY
from illwatch.modules.incidents import service as incidents
from illwatch.shared.enums import RiskPriority, Severity

PRIORITY_SEVERITY = {
    RiskPriority.P0_CRITIQUE: Severity.CRITICAL,
    RiskPriority.P1_ELEVE: Severity.HIGH,
    RiskPriority.P2_MOYEN: Severity.MEDIUM,
    RiskPriority.P3_FAIBLE: Severity.LOW,
}


class CorrelationNotFoundError(LookupError):
    pass


@dataclass(frozen=True)
class EventPage:
    items: list[tuple[CorrelatedEvent, str]]  # (évènement, nom de l'actif)
    total: int


async def list_events(
    session: AsyncSession,
    *,
    limit: int,
    offset: int,
    open_only: bool = True,
    priority: RiskPriority | None = None,
    rule: str | None = None,
    asset_id: UUID | None = None,
) -> EventPage:
    conditions: list[ColumnElement[bool]] = []
    if open_only:
        conditions.append(CorrelatedEvent.acknowledged_at.is_(None))
    if priority is not None:
        conditions.append(CorrelatedEvent.priority == priority.value)
    if rule:
        conditions.append(CorrelatedEvent.rule_id == rule)
    if asset_id is not None:
        conditions.append(CorrelatedEvent.asset_id == asset_id)
    total = int(
        await session.scalar(select(func.count()).select_from(CorrelatedEvent).where(*conditions))
        or 0
    )
    # Tri : l'ordre alphabétique des priorités est leur ordre de gravité (P0 < P1 < P2 < P3).
    rows = await session.execute(
        select(CorrelatedEvent, Asset.name)
        .join(Asset, Asset.id == CorrelatedEvent.asset_id)
        .where(*conditions)
        .order_by(
            CorrelatedEvent.priority,
            CorrelatedEvent.score.desc(),
            CorrelatedEvent.last_seen.desc(),
            CorrelatedEvent.id,
        )
        .limit(limit)
        .offset(offset)
    )
    return EventPage(items=[(e, n) for e, n in rows.tuples().all()], total=total)


async def get_event(session: AsyncSession, event_id: UUID) -> tuple[CorrelatedEvent, str]:
    row = (
        await session.execute(
            select(CorrelatedEvent, Asset.name)
            .join(Asset, Asset.id == CorrelatedEvent.asset_id)
            .where(CorrelatedEvent.id == event_id)
        )
    ).first()
    if row is None:
        raise CorrelationNotFoundError(f"Évènement corrélé {event_id} introuvable.")
    return row[0], row[1]


def _mark_acknowledged(event: CorrelatedEvent, user_id: UUID | None) -> None:
    """Acquitte en retenant la priorité du moment : le moteur ne rouvrira l'évènement que
    s'il devient plus grave que cela (ADR-020)."""
    if event.acknowledged_at is not None:
        return
    event.acknowledged_at = datetime.now(UTC)
    event.acknowledged_by = user_id
    event.detail = {**(event.detail or {}), ACK_PRIORITY: event.priority}


async def _locked(session: AsyncSession, event_id: UUID) -> CorrelatedEvent:
    event = await session.scalar(
        select(CorrelatedEvent).where(CorrelatedEvent.id == event_id).with_for_update()
    )
    if event is None:
        raise CorrelationNotFoundError(f"Évènement corrélé {event_id} introuvable.")
    return event


async def acknowledge(session: AsyncSession, event_id: UUID, user_id: UUID) -> CorrelatedEvent:
    event = await _locked(session, event_id)
    _mark_acknowledged(event, user_id)
    await session.flush()
    return event


async def open_incident(
    session: AsyncSession, event_id: UUID, *, author_id: UUID | None
) -> tuple[Incident, bool]:
    """Incident de réponse à un évènement corrélé (idempotent : un seul incident par évènement ;
    la ligne est verrouillée, deux clics simultanés n'ouvrent pas deux incidents)."""
    event = await _locked(session, event_id)
    _, asset_name = await get_event(session, event_id)
    if event.incident_id is not None:
        existing = await session.get(Incident, event.incident_id)
        if existing is not None:
            return existing, False
    detail = event.detail or {}
    lines = [
        f"Évènement corrélé {event.rule_id} : {detail.get('rule_label', '')}.",
        f"Actif : {asset_name} (criticité {detail.get('asset_criticality', '?')}).",
        f"Score {float(event.score):.1f}".replace(".", ",")
        + f" / 100, priorité {event.priority[:2]}.",
    ]
    incident = await incidents.create_incident(
        session,
        title=event.title[:200],
        description="\n".join(lines),
        severity=PRIORITY_SEVERITY[RiskPriority(event.priority)],
        author_id=author_id,
    )
    if event.cve_id:
        await incidents.attach_cve(session, incident.id, event.cve_id, author_id=author_id)
    if event.indicator_id:
        await incidents.attach_indicator(
            session, incident.id, author_id=author_id, indicator_id=event.indicator_id
        )
    event.incident_id = incident.id
    _mark_acknowledged(event, author_id)
    await session.flush()
    return incident, True


async def open_count(session: AsyncSession) -> dict[str, int]:
    rows = await session.execute(
        select(CorrelatedEvent.priority, func.count())
        .where(CorrelatedEvent.acknowledged_at.is_(None))
        .group_by(CorrelatedEvent.priority)
    )
    by_priority = {str(p): int(n) for p, n in rows.tuples().all()}
    return {p.value: by_priority.get(p.value, 0) for p in RiskPriority}
