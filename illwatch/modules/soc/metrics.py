"""Pilotage du SOC, M9 (ADR-022) : délais, délais cibles, niveaux, charge, séries.

Définitions (affichées telles quelles dans l'écran Pilotage) :

- **Prise en charge** : premier geste d'un analyste après l'ouverture (assignation,
  changement de statut, escalade, action déclarée ou chasse). **MTTA** : délai moyen
  d'ouverture → prise en charge, sur les incidents ouverts dans la fenêtre.
- **MTTR** : délai moyen d'ouverture → clôture, sur les incidents clos dans la fenêtre.
- **Délais cibles** (SLA) par sévérité : prise en charge et résolution (tableau ci-dessous).
  Un incident ouvert qui dépasse l'un d'eux figure dans « en dépassement ».

Calcul en mémoire sur les incidents de la fenêtre et les incidents encore ouverts : un SOC en
compte des centaines, pas des millions ; les chiffres restent exacts et explicables.
"""

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from statistics import mean, median
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import CorrelatedEvent, Exclusion, Incident, IncidentEvent, User
from illwatch.shared.enums import IncidentEventType, IncidentStatus, Severity, SocTier, UserRole

ACK_SLA_HOURS = {Severity.CRITICAL: 1, Severity.HIGH: 4, Severity.MEDIUM: 24, Severity.LOW: 72}
RESOLUTION_SLA_HOURS = {
    Severity.CRITICAL: 24,
    Severity.HIGH: 72,
    Severity.MEDIUM: 168,
    Severity.LOW: 720,
}
TAKEN_IN_CHARGE = frozenset(
    {
        IncidentEventType.ASSIGNED,
        IncidentEventType.STATUS_CHANGE,
        IncidentEventType.ESCALATED,
        IncidentEventType.ACTION_TAKEN,
        IncidentEventType.HUNT_RUN,
    }
)
WINDOWS = (7, 30)


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


@dataclass(slots=True)
class SeverityStats:
    severity: str
    ack_sla_hours: int
    resolution_sla_hours: int
    opened: int = 0
    closed: int = 0
    mtta_minutes: float | None = None
    mttr_hours: float | None = None
    ack_within_sla: float | None = None  # part (0-1) des prises en charge dans le délai cible
    resolved_within_sla: float | None = None


@dataclass(slots=True)
class Breach:
    incident_id: UUID
    title: str
    severity: str
    tier: str
    kind: str  # « prise en charge » ou « résolution »
    age_hours: float
    target_hours: int


@dataclass(slots=True)
class Workload:
    label: str
    open_assigned: int
    closed_in_window: int


@dataclass(slots=True)
class DayCount:
    day: date
    opened: int
    closed: int


@dataclass(slots=True)
class SocMetrics:
    window_days: int
    generated_at: datetime
    opened: int = 0
    closed: int = 0
    open_now: int = 0
    mtta_minutes: float | None = None
    mttr_hours: float | None = None
    median_ttr_hours: float | None = None
    by_severity: list[SeverityStats] = field(default_factory=list)
    open_by_tier: dict[str, int] = field(default_factory=dict)
    escalations: dict[str, int] = field(default_factory=dict)
    workload: list[Workload] = field(default_factory=list)
    breaches: list[Breach] = field(default_factory=list)
    daily: list[DayCount] = field(default_factory=list)
    exclusions: int = 0
    false_positive_events: int = 0


def _round(value: float | None, digits: int = 1) -> float | None:
    return None if value is None else round(value, digits)


async def soc_metrics(
    session: AsyncSession, *, viewer: User, days: int = 7, now: datetime | None = None
) -> SocMetrics:
    if days not in WINDOWS:
        raise ValueError(f"Fenêtre de {' ou '.join(map(str, WINDOWS))} jours.")
    moment = now or datetime.now(UTC)
    start = moment - timedelta(days=days)
    out = SocMetrics(window_days=days, generated_at=moment)

    incidents = (
        await session.scalars(
            select(Incident).where(
                or_(
                    Incident.created_at >= start,
                    Incident.closed_at >= start,
                    Incident.status != IncidentStatus.CLOTURE,
                )
            )
        )
    ).all()
    ids = [i.id for i in incidents]
    events = (
        (
            await session.execute(
                select(
                    IncidentEvent.incident_id,
                    IncidentEvent.event_type,
                    IncidentEvent.message,
                    IncidentEvent.created_at,
                )
                .where(IncidentEvent.incident_id.in_(ids))
                .order_by(IncidentEvent.created_at, IncidentEvent.id)
            )
        ).all()
        if ids
        else []
    )
    taken: dict[UUID, datetime] = {}
    escalations: Counter[str] = Counter()
    for incident_id, kind, message, at in events:
        when = _utc(at)
        if when is None:
            continue
        if kind in TAKEN_IN_CHARGE and incident_id not in taken:
            taken[incident_id] = when
        if kind == IncidentEventType.ESCALATED and when >= start:
            step = message.split(" (")[0].removeprefix("Escalade ").strip()  # « L1 → L2 »
            escalations[step] += 1
    out.escalations = dict(escalations)

    stats = {
        s: SeverityStats(s.value, ACK_SLA_HOURS[s], RESOLUTION_SLA_HOURS[s])
        for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
    }
    ack_all: list[float] = []
    ttr_all: list[float] = []
    per_sev_ack: dict[Severity, list[tuple[float, bool]]] = {s: [] for s in stats}
    per_sev_ttr: dict[Severity, list[tuple[float, bool]]] = {s: [] for s in stats}
    tiers: Counter[str] = Counter()
    days_opened: Counter[date] = Counter()
    days_closed: Counter[date] = Counter()
    for incident in incidents:
        severity = Severity(incident.severity)
        created = _utc(incident.created_at) or moment
        closed = _utc(incident.closed_at)
        if created >= start:
            out.opened += 1
            stats[severity].opened += 1
            days_opened[created.date()] += 1
            if incident.id in taken:
                minutes = (taken[incident.id] - created).total_seconds() / 60
                ack_all.append(minutes)
                per_sev_ack[severity].append((minutes, minutes <= ACK_SLA_HOURS[severity] * 60))
        if closed is not None and closed >= start:
            out.closed += 1
            stats[severity].closed += 1
            days_closed[closed.date()] += 1
            hours = (closed - created).total_seconds() / 3600
            ttr_all.append(hours)
            per_sev_ttr[severity].append((hours, hours <= RESOLUTION_SLA_HOURS[severity]))
        if incident.status != IncidentStatus.CLOTURE:
            out.open_now += 1
            tiers[incident.tier] += 1
            age = (moment - created).total_seconds() / 3600
            if incident.id not in taken and age > ACK_SLA_HOURS[severity]:
                out.breaches.append(
                    Breach(
                        incident.id,
                        incident.title,
                        severity.value,
                        incident.tier,
                        "prise en charge",
                        round(age, 1),
                        ACK_SLA_HOURS[severity],
                    )
                )
            elif age > RESOLUTION_SLA_HOURS[severity]:
                out.breaches.append(
                    Breach(
                        incident.id,
                        incident.title,
                        severity.value,
                        incident.tier,
                        "résolution",
                        round(age, 1),
                        RESOLUTION_SLA_HOURS[severity],
                    )
                )
    out.mtta_minutes = _round(mean(ack_all)) if ack_all else None
    out.mttr_hours = _round(mean(ttr_all)) if ttr_all else None
    out.median_ttr_hours = _round(median(ttr_all)) if ttr_all else None
    for severity, row in stats.items():
        acks, ttrs = per_sev_ack[severity], per_sev_ttr[severity]
        row.mtta_minutes = _round(mean(m for m, _ in acks)) if acks else None
        row.mttr_hours = _round(mean(h for h, _ in ttrs)) if ttrs else None
        row.ack_within_sla = _round(sum(ok for _, ok in acks) / len(acks), 3) if acks else None
        row.resolved_within_sla = _round(sum(ok for _, ok in ttrs) / len(ttrs), 3) if ttrs else None
    out.by_severity = list(stats.values())
    out.open_by_tier = {t.value: tiers.get(t.value, 0) for t in SocTier}
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    out.breaches.sort(key=lambda b: (severity_rank.get(b.severity, 9), -b.age_hours))
    out.breaches = out.breaches[:20]
    first_day = start.date()
    out.daily = [
        DayCount(d, days_opened.get(d, 0), days_closed.get(d, 0))
        for d in (first_day + timedelta(days=n) for n in range(1, days + 1))
    ]
    out.workload = await _workload(session, viewer, incidents, start)
    out.exclusions = (
        await session.scalar(
            select(func.count()).select_from(Exclusion).where(Exclusion.created_at >= start)
        )
    ) or 0
    fp_rows = await session.scalars(
        select(CorrelatedEvent.detail).where(CorrelatedEvent.acknowledged_at >= start)
    )
    out.false_positive_events = sum(1 for d in fp_rows.all() if (d or {}).get("false_positive"))
    return out


async def _workload(
    session: AsyncSession, viewer: User, incidents: Sequence[Incident], start: datetime
) -> list[Workload]:
    """Charge par analyste. Les noms ne sont montrés qu'à un administrateur ; les autres rôles
    voient « vous » et des libellés neutres (même règle que la chronologie)."""
    open_by: Counter[UUID | None] = Counter()
    closed_by: Counter[UUID | None] = Counter()
    for incident in incidents:
        closed = _utc(incident.closed_at)
        if incident.status != IncidentStatus.CLOTURE:
            open_by[incident.assigned_to] += 1
        elif closed is not None and closed >= start:
            closed_by[incident.assigned_to] += 1
    people = [p for p in set(open_by) | set(closed_by) if p is not None]
    names: dict[UUID, str] = {}
    if people:
        rows = await session.execute(select(User.id, User.username).where(User.id.in_(people)))
        names = dict(rows.all())
    ordered = sorted(people, key=lambda p: (-open_by[p], -closed_by[p], names.get(p, "")))
    out: list[Workload] = []
    for index, person in enumerate(ordered, start=1):
        if viewer.role == UserRole.ADMIN:
            label = names.get(person, "compte supprimé")
        elif person == viewer.id:
            label = "vous"
        else:
            label = f"analyste {index}"
        out.append(Workload(label, open_by[person], closed_by[person]))
    if open_by[None] or closed_by[None]:
        out.append(Workload("non assigné", open_by[None], closed_by[None]))
    return out
