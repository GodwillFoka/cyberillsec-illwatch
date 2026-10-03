"""Gestion des incidents — MOD-04, RF-17 à RF-20 (phase 4, ADR-008).

Toute action sur un incident passe par ce service, qui garantit trois invariants :

1. **Machine d'état** (RF-18) : un changement de statut est validé par
   `state_machine.validate_transition` (graphe NIST SP 800-61, retour en ANALYSE permis,
   clôture impossible sans résumé, CLOTURE terminal).
2. **Chronologie complète et immuable** (RF-19) : création, transition, assignation,
   commentaire, action, ajout d'IOC ou de CVE produisent chacun un `IncidentEvent`, dans la
   même transaction que le changement qu'il décrit. Pas d'événement, pas de changement.
3. **Incident clos = gelé** : après CLOTURE, seuls les commentaires restent possibles (retour
   d'expérience) ; ni transition, ni assignation, ni ajout d'IOC/CVE.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import ColumnElement, case, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from sentry.app.models import (
    CVE,
    CVEAlert,
    Incident,
    IncidentCVE,
    IncidentEvent,
    IncidentIndicator,
    Indicator,
    User,
)
from sentry.modules.cve_tracker.scoring import remediation_sla_hours
from sentry.modules.incidents.state_machine import validate_transition
from sentry.modules.threat_feeds.validators import InvalidIndicatorError, normalize_indicator
from sentry.shared.enums import (
    IncidentEventType,
    IncidentStatus,
    RiskPriority,
    Severity,
    UserRole,
)

MAX_TITLE_LENGTH = 200
SEVERITY_ORDER = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1}
PRIORITY_TO_SEVERITY = {
    RiskPriority.P0_CRITIQUE: Severity.CRITICAL,
    RiskPriority.P1_ELEVE: Severity.HIGH,
    RiskPriority.P2_MOYEN: Severity.MEDIUM,
    RiskPriority.P3_FAIBLE: Severity.LOW,
}


class IncidentNotFoundError(LookupError):
    """Aucun incident ne porte cet identifiant."""


class IncidentClosedError(ValueError):
    """L'incident est clos : seuls les commentaires restent possibles."""


class LinkTargetNotFoundError(LookupError):
    """IOC, CVE, alerte ou utilisateur introuvable."""


class InvalidAssigneeError(ValueError):
    """L'utilisateur ne peut pas être assigné (inactif ou lecteur seul)."""


@dataclass(frozen=True, slots=True)
class IncidentPage:
    items: Sequence[Incident]
    total: int


def _now() -> datetime:
    return datetime.now(UTC)


def _event(
    incident: Incident,
    kind: IncidentEventType,
    message: str,
    author_id: UUID | None,
    *,
    from_status: str | None = None,
    to_status: str | None = None,
) -> IncidentEvent:
    return IncidentEvent(
        incident_id=incident.id,
        author_id=author_id,
        event_type=kind,
        message=message,
        from_status=from_status,
        to_status=to_status,
        created_at=_now(),
    )


def _ensure_open(incident: Incident) -> None:
    if incident.status == IncidentStatus.CLOTURE:
        raise IncidentClosedError(
            "Incident clos : seuls les commentaires de retour d'expérience restent possibles."
        )


# --- Lecture ------------------------------------------------------------------------------


async def get_incident(session: AsyncSession, incident_id: UUID) -> Incident:
    """Incident avec chronologie, IOC et CVE chargés."""
    incident = await session.get(
        Incident,
        incident_id,
        populate_existing=True,
        options=[
            selectinload(Incident.events),
            selectinload(Incident.indicators),
            selectinload(Incident.cves),
        ],
    )
    if incident is None:
        raise IncidentNotFoundError(str(incident_id))
    return incident


async def list_incidents(
    session: AsyncSession,
    *,
    limit: int,
    offset: int,
    status: IncidentStatus | None = None,
    severity: Severity | None = None,
    assigned_to: UUID | None = None,
    open_only: bool = False,
) -> IncidentPage:
    """Les plus graves d'abord, puis les plus récents."""
    conditions: list[ColumnElement[bool]] = []
    if status is not None:
        conditions.append(Incident.status == status)
    if severity is not None:
        conditions.append(Incident.severity == severity)
    if assigned_to is not None:
        conditions.append(Incident.assigned_to == assigned_to)
    if open_only:
        conditions.append(Incident.status != IncidentStatus.CLOTURE)
    rank = case(*((Incident.severity == s.value, r) for s, r in SEVERITY_ORDER.items()), else_=0)
    total = await session.scalar(select(func.count()).select_from(Incident).where(*conditions))
    rows = await session.execute(
        select(Incident)
        .where(*conditions)
        .order_by(rank.desc(), Incident.created_at.desc(), Incident.id)
        .limit(limit)
        .offset(offset)
    )
    return IncidentPage(items=rows.scalars().all(), total=total or 0)


# --- Écritures --------------------------------------------------------------------------


async def _check_assignee(session: AsyncSession, user_id: UUID) -> User:
    user = await session.get(User, user_id)
    if user is None:
        raise LinkTargetNotFoundError(f"Utilisateur {user_id} introuvable.")
    if not user.is_active or user.role == UserRole.VIEWER:
        raise InvalidAssigneeError(
            f"{user.username} ne peut pas être assigné (compte inactif ou lecteur seul)."
        )
    return user


async def create_incident(
    session: AsyncSession,
    *,
    title: str,
    description: str,
    severity: Severity,
    author_id: UUID | None,
    assigned_to: UUID | None = None,
    source_alert_id: UUID | None = None,
) -> Incident:
    """Ouvre un incident en statut NOUVEAU (RF-17) et trace sa création."""
    clean_title = " ".join(title.split())
    if not clean_title or len(clean_title) > MAX_TITLE_LENGTH:
        raise ValueError(f"Titre obligatoire, {MAX_TITLE_LENGTH} caractères au plus.")
    if assigned_to is not None:
        await _check_assignee(session, assigned_to)
    incident = Incident(
        title=clean_title,
        description=description.strip() or clean_title,
        severity=Severity(severity),
        status=IncidentStatus.NOUVEAU,
        assigned_to=assigned_to,
        created_by=author_id,
        source_alert_id=source_alert_id,
    )
    session.add(incident)
    await session.flush()
    session.add(
        _event(
            incident,
            IncidentEventType.CREATED,
            f"Incident ouvert, sévérité {incident.severity}.",
            author_id,
            to_status=IncidentStatus.NOUVEAU,
        )
    )
    await session.flush()
    return incident


async def transition(
    session: AsyncSession,
    incident_id: UUID,
    target: IncidentStatus,
    *,
    author_id: UUID | None,
    note: str | None = None,
    closure_summary: str | None = None,
) -> Incident:
    """Change le statut selon la machine d'état (RF-18) et l'inscrit dans la chronologie.

    Raises:
        InvalidTransitionError: transition hors du graphe NIST.
        ClosureRequirementError: clôture sans résumé.
    """
    incident = await get_incident(session, incident_id)
    current = IncidentStatus(incident.status)
    target = IncidentStatus(target)
    validate_transition(current, target, closure_summary=closure_summary)

    incident.status = target
    message = f"{current} → {target}"
    if target is IncidentStatus.CLOTURE:
        incident.closure_summary = (closure_summary or "").strip()
        incident.closed_at = _now()
        message += f". Résumé de clôture : {incident.closure_summary}"
    if note and note.strip():
        message += f". {note.strip()}"
    session.add(
        _event(
            incident,
            IncidentEventType.STATUS_CHANGE,
            message,
            author_id,
            from_status=current,
            to_status=target,
        )
    )
    await session.flush()
    return incident


async def add_note(
    session: AsyncSession,
    incident_id: UUID,
    message: str,
    *,
    author_id: UUID | None,
    kind: IncidentEventType = IncidentEventType.COMMENT,
) -> IncidentEvent:
    """Commentaire (toujours permis) ou action menée (incident ouvert seulement)."""
    if kind not in (IncidentEventType.COMMENT, IncidentEventType.ACTION_TAKEN):
        raise ValueError("Type de note : COMMENT ou ACTION_TAKEN.")
    text = message.strip()
    if not text:
        raise ValueError("Message vide.")
    incident = await get_incident(session, incident_id)
    if kind is IncidentEventType.ACTION_TAKEN:
        _ensure_open(incident)
    note = _event(incident, kind, text, author_id)
    session.add(note)
    await session.flush()
    return note


async def assign(
    session: AsyncSession, incident_id: UUID, assignee: UUID | None, *, author_id: UUID | None
) -> Incident:
    incident = await get_incident(session, incident_id)
    _ensure_open(incident)
    if assignee is None:
        message = "Incident désassigné."
    else:
        user = await _check_assignee(session, assignee)
        message = f"Incident assigné à {user.username}."
    incident.assigned_to = assignee
    session.add(_event(incident, IncidentEventType.ASSIGNED, message, author_id))
    await session.flush()
    return incident


async def attach_indicator(
    session: AsyncSession,
    incident_id: UUID,
    *,
    author_id: UUID | None,
    indicator_id: UUID | None = None,
    value: str | None = None,
) -> bool:
    """Associe un IOC (par identifiant ou par valeur normalisée). Idempotent.

    Retourne `False` si l'IOC était déjà associé (aucun événement en double).
    """
    incident = await get_incident(session, incident_id)
    _ensure_open(incident)
    indicator: Indicator | None = None
    if indicator_id is not None:
        indicator = await session.get(Indicator, indicator_id)
    elif value is not None:
        try:
            ioc_type, normalized = normalize_indicator(value)
        except InvalidIndicatorError as exc:
            raise LinkTargetNotFoundError(str(exc)) from exc
        indicator = await session.scalar(
            select(Indicator).where(Indicator.type == ioc_type, Indicator.value == normalized)
        )
    if indicator is None:
        raise LinkTargetNotFoundError("IOC introuvable : ingérez-le avant de l'associer.")
    if any(link.indicator_id == indicator.id for link in incident.indicators):
        return False
    incident.indicators.append(
        IncidentIndicator(indicator_id=indicator.id, added_by=author_id, added_at=_now())
    )
    session.add(
        _event(
            incident,
            IncidentEventType.IOC_ATTACHED,
            f"IOC associé : {indicator.type} {indicator.value}",
            author_id,
        )
    )
    await session.flush()
    return True


async def attach_cve(
    session: AsyncSession, incident_id: UUID, cve_id: str, *, author_id: UUID | None
) -> bool:
    """Associe une CVE suivie. Idempotent ; `False` si déjà associée."""
    incident = await get_incident(session, incident_id)
    _ensure_open(incident)
    cve = await session.get(CVE, cve_id.strip().upper())
    if cve is None:
        raise LinkTargetNotFoundError(f"{cve_id} n'est pas suivie : `sentry cves sync`.")
    if any(link.cve_id == cve.id for link in incident.cves):
        return False
    incident.cves.append(IncidentCVE(cve_id=cve.id, added_by=author_id, added_at=_now()))
    session.add(
        _event(
            incident,
            IncidentEventType.CVE_ATTACHED,
            f"CVE associée : {cve.id} (score {float(cve.composite_risk_score):.1f}, "
            f"{cve.priority})",
            author_id,
        )
    )
    await session.flush()
    return True


async def open_from_alert(
    session: AsyncSession, alert_id: UUID, *, author_id: UUID | None
) -> tuple[Incident, bool]:
    """Ouvre l'incident de réponse à une alerte CVE (ou retrouve celui déjà ouvert).

    La sévérité découle de la priorité SOC (P0 → CRITICAL…), la CVE est associée et
    l'alerte acquittée. Retourne (incident, créé ?).
    """
    alert = await session.get(CVEAlert, alert_id)
    if alert is None:
        raise LinkTargetNotFoundError(f"Alerte {alert_id} introuvable.")
    existing = await session.scalar(select(Incident).where(Incident.source_alert_id == alert_id))
    if existing is not None:
        return existing, False
    cve = await session.get(CVE, alert.cve_id)
    priority = RiskPriority(alert.priority)
    sla = remediation_sla_hours(priority)
    description = (
        f"Alerte SENTRY : {alert.cve_id} a franchi le seuil de risque "
        f"(score {float(alert.score):.1f}/100, {priority}, remédiation sous {sla} h, "
        f"déclencheur : {alert.reason}).\n\n{cve.description if cve else ''}"
    )
    incident = await create_incident(
        session,
        title=f"{alert.cve_id} — remédiation {priority} (score {float(alert.score):.0f})",
        description=description,
        severity=PRIORITY_TO_SEVERITY[priority],
        author_id=author_id,
        source_alert_id=alert.id,
    )
    if cve is not None:
        await attach_cve(session, incident.id, cve.id, author_id=author_id)
    if alert.acknowledged_at is None:
        alert.acknowledged_at = _now()
        alert.acknowledged_by = author_id
    await session.flush()
    return incident, True
