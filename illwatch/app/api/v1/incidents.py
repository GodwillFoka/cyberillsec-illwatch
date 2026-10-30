"""Routes de gestion des incidents : `/api/v1/incidents` (MOD-04, RF-17 à RF-20).

| Opération                                          | ADMIN | ANALYST | VIEWER |
|----------------------------------------------------|:-----:|:-------:|:------:|
| Lister / consulter (avec chronologie)              |   ✅  |   ✅    |   ✅   |
| Créer, faire évoluer, assigner, commenter, lier    |   ✅  |   ✅    |   ❌   |
| Ouvrir un incident depuis une alerte CVE           |   ✅  |   ✅    |   ❌   |
| Escalader (L1 → L2 → L3), chasser depuis l'incident |   ✅  |   ✅    |   ❌   |

Pas de suppression ni de modification d'événement : la chronologie est une preuve (RF-19).
Codes d'erreur : 409 transition ou escalade interdite, incident clos ; 422 clôture sans
résumé ou motif manquant.
"""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.api.deps import Audit, CurrentUser, DbSession, require_roles
from illwatch.app.api.v1.attack import AttackContextRead, attack_context
from illwatch.app.config import get_settings
from illwatch.app.models import (
    CVE,
    CorrelatedEvent,
    HuntingMatch,
    Incident,
    IncidentCVE,
    IncidentIndicator,
    Indicator,
    User,
)
from illwatch.modules.cve_tracker.queries import CVENotFoundError, get_cve
from illwatch.modules.incidents import service
from illwatch.modules.incidents.service import (
    IncidentClosedError,
    IncidentNotFoundError,
    InvalidAssigneeError,
    InvalidEscalationError,
    LinkTargetNotFoundError,
)
from illwatch.modules.incidents.state_machine import (
    ClosureRequirementError,
    InvalidTransitionError,
    next_states,
)
from illwatch.modules.soc import response as soc_response
from illwatch.modules.threat_feeds.fetcher import fetch_feed_content
from illwatch.shared.enums import (
    HuntStatus,
    HuntTrigger,
    IncidentEventType,
    IncidentStatus,
    Severity,
    SocTier,
    UserRole,
)

router = APIRouter(prefix="/incidents", tags=["incidents"])
alert_router = APIRouter(prefix="/alerts", tags=["alertes"])

Responder = Annotated[User, Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST))]

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200


# --- Schémas ------------------------------------------------------------------------------


class IncidentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=service.MAX_TITLE_LENGTH)
    description: str = Field(min_length=1, max_length=20_000)
    severity: Severity
    assigned_to: UUID | None = None
    cve_ids: list[Annotated[str, Field(max_length=32)]] = Field(
        default_factory=list,
        max_length=20,
        description="CVE à associer dès l'ouverture (même transaction : tout ou rien).",
    )


class TransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: IncidentStatus
    note: str | None = Field(default=None, max_length=5_000)
    closure_summary: str | None = Field(default=None, max_length=20_000)


class NoteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(min_length=1, max_length=20_000)
    kind: IncidentEventType = IncidentEventType.COMMENT


class AssignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: UUID | None


class IndicatorLink(BaseModel):
    model_config = ConfigDict(extra="forbid")

    indicator_id: UUID | None = None
    value: str | None = Field(default=None, max_length=2048)

    @model_validator(mode="after")
    def _one_of(self) -> "IndicatorLink":
        if (self.indicator_id is None) == (self.value is None):
            raise ValueError("Fournir indicator_id ou value (l'un des deux).")
        return self


class CVELink(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_id: str = Field(pattern=r"^(?i:CVE)-\d{4}-\d{4,}$")


class EventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    event_type: IncidentEventType
    message: str
    author_id: UUID | None
    from_status: IncidentStatus | None
    to_status: IncidentStatus | None
    created_at: datetime


class IncidentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    title: str
    severity: Severity
    status: IncidentStatus
    tier: SocTier
    assigned_to: UUID | None
    created_by: UUID | None
    source_alert_id: UUID | None
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None


class RecommendationRead(BaseModel):
    phase: IncidentStatus
    title: str
    detail: str
    current: bool


class IncidentHuntRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    trigger: HuntTrigger
    status: HuntStatus
    observables_count: int
    matches_count: int
    started_at: datetime
    finished_at: datetime | None


class IncidentDetail(IncidentRead):
    description: str
    closure_summary: str | None
    next_states: list[IncidentStatus]
    indicator_ids: list[UUID]
    cve_ids: list[str]
    timeline: list[EventRead]
    recommendations: list[RecommendationRead] = Field(
        description="Recommandations de réponse (M9) : la phase en cours d'abord."
    )
    hunts: list[IncidentHuntRead] = Field(description="Chasses lancées depuis l'incident.")
    attack: AttackContextRead = Field(
        description="Techniques ATT&CK (chasses, corrélations, CVE exploitées), acteurs cités."
    )


class EscalationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=5, max_length=2000)
    target: SocTier | None = Field(
        default=None, description="Niveau visé ; défaut : le niveau suivant."
    )


class IncidentHuntRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observables: list[Annotated[str, Field(max_length=2048)]] = Field(
        default_factory=list,
        max_length=soc_response.MAX_EXTRA,
        description="Observables relevés pendant l'investigation, en plus des IOC associés.",
    )


class IncidentPage(BaseModel):
    items: list[IncidentRead]
    total: int
    limit: int
    offset: int


class LinkResult(BaseModel):
    created: bool


async def _detail(session: AsyncSession, incident: Incident) -> IncidentDetail:
    recommendations = await soc_response.incident_recommendations(session, incident)
    hunts = await soc_response.incident_hunts(session, incident.id)
    attack = await _incident_attack(session, incident, [h.id for h in hunts])
    return IncidentDetail(
        **IncidentRead.model_validate(incident).model_dump(),
        description=incident.description,
        closure_summary=incident.closure_summary,
        next_states=sorted(next_states(IncidentStatus(incident.status))),
        indicator_ids=[link.indicator_id for link in incident.indicators],
        cve_ids=[link.cve_id for link in incident.cves],
        timeline=[EventRead.model_validate(e) for e in incident.events],
        recommendations=[
            RecommendationRead(
                phase=IncidentStatus(r.phase), title=r.title, detail=r.detail, current=r.current
            )
            for r in recommendations
        ],
        hunts=[IncidentHuntRead.model_validate(h) for h in hunts],
        attack=attack,
    )


async def _incident_attack(
    session: AsyncSession, incident: Incident, hunt_ids: list[UUID]
) -> AttackContextRead:
    """Règles qui ont parlé (chasses de l'incident, évènements corrélés qui l'ont ouvert),
    CVE exploitées (T1190), acteurs cités par les IOC ou le titre."""
    rules: list[str] = []
    if hunt_ids:
        rules += list(
            (
                await session.scalars(
                    select(HuntingMatch.rule_id)
                    .where(HuntingMatch.session_id.in_(hunt_ids))
                    .distinct()
                )
            ).all()
        )
    rules += list(
        (
            await session.scalars(
                select(CorrelatedEvent.rule_id)
                .where(CorrelatedEvent.incident_id == incident.id)
                .distinct()
            )
        ).all()
    )
    exploited = await session.scalar(
        select(func.count())
        .select_from(IncidentCVE)
        .join(CVE, CVE.id == IncidentCVE.cve_id)
        .where(
            IncidentCVE.incident_id == incident.id,
            or_(CVE.is_kev.is_(True), CVE.has_public_exploit.is_(True)),
        )
    )
    texts = list(
        (
            await session.scalars(
                select(Indicator.description)
                .join(IncidentIndicator, IncidentIndicator.indicator_id == Indicator.id)
                .where(IncidentIndicator.incident_id == incident.id)
            )
        ).all()
    )
    return await attack_context(
        session,
        rule_ids=sorted(set(rules)),
        techniques=["T1190"] if exploited else [],
        texts=[incident.title, incident.description, *texts],
        indicator_ids=[link.indicator_id for link in incident.indicators],
    )


def _translate(exc: Exception) -> HTTPException:
    if isinstance(exc, IncidentNotFoundError):
        return HTTPException(status.HTTP_404_NOT_FOUND, detail=f"Incident {exc} introuvable.")
    if isinstance(exc, LinkTargetNotFoundError):
        return HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc))
    if isinstance(exc, InvalidTransitionError | IncidentClosedError | InvalidEscalationError):
        return HTTPException(status.HTTP_409_CONFLICT, detail=str(exc))
    return HTTPException(422, detail=str(exc))  # ClosureRequirement, assignation, valeur


_HANDLED = (
    IncidentNotFoundError,
    LinkTargetNotFoundError,
    InvalidTransitionError,
    IncidentClosedError,
    ClosureRequirementError,
    InvalidAssigneeError,
    InvalidEscalationError,
    ValueError,
)


# --- Routes --------------------------------------------------------------------------------


@router.get(
    "", response_model=IncidentPage, summary="Lister les incidents, les plus graves d'abord"
)
async def list_incidents(
    session: DbSession,
    _: CurrentUser,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
    offset: Annotated[int, Query(ge=0)] = 0,
    status_filter: Annotated[IncidentStatus | None, Query(alias="status")] = None,
    severity: Severity | None = None,
    assigned_to: UUID | None = None,
    open_only: bool = False,
    indicator_id: Annotated[
        UUID | None, Query(description="Incidents auxquels cet IOC est associé.")
    ] = None,
    cve_id: Annotated[
        str | None,
        Query(max_length=32, description="Incidents auxquels cette CVE est associée."),
    ] = None,
    tier: Annotated[SocTier | None, Query(description="Niveau SOC (M9).")] = None,
) -> IncidentPage:
    page = await service.list_incidents(
        session,
        limit=limit,
        offset=offset,
        status=status_filter,
        severity=severity,
        assigned_to=assigned_to,
        open_only=open_only,
        indicator_id=indicator_id,
        cve_id=cve_id,
        tier=tier,
    )
    return IncidentPage(
        items=[IncidentRead.model_validate(i) for i in page.items],
        total=page.total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "",
    response_model=IncidentDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Ouvrir un incident (ADMIN, ANALYST)",
)
async def create_incident(
    payload: IncidentCreate, session: DbSession, user: Responder, response: Response
) -> IncidentDetail:
    # CVE vérifiées avant toute écriture : un identifiant inconnu n'ouvre pas d'incident orphelin.
    for cve_id in payload.cve_ids:
        try:
            await get_cve(session, cve_id)
        except CVENotFoundError:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND, detail=f"{cve_id} n'est pas suivie par ILLWATCH."
            ) from None
    try:
        incident = await service.create_incident(
            session,
            title=payload.title,
            description=payload.description,
            severity=payload.severity,
            assigned_to=payload.assigned_to,
            author_id=user.id,
        )
        for cve_id in dict.fromkeys(payload.cve_ids):
            await service.attach_cve(session, incident.id, cve_id, author_id=user.id)
        detail = await _detail(session, await service.get_incident(session, incident.id))
    except _HANDLED as exc:
        raise _translate(exc) from None
    response.headers["Location"] = f"{get_settings().api_v1_prefix}/incidents/{incident.id}"
    return detail


@router.get("/{incident_id}", response_model=IncidentDetail, summary="Incident et chronologie")
async def read_incident(incident_id: UUID, session: DbSession, _: CurrentUser) -> IncidentDetail:
    try:
        return await _detail(session, await service.get_incident(session, incident_id))
    except IncidentNotFoundError as exc:
        raise _translate(exc) from None


@router.post(
    "/{incident_id}/transitions",
    response_model=IncidentDetail,
    summary="Faire évoluer le statut (machine d'état NIST SP 800-61)",
)
async def transition(
    incident_id: UUID, payload: TransitionRequest, session: DbSession, user: Responder
) -> IncidentDetail:
    try:
        await service.transition(
            session,
            incident_id,
            payload.target,
            author_id=user.id,
            note=payload.note,
            closure_summary=payload.closure_summary,
        )
        return await _detail(session, await service.get_incident(session, incident_id))
    except _HANDLED as exc:
        raise _translate(exc) from None


@router.post(
    "/{incident_id}/notes",
    response_model=EventRead,
    status_code=status.HTTP_201_CREATED,
    summary="Ajouter un commentaire ou une action menée",
)
async def add_note(
    incident_id: UUID, payload: NoteRequest, session: DbSession, user: Responder
) -> EventRead:
    try:
        note = await service.add_note(
            session, incident_id, payload.message, author_id=user.id, kind=payload.kind
        )
    except _HANDLED as exc:
        raise _translate(exc) from None
    return EventRead.model_validate(note)


@router.put("/{incident_id}/assignee", response_model=IncidentDetail, summary="Assigner")
async def assign(
    incident_id: UUID, payload: AssignRequest, session: DbSession, user: Responder
) -> IncidentDetail:
    try:
        await service.assign(session, incident_id, payload.user_id, author_id=user.id)
        return await _detail(session, await service.get_incident(session, incident_id))
    except _HANDLED as exc:
        raise _translate(exc) from None


@router.post("/{incident_id}/indicators", response_model=LinkResult, summary="Associer un IOC")
async def link_indicator(
    incident_id: UUID, payload: IndicatorLink, session: DbSession, user: Responder
) -> LinkResult:
    try:
        created = await service.attach_indicator(
            session,
            incident_id,
            author_id=user.id,
            indicator_id=payload.indicator_id,
            value=payload.value,
        )
    except _HANDLED as exc:
        raise _translate(exc) from None
    return LinkResult(created=created)


@router.post("/{incident_id}/cves", response_model=LinkResult, summary="Associer une CVE")
async def link_cve(
    incident_id: UUID, payload: CVELink, session: DbSession, user: Responder
) -> LinkResult:
    try:
        created = await service.attach_cve(session, incident_id, payload.cve_id, author_id=user.id)
    except _HANDLED as exc:
        raise _translate(exc) from None
    return LinkResult(created=created)


@alert_router.post(
    "/{alert_id}/incident",
    response_model=IncidentDetail,
    summary="Ouvrir l'incident de réponse à une alerte CVE (idempotent)",
)
async def incident_from_alert(
    alert_id: UUID, session: DbSession, user: Responder, response: Response
) -> IncidentDetail:
    try:
        incident, created = await service.open_from_alert(session, alert_id, author_id=user.id)
        detail = await _detail(session, await service.get_incident(session, incident.id))
    except _HANDLED as exc:
        raise _translate(exc) from None
    response.status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK
    return detail


@router.post(
    "/{incident_id}/escalate",
    response_model=IncidentDetail,
    summary="Escalader au niveau SOC supérieur, motif obligatoire (M9)",
)
async def escalate(
    incident_id: UUID,
    payload: EscalationRequest,
    session: DbSession,
    user: Responder,
    audit: Audit,
) -> IncidentDetail:
    try:
        incident = await service.escalate(
            session, incident_id, reason=payload.reason, author_id=user.id, target=payload.target
        )
        detail = await _detail(session, await service.get_incident(session, incident.id))
    except _HANDLED as exc:
        raise _translate(exc) from None
    await audit.record(
        "incident.escalate",
        actor=user,
        target_type="incident",
        target_id=incident_id,
        detail={"tier": detail.tier, "reason": payload.reason[:200]},
    )
    return detail


@router.post(
    "/{incident_id}/hunt",
    response_model=IncidentHuntRead,
    status_code=status.HTTP_201_CREATED,
    summary="Chasser depuis l'incident : ses IOC, les observables relevés, l'inventaire (M9)",
)
async def hunt(
    incident_id: UUID,
    payload: IncidentHuntRequest,
    session: DbSession,
    user: Responder,
    audit: Audit,
) -> IncidentHuntRead:
    try:
        session_hunt = await soc_response.hunt_from_incident(
            session,
            incident_id,
            author_id=user.id,
            settings=get_settings(),
            fetch=fetch_feed_content,
            extra=payload.observables,
        )
    except _HANDLED as exc:
        raise _translate(exc) from None
    await audit.record(
        "hunt.run",
        actor=user,
        target_type="hunt",
        target_id=session_hunt.id,
        detail={
            "incident": str(incident_id),
            "observables": session_hunt.observables_count,
            "matches": session_hunt.matches_count,
            "status": session_hunt.status,
        },
    )
    return IncidentHuntRead.model_validate(session_hunt)
