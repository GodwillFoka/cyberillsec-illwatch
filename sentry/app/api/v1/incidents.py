"""Routes de gestion des incidents — `/api/v1/incidents` (MOD-04, RF-17 à RF-20).

| Opération                                          | ADMIN | ANALYST | VIEWER |
|----------------------------------------------------|:-----:|:-------:|:------:|
| Lister / consulter (avec chronologie)              |   ✅  |   ✅    |   ✅   |
| Créer, faire évoluer, assigner, commenter, lier    |   ✅  |   ✅    |   ❌   |
| Ouvrir un incident depuis une alerte CVE           |   ✅  |   ✅    |   ❌   |

Pas de suppression ni de modification d'événement : la chronologie est une preuve (RF-19).
Codes d'erreur : 409 transition interdite ou incident clos, 422 clôture sans résumé.
"""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field, model_validator

from sentry.app.api.deps import CurrentUser, DbSession, require_roles
from sentry.app.config import get_settings
from sentry.app.models import Incident, User
from sentry.modules.incidents import service
from sentry.modules.incidents.service import (
    IncidentClosedError,
    IncidentNotFoundError,
    InvalidAssigneeError,
    LinkTargetNotFoundError,
)
from sentry.modules.incidents.state_machine import (
    ClosureRequirementError,
    InvalidTransitionError,
    next_states,
)
from sentry.shared.enums import IncidentEventType, IncidentStatus, Severity, UserRole

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
    assigned_to: UUID | None
    created_by: UUID | None
    source_alert_id: UUID | None
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None


class IncidentDetail(IncidentRead):
    description: str
    closure_summary: str | None
    next_states: list[IncidentStatus]
    indicator_ids: list[UUID]
    cve_ids: list[str]
    timeline: list[EventRead]


class IncidentPage(BaseModel):
    items: list[IncidentRead]
    total: int
    limit: int
    offset: int


class LinkResult(BaseModel):
    created: bool


def _detail(incident: Incident) -> IncidentDetail:
    return IncidentDetail(
        **IncidentRead.model_validate(incident).model_dump(),
        description=incident.description,
        closure_summary=incident.closure_summary,
        next_states=sorted(next_states(IncidentStatus(incident.status))),
        indicator_ids=[link.indicator_id for link in incident.indicators],
        cve_ids=[link.cve_id for link in incident.cves],
        timeline=[EventRead.model_validate(e) for e in incident.events],
    )


def _translate(exc: Exception) -> HTTPException:
    if isinstance(exc, IncidentNotFoundError):
        return HTTPException(status.HTTP_404_NOT_FOUND, detail=f"Incident {exc} introuvable.")
    if isinstance(exc, LinkTargetNotFoundError):
        return HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc))
    if isinstance(exc, InvalidTransitionError | IncidentClosedError):
        return HTTPException(status.HTTP_409_CONFLICT, detail=str(exc))
    return HTTPException(422, detail=str(exc))  # ClosureRequirement, assignation, valeur


_HANDLED = (
    IncidentNotFoundError,
    LinkTargetNotFoundError,
    InvalidTransitionError,
    IncidentClosedError,
    ClosureRequirementError,
    InvalidAssigneeError,
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
) -> IncidentPage:
    page = await service.list_incidents(
        session,
        limit=limit,
        offset=offset,
        status=status_filter,
        severity=severity,
        assigned_to=assigned_to,
        open_only=open_only,
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
    try:
        incident = await service.create_incident(
            session,
            title=payload.title,
            description=payload.description,
            severity=payload.severity,
            assigned_to=payload.assigned_to,
            author_id=user.id,
        )
        detail = _detail(await service.get_incident(session, incident.id))
    except _HANDLED as exc:
        raise _translate(exc) from None
    response.headers["Location"] = f"{get_settings().api_v1_prefix}/incidents/{incident.id}"
    return detail


@router.get("/{incident_id}", response_model=IncidentDetail, summary="Incident et chronologie")
async def read_incident(incident_id: UUID, session: DbSession, _: CurrentUser) -> IncidentDetail:
    try:
        return _detail(await service.get_incident(session, incident_id))
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
        return _detail(await service.get_incident(session, incident_id))
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
        return _detail(await service.get_incident(session, incident_id))
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
        detail = _detail(await service.get_incident(session, incident.id))
    except _HANDLED as exc:
        raise _translate(exc) from None
    response.status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK
    return detail
