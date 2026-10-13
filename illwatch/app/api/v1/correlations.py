"""Évènements corrélés — `/api/v1/correlations` (M8, ADR-020).

Lecture pour tous ; acquittement, ouverture d'incident et passe manuelle de corrélation pour
ADMIN et ANALYST (consignés au journal d'audit).
"""

from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field

from illwatch.app.api.deps import Audit, CurrentUser, DbSession, require_roles
from illwatch.app.config import get_settings
from illwatch.app.models import CorrelatedEvent, User
from illwatch.modules.correlation import engine
from illwatch.modules.correlation import events as service
from illwatch.modules.incidents.service import IncidentClosedError, LinkTargetNotFoundError
from illwatch.shared.enums import CorrelationRule, RiskPriority, UserRole

router = APIRouter(prefix="/correlations", tags=["corrélation"])

Responder = Annotated[User, Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST))]

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200


class CorrelationRead(BaseModel):
    id: UUID
    rule_id: CorrelationRule
    priority: RiskPriority
    score: float
    title: str
    asset_id: UUID
    asset_name: str
    cve_id: str | None
    indicator_id: UUID | None
    incident_id: UUID | None
    first_seen: datetime
    last_seen: datetime
    acknowledged_at: datetime | None
    detail: dict[str, Any] = Field(
        description="Pourquoi : produit, signaux, confiance, décomposition du score (breakdown)."
    )


class CorrelationPage(BaseModel):
    items: list[CorrelationRead]
    total: int
    limit: int
    offset: int


class CorrelationRunRead(BaseModel):
    assets: int
    created: int
    updated: int
    reopened: int
    by_rule: dict[str, int]


class IncidentLink(BaseModel):
    incident_id: UUID
    created: bool


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _read(event: CorrelatedEvent, asset_name: str) -> CorrelationRead:
    return CorrelationRead(
        id=event.id,
        rule_id=CorrelationRule(event.rule_id),
        priority=RiskPriority(event.priority),
        score=float(event.score),
        title=event.title,
        asset_id=event.asset_id,
        asset_name=asset_name,
        cve_id=event.cve_id,
        indicator_id=event.indicator_id,
        incident_id=event.incident_id,
        first_seen=_utc(event.first_seen) or event.first_seen,
        last_seen=_utc(event.last_seen) or event.last_seen,
        acknowledged_at=_utc(event.acknowledged_at),
        detail=event.detail or {},
    )


def _not_found(exc: Exception) -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.get("", response_model=CorrelationPage, summary="Évènements corrélés")
async def list_correlations(
    session: DbSession,
    _: CurrentUser,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
    offset: Annotated[int, Query(ge=0)] = 0,
    open_only: Annotated[bool, Query(alias="open")] = True,
    priority: RiskPriority | None = None,
    rule: CorrelationRule | None = None,
    asset_id: UUID | None = None,
) -> CorrelationPage:
    page = await service.list_events(
        session,
        limit=limit,
        offset=offset,
        open_only=open_only,
        priority=priority,
        rule=rule.value if rule else None,
        asset_id=asset_id,
    )
    return CorrelationPage(
        items=[_read(e, n) for e, n in page.items], total=page.total, limit=limit, offset=offset
    )


@router.post(
    "/run",
    response_model=CorrelationRunRead,
    summary="Lancer une passe de corrélation maintenant (ADMIN, ANALYST)",
)
async def run_now(session: DbSession, user: Responder, audit: Audit) -> CorrelationRunRead:
    now = datetime.now(UTC)
    report = await engine.run_correlation(
        session, now=now, min_confidence=get_settings().correlation_min_confidence
    )
    await engine.mark_correlation(session, now, report.created + report.updated)
    await audit.record("correlation.run", actor=user, detail=report.as_dict())
    return CorrelationRunRead(**report.as_dict())


@router.get("/{event_id}", response_model=CorrelationRead, summary="Un évènement corrélé")
async def read_correlation(event_id: UUID, session: DbSession, _: CurrentUser) -> CorrelationRead:
    try:
        event, name = await service.get_event(session, event_id)
    except service.CorrelationNotFoundError as exc:
        raise _not_found(exc) from None
    return _read(event, name)


@router.post(
    "/{event_id}/ack", response_model=CorrelationRead, summary="Acquitter (ADMIN, ANALYST)"
)
async def ack_correlation(
    event_id: UUID, session: DbSession, user: Responder, audit: Audit
) -> CorrelationRead:
    try:
        await service.acknowledge(session, event_id, user.id)
        event, name = await service.get_event(session, event_id)
    except service.CorrelationNotFoundError as exc:
        raise _not_found(exc) from None
    await audit.record(
        "correlation.ack",
        actor=user,
        target_type="correlation",
        target_id=event_id,
        detail={"rule": event.rule_id, "asset": name},
    )
    return _read(event, name)


class FalsePositiveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=5, max_length=2000)
    exclude_ioc: bool = Field(
        default=True,
        description="CORR-03 : mettre aussi l'IOC en cause en liste d'exclusion.",
    )


@router.post(
    "/{event_id}/false-positive",
    response_model=CorrelationRead,
    summary="Qualifier de faux positif (ADMIN, ANALYST) : clos, jamais rouvert (M9)",
)
async def false_positive(
    event_id: UUID,
    payload: FalsePositiveRequest,
    session: DbSession,
    user: Responder,
    audit: Audit,
) -> CorrelationRead:
    try:
        await service.mark_false_positive(
            session,
            event_id,
            user_id=user.id,
            reason=payload.reason,
            exclude_ioc=payload.exclude_ioc,
        )
        event, name = await service.get_event(session, event_id)
    except service.CorrelationNotFoundError as exc:
        raise _not_found(exc) from None
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from None
    await audit.record(
        "correlation.false_positive",
        actor=user,
        target_type="correlation",
        target_id=event_id,
        detail={"rule": event.rule_id, "asset": name, "reason": payload.reason[:200]},
    )
    return _read(event, name)


@router.post(
    "/{event_id}/incident",
    response_model=IncidentLink,
    summary="Ouvrir l'incident de réponse (idempotent)",
)
async def incident_from_correlation(
    event_id: UUID, session: DbSession, user: Responder, response: Response
) -> IncidentLink:
    try:
        incident, created = await service.open_incident(session, event_id, author_id=user.id)
    except service.CorrelationNotFoundError as exc:
        raise _not_found(exc) from None
    except (LinkTargetNotFoundError, IncidentClosedError) as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from None
    response.status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK
    return IncidentLink(incident_id=incident.id, created=created)
