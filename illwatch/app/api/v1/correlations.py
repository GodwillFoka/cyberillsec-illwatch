"""Évènements corrélés : `/api/v1/correlations` (M8, ADR-020).

Lecture pour tous ; acquittement, ouverture d'incident et passe manuelle de corrélation pour
ADMIN et ANALYST (consignés au journal d'audit).
"""

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.api.deps import Audit, CurrentUser, DbSession, require_roles
from illwatch.app.api.v1.attack import AttackContextRead, attack_context
from illwatch.app.config import get_settings
from illwatch.app.models import CVE, Asset, CorrelatedEvent, User
from illwatch.modules.attack.service import TechniqueRef, actor_index
from illwatch.modules.correlation import engine
from illwatch.modules.correlation import events as service
from illwatch.modules.correlation.explain import AssetFacts, CveFacts, explain
from illwatch.modules.incidents.service import IncidentClosedError, LinkTargetNotFoundError
from illwatch.shared.enums import CorrelationRule, RiskPriority, UserRole

router = APIRouter(prefix="/correlations", tags=["corrélation"])

Responder = Annotated[User, Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST))]

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200


class FactorRead(BaseModel):
    key: str = Field(description="rule, criticality, exposure, exploitation, version, confidence")
    label: str
    value: str
    effect: Literal["raises", "lowers", "neutral", "check"] = Field(
        description="Pousse la priorité, la modère, sans effet, ou reste à vérifier."
    )
    points: float | None = Field(description="Part du score, quand le facteur en a une.")


class ExplanationRead(BaseModel):
    summary: str = Field(description="Pourquoi cet évènement a sa priorité, en une phrase.")
    deadline: datetime | None = Field(description="Quand agir au plus tard.")
    deadline_reason: str
    factors: list[FactorRead]
    to_check: list[str] = Field(description="Ce qu'il faut vérifier avant d'agir.")


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
    attack: AttackContextRead | None = Field(
        default=None, description="Technique ATT&CK de la règle, acteurs cités (M10)."
    )
    explanation: ExplanationRead | None = Field(
        default=None,
        description=(
            "Priorisation expliquée (ADR-030) : criticité, exposition, exploitation, version, "
            "échéance et points à vérifier."
        ),
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


async def _reads(
    session: AsyncSession, pairs: Sequence[tuple[CorrelatedEvent, str]]
) -> list[CorrelationRead]:
    """Évènements avec leur contexte ATT&CK (index des acteurs lu une fois par page)."""
    index = await actor_index(session) if pairs else None
    memo: dict[str, tuple[TechniqueRef, ...]] = {}
    asset_ids = sorted({e.asset_id for e, _ in pairs})
    cve_ids = sorted({e.cve_id for e, _ in pairs if e.cve_id})
    assets = (
        {a.id: a for a in (await session.scalars(select(Asset).where(Asset.id.in_(asset_ids))))}
        if asset_ids
        else {}
    )
    cves = (
        {c.id: c for c in (await session.scalars(select(CVE).where(CVE.id.in_(cve_ids))))}
        if cve_ids
        else {}
    )
    out = []
    for event, name in pairs:
        item = _read(event, name)
        detail = event.detail or {}
        item.explanation = _explanation(event, assets.get(event.asset_id), cves)
        item.attack = await attack_context(
            session,
            rule_ids=[event.rule_id],
            texts=[str(detail.get("description") or ""), event.title],
            memo=memo,
            index=index,
            indicator_ids=[event.indicator_id],
        )
        out.append(item)
    return out


def _explanation(
    event: CorrelatedEvent, asset: Asset | None, cves: dict[str, CVE]
) -> ExplanationRead | None:
    if asset is None:
        return None
    cve = cves.get(event.cve_id) if event.cve_id else None
    facts = (
        CveFacts(
            cve_id=cve.id,
            cvss=None if cve.cvss_score is None else float(cve.cvss_score),
            epss=None if cve.epss_score is None else float(cve.epss_score),
            epss_percentile=None if cve.epss_percentile is None else float(cve.epss_percentile),
            is_kev=cve.is_kev,
            kev_date_added=cve.kev_date_added,
            kev_due_date=cve.kev_due_date,
            has_public_exploit=cve.has_public_exploit,
            has_ransomware_campaign=cve.has_ransomware_campaign,
        )
        if cve is not None
        else None
    )
    result = explain(
        rule_id=event.rule_id,
        priority=event.priority,
        score=float(event.score),
        first_seen=_utc(event.first_seen) or event.first_seen,
        detail=event.detail or {},
        asset=AssetFacts(
            name=asset.name,
            criticality=asset.criticality,
            version=asset.version,
            platform=asset.platform,
            addresses=tuple(asset.addresses or ()),
            domains=tuple(asset.domains or ()),
        ),
        cve=facts,
    )
    return ExplanationRead.model_validate(result.public())


async def _read_one(session: AsyncSession, event: CorrelatedEvent, name: str) -> CorrelationRead:
    return (await _reads(session, [(event, name)]))[0]


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
        items=await _reads(session, page.items), total=page.total, limit=limit, offset=offset
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
    return await _read_one(session, event, name)


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
    return await _read_one(session, event, name)


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
    return await _read_one(session, event, name)


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
