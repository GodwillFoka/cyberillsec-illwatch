"""Campagnes : `/api/v1/campaigns` (M10, incrément 2, ADR-024).

| Opération                                          | ADMIN | ANALYST | VIEWER |
|----------------------------------------------------|:-----:|:-------:|:------:|
| Consulter les campagnes et leur infrastructure     |   ✅  |   ✅    |   ✅   |
| Créer, modifier, rattacher ou détacher des IOC     |   ✅  |   ✅    |   ❌   |
| Supprimer une campagne                             |   ✅  |   ❌    |   ❌   |
"""

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field

from illwatch.app.api.deps import Audit, CurrentUser, DbSession, require_roles
from illwatch.app.api.v1.attack import ActorRefRead
from illwatch.app.models import Campaign, User
from illwatch.modules.attack import campaigns as service
from illwatch.modules.attack.service import actor_refs
from illwatch.shared.enums import UserRole

router = APIRouter(prefix="/campaigns", tags=["campagnes"])

Contributor = Annotated[User, Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST))]
AdminUser = Annotated[User, Depends(require_roles(UserRole.ADMIN))]


class CampaignRead(BaseModel):
    id: UUID
    name: str
    description: str | None
    actor_id: str | None
    actor: ActorRefRead | None
    indicators: int
    by_type: dict[str, int]
    last_seen: datetime | None
    created_at: datetime


class CampaignIndicatorRead(BaseModel):
    id: UUID
    type: str
    value: str
    severity: str
    description: str | None
    last_seen: datetime


class CampaignDetail(CampaignRead):
    infrastructure: list[CampaignIndicatorRead] = Field(
        description="IOC rattachés, les plus récemment observés d'abord (200 au plus)."
    )


class CampaignWrite(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=3, max_length=160)
    description: str | None = Field(default=None, max_length=4000)
    actor_id: str | None = Field(
        default=None, max_length=16, description="Groupe ou logiciel ATT&CK (G0102, S0650)."
    )


class CampaignUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str | None = Field(default=None, max_length=4000)
    actor_id: str | None = Field(default=None, max_length=16)


class AttachRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    values: list[Annotated[str, Field(max_length=2048)]] = Field(
        default_factory=list, max_length=service.MAX_ATTACH
    )
    description_contains: str | None = Field(
        default=None,
        min_length=service.MIN_PATTERN,
        max_length=200,
        description="Tous les IOC dont la description (par leur source) contient ce texte.",
    )


class AttachResult(BaseModel):
    attached: int
    unknown: int


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


async def _read(session: DbSession, summary: service.CampaignSummary) -> CampaignRead:
    c = summary.campaign
    actor = None
    if c.actor_id:
        refs = await actor_refs(session, [(c.actor_id, "acteur de la campagne")])
        if refs:
            a = refs[0]
            actor = ActorRefRead(
                id=a.id, kind=a.kind, name=a.name, url=a.url, matched=a.matched, techniques=[]
            )
    return CampaignRead(
        id=c.id,
        name=c.name,
        description=c.description,
        actor_id=c.actor_id,
        actor=actor,
        indicators=summary.indicators,
        by_type=summary.by_type,
        last_seen=_utc(summary.last_seen),
        created_at=_utc(c.created_at) or c.created_at,
    )


async def _summary(session: DbSession, campaign: Campaign) -> service.CampaignSummary:
    for item in await service.list_campaigns(session):
        if item.campaign.id == campaign.id:
            return item
    return service.CampaignSummary(campaign, 0, {}, None)


def _translate(exc: Exception) -> HTTPException:
    if isinstance(exc, service.CampaignNotFoundError):
        return HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc))
    if isinstance(exc, service.CampaignExistsError):
        return HTTPException(status.HTTP_409_CONFLICT, detail=str(exc))
    return HTTPException(422, detail=str(exc))


@router.get("", response_model=list[CampaignRead], summary="Campagnes")
async def list_campaigns(session: DbSession, _: CurrentUser) -> list[CampaignRead]:
    return [await _read(session, s) for s in await service.list_campaigns(session)]


@router.post(
    "",
    response_model=CampaignRead,
    status_code=status.HTTP_201_CREATED,
    summary="Créer une campagne (ADMIN, ANALYST)",
)
async def create_campaign(
    payload: CampaignWrite, session: DbSession, user: Contributor, audit: Audit
) -> CampaignRead:
    try:
        campaign = await service.create_campaign(
            session,
            name=payload.name,
            description=payload.description,
            actor_id=payload.actor_id,
            author_id=user.id,
        )
    except (service.CampaignError, service.CampaignNotFoundError) as exc:
        raise _translate(exc) from None
    await audit.record(
        "campaign.create",
        actor=user,
        target_type="campaign",
        target_id=campaign.id,
        detail={"name": campaign.name, "actor": campaign.actor_id},
    )
    return await _read(session, await _summary(session, campaign))


@router.get("/{campaign_id}", response_model=CampaignDetail, summary="Une campagne")
async def read_campaign(campaign_id: UUID, session: DbSession, _: CurrentUser) -> CampaignDetail:
    try:
        campaign = await service.get_campaign(session, campaign_id)
    except service.CampaignNotFoundError as exc:
        raise _translate(exc) from None
    base = await _read(session, await _summary(session, campaign))
    rows = await service.campaign_indicators(session, campaign_id)
    return CampaignDetail(
        **base.model_dump(),
        infrastructure=[
            CampaignIndicatorRead(
                id=i.id,
                type=str(i.type),
                value=i.value,
                severity=str(i.severity),
                description=i.description,
                last_seen=_utc(i.last_seen) or i.last_seen,
            )
            for i in rows
        ],
    )


@router.put("/{campaign_id}", response_model=CampaignRead, summary="Modifier (ADMIN, ANALYST)")
async def update_campaign(
    campaign_id: UUID, payload: CampaignUpdate, session: DbSession, user: Contributor, audit: Audit
) -> CampaignRead:
    try:
        campaign = await service.update_campaign(
            session, campaign_id, description=payload.description, actor_id=payload.actor_id
        )
    except (service.CampaignError, service.CampaignNotFoundError) as exc:
        raise _translate(exc) from None
    await audit.record(
        "campaign.update",
        actor=user,
        target_type="campaign",
        target_id=campaign.id,
        detail={"actor": campaign.actor_id},
    )
    return await _read(session, await _summary(session, campaign))


@router.post(
    "/{campaign_id}/indicators",
    response_model=AttachResult,
    summary="Rattacher des IOC connus (valeurs ou description) : ADMIN, ANALYST",
)
async def attach(
    campaign_id: UUID, payload: AttachRequest, session: DbSession, user: Contributor, audit: Audit
) -> AttachResult:
    if not payload.values and payload.description_contains is None:
        raise HTTPException(422, detail="Fournir des valeurs ou un texte de description.")
    try:
        attached, unknown = await service.attach(
            session,
            campaign_id,
            values=payload.values,
            description_contains=payload.description_contains,
        )
    except (service.CampaignError, service.CampaignNotFoundError) as exc:
        raise _translate(exc) from None
    await audit.record(
        "campaign.attach",
        actor=user,
        target_type="campaign",
        target_id=campaign_id,
        detail={"attached": attached, "unknown": unknown},
    )
    return AttachResult(attached=attached, unknown=unknown)


@router.delete(
    "/{campaign_id}/indicators/{indicator_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Détacher un IOC : ADMIN, ANALYST",
)
async def detach(
    campaign_id: UUID, indicator_id: UUID, session: DbSession, _: Contributor
) -> Response:
    if not await service.detach(session, campaign_id, indicator_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="IOC non rattaché à la campagne.")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/{campaign_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Supprimer: ADMIN")
async def delete_campaign(
    campaign_id: UUID, session: DbSession, user: AdminUser, audit: Audit
) -> Response:
    try:
        campaign = await service.delete_campaign(session, campaign_id)
    except service.CampaignNotFoundError as exc:
        raise _translate(exc) from None
    await audit.record(
        "campaign.delete",
        actor=user,
        target_type="campaign",
        target_id=campaign_id,
        detail={"name": campaign.name},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
