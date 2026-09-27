"""Routes des indicateurs de compromission — `/api/v1/indicators` (RF-07, RF-08).

| Opération                         | ADMIN | ANALYST | VIEWER |
|-----------------------------------|:-----:|:-------:|:------:|
| Lister / consulter                |   ✅  |   ✅    |   ✅   |
| Soumettre un lot d'IOC (ingestion)|   ✅  |   ✅    |   ❌   |

Soumettre des IOC ne déclenche aucune requête sortante (contrairement à l'URL d'un
flux) : c'est le geste quotidien d'un analyste qui reporte les IOC d'un bulletin.
Il n'y a volontairement ni modification ni suppression : l'historique d'un IOC est
une donnée d'enquête. La gestion des faux positifs fera l'objet d'une évolution dédiée.
"""

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field

from sentry.app.api.deps import CurrentUser, DbSession, require_roles
from sentry.app.models import User
from sentry.modules.threat_feeds import indicators as service
from sentry.modules.threat_feeds.indicators import (
    MAX_BATCH_SIZE,
    IndicatorNotFoundError,
    Observation,
)
from sentry.modules.threat_feeds.service import FeedNotFoundError, get_feed
from sentry.shared.enums import IndicatorType, Severity, UserRole

router = APIRouter(prefix="/indicators", tags=["indicateurs (IOC)"])

Contributor = Annotated[User, Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST))]

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200


# --- Schémas -------------------------------------------------------------------


class ObservationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: str = Field(min_length=1, max_length=2048)
    type: IndicatorType | None = Field(
        default=None, description="Facultatif : si fourni, doit correspondre au type détecté."
    )
    severity: Severity = Severity.MEDIUM
    description: str | None = Field(default=None, max_length=2000)
    observed_at: datetime | None = None


class IngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ObservationIn] = Field(min_length=1, max_length=MAX_BATCH_SIZE)
    feed_id: UUID | None = Field(default=None, description="Source à laquelle rattacher le lot.")


class RejectionOut(BaseModel):
    value: str
    reason: str


class IngestResponse(BaseModel):
    received: int
    inserted: int
    updated: int
    duplicates_in_batch: int
    rejected: list[RejectionOut]


class IndicatorRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    type: IndicatorType
    value: str
    severity: Severity
    description: str | None
    hit_count: int
    first_seen: datetime
    last_seen: datetime
    expires_at: datetime | None
    is_active: bool
    feed_id: UUID | None


class IndicatorPage(BaseModel):
    items: list[IndicatorRead]
    total: int
    limit: int
    offset: int


def _to_read(indicator: object, now: datetime) -> IndicatorRead:
    expires_at = getattr(indicator, "expires_at", None)
    if expires_at is not None and expires_at.tzinfo is None:  # SQLite rend des dates naïves
        expires_at = expires_at.replace(tzinfo=UTC)
    data = IndicatorRead.model_validate(
        {
            **{f: getattr(indicator, f) for f in IndicatorRead.model_fields if f != "is_active"},
            "is_active": expires_at is None or expires_at > now,
        }
    )
    return data


# --- Routes --------------------------------------------------------------------


@router.get("", response_model=IndicatorPage, summary="Lister les IOC")
async def list_indicators(
    session: DbSession,
    _: CurrentUser,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
    offset: Annotated[int, Query(ge=0)] = 0,
    ioc_type: Annotated[IndicatorType | None, Query(alias="type")] = None,
    severity: Severity | None = None,
    min_severity: Severity | None = None,
    feed_id: UUID | None = None,
    active: Annotated[
        bool | None, Query(description="true : non expirés ; false : expirés.")
    ] = None,
    value: Annotated[
        str | None,
        Query(max_length=2048, description="Recherche exacte, après normalisation."),
    ] = None,
) -> IndicatorPage:
    now = datetime.now(UTC)
    page = await service.list_indicators(
        session,
        limit=limit,
        offset=offset,
        now=now,
        ioc_type=ioc_type,
        severity=severity,
        min_severity=min_severity,
        feed_id=feed_id,
        active=active,
        value=value,
    )
    return IndicatorPage(
        items=[_to_read(i, now) for i in page.items], total=page.total, limit=limit, offset=offset
    )


@router.get("/{indicator_id}", response_model=IndicatorRead, summary="Consulter un IOC")
async def read_indicator(indicator_id: UUID, session: DbSession, _: CurrentUser) -> IndicatorRead:
    try:
        indicator = await service.get_indicator(session, indicator_id)
    except IndicatorNotFoundError:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, detail=f"IOC {indicator_id} introuvable."
        ) from None
    return _to_read(indicator, datetime.now(UTC))


@router.post(
    "",
    response_model=IngestResponse,
    summary="Soumettre un lot d'IOC (ADMIN, ANALYST)",
    description=(
        "Normalise, valide et déduplique jusqu'à 1 000 observations. Un IOC déjà connu "
        "n'est pas dupliqué : `last_seen`, `hit_count`, la sévérité maximale et "
        "`expires_at` sont mis à jour. Les valeurs invalides sont listées dans `rejected`."
    ),
)
async def ingest(payload: IngestRequest, session: DbSession, _: Contributor) -> IngestResponse:
    if payload.feed_id is not None:
        try:
            await get_feed(session, payload.feed_id)
        except FeedNotFoundError:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND, detail=f"Flux {payload.feed_id} introuvable."
            ) from None

    result = await service.ingest_indicators(
        session,
        (Observation(**item.model_dump()) for item in payload.items),
        feed_id=payload.feed_id,
    )
    return IngestResponse(
        received=result.received,
        inserted=result.inserted,
        updated=result.updated,
        duplicates_in_batch=result.duplicates_in_batch,
        rejected=[RejectionOut(value=r.value, reason=r.reason) for r in result.rejected],
    )
