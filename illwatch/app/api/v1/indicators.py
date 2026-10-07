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

from illwatch.app.api.deps import Audit, CurrentUser, DbSession, require_roles
from illwatch.app.models import Indicator, User
from illwatch.modules.threat_feeds import indicators as service
from illwatch.modules.threat_feeds.indicators import (
    MAX_BATCH_SIZE,
    IndicatorNotFoundError,
    Observation,
)
from illwatch.modules.threat_feeds.service import FeedNotFoundError, get_feed
from illwatch.shared.enums import IndicatorType, Severity, UserRole

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
    rejected_count: int
    rejected: list[RejectionOut] = Field(description="Échantillon (100 premiers rejets au plus).")


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
    feed_id: UUID | None = Field(description="Première source connue.")
    source_count: int = Field(description="Nombre de flux distincts ayant rapporté l'IOC.")


class IndicatorSourceRead(BaseModel):
    feed_id: UUID
    feed_name: str
    first_seen: datetime
    last_seen: datetime
    hit_count: int


class IndicatorDetail(IndicatorRead):
    sources: list[IndicatorSourceRead] = Field(
        description="Provenance : chaque flux ayant rapporté l'IOC (ADR-006)."
    )


class IndicatorPage(BaseModel):
    items: list[IndicatorRead]
    total: int
    limit: int
    offset: int


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)  # SQLite : naïf


_COMPUTED = {"is_active", "source_count"}


def _to_read(indicator: Indicator, now: datetime, source_count: int) -> IndicatorRead:
    expires_at = indicator.expires_at
    return IndicatorRead.model_validate(
        {
            **{f: getattr(indicator, f) for f in IndicatorRead.model_fields if f not in _COMPUTED},
            "is_active": expires_at is None or _utc(expires_at) > now,
            "source_count": source_count,
        }
    )


def _to_detail(indicator: Indicator, now: datetime) -> IndicatorDetail:
    sources = [
        IndicatorSourceRead(
            feed_id=s.feed_id,
            feed_name=s.feed.name,
            first_seen=_utc(s.first_seen),
            last_seen=_utc(s.last_seen),
            hit_count=s.hit_count,
        )
        for s in indicator.sources
    ]
    base = _to_read(indicator, now, len(sources))
    return IndicatorDetail(**base.model_dump(), sources=sources)


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
    counts = await service.source_counts(session, [i.id for i in page.items])
    return IndicatorPage(
        items=[_to_read(i, now, counts.get(i.id, 0)) for i in page.items],
        total=page.total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{indicator_id}", response_model=IndicatorDetail, summary="Consulter un IOC et sa provenance"
)
async def read_indicator(indicator_id: UUID, session: DbSession, _: CurrentUser) -> IndicatorDetail:
    try:
        indicator = await service.get_indicator(session, indicator_id)
    except IndicatorNotFoundError:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, detail=f"IOC {indicator_id} introuvable."
        ) from None
    return _to_detail(indicator, datetime.now(UTC))


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
async def ingest(
    payload: IngestRequest, session: DbSession, user: Contributor, audit: Audit
) -> IngestResponse:
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
    await audit.record(
        "indicator.submit",
        actor=user,
        target_type="feed" if payload.feed_id else None,
        target_id=payload.feed_id,
        detail={
            "received": result.received,
            "inserted": result.inserted,
            "updated": result.updated,
            "rejected": result.rejected_count,
        },
    )
    return IngestResponse(
        received=result.received,
        inserted=result.inserted,
        updated=result.updated,
        duplicates_in_batch=result.duplicates_in_batch,
        rejected_count=result.rejected_count,
        rejected=[RejectionOut(value=r.value, reason=r.reason) for r in result.rejected],
    )
