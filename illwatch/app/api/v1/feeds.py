"""Routes de gestion des sources de flux — `/api/v1/feeds` (RF-04, T2.2).

Contrôle d'accès :

| Opération                  | ADMIN | ANALYST | VIEWER |
|----------------------------|:-----:|:-------:|:------:|
| Lister / consulter         |   ✅  |   ✅    |   ✅   |
| Santé, journal de collecte |   ✅  |   ✅    |   ✅   |
| Créer / modifier / supprimer |  ✅  |   ❌    |   ❌   |

L'écriture est réservée aux administrateurs : l'URL d'un flux déclenche des
requêtes sortantes depuis le serveur (surface SSRF, voir `service.py`). La
collecte elle-même (statut, dernière erreur, dernier succès) relève du worker
T2.6 ; ces champs sont en lecture seule ici.
"""

from datetime import datetime
from typing import Annotated, Self
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from illwatch.app.api.deps import Audit, CurrentUser, DbSession, require_roles
from illwatch.app.config import get_settings
from illwatch.app.models import User
from illwatch.modules.threat_feeds import runs as run_journal
from illwatch.modules.threat_feeds import service
from illwatch.modules.threat_feeds.service import (
    MAX_NAME_LENGTH,
    MAX_POLLING_INTERVAL,
    MAX_URL_LENGTH,
    MIN_POLLING_INTERVAL,
    FeedNameConflictError,
    FeedNotFoundError,
    UnsafeFeedURLError,
)
from illwatch.shared.enums import AuditOutcome, FeedStatus, FeedType, UserRole

router = APIRouter(prefix="/feeds", tags=["flux de menaces"])

AdminUser = Annotated[User, Depends(require_roles(UserRole.ADMIN))]

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200

PollingInterval = Annotated[int, Field(ge=MIN_POLLING_INTERVAL, le=MAX_POLLING_INTERVAL)]


# --- Schémas -------------------------------------------------------------------


class _FeedFieldsValidation(BaseModel):
    """Validation partagée : mêmes règles à la création et à la modification."""

    model_config = ConfigDict(extra="forbid")

    @field_validator("name", check_fields=False)
    @classmethod
    def _valid_name(cls, value: str | None) -> str | None:
        return None if value is None else service.normalize_feed_name(value)

    @field_validator("url", check_fields=False)
    @classmethod
    def _safe_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        # `UnsafeFeedURLError` hérite de `ValueError` : Pydantic la convertit en 422 et la garde
        # dans `ctx["error"]`, où le gestionnaire de validation la reconnaît pour l'auditer.
        return service.validate_feed_url(value)


class FeedCreate(_FeedFieldsValidation):
    name: str = Field(min_length=1, max_length=MAX_NAME_LENGTH)
    url: str = Field(min_length=1, max_length=MAX_URL_LENGTH)
    feed_type: FeedType
    polling_interval: PollingInterval = 3600
    is_active: bool = True


class FeedUpdate(_FeedFieldsValidation):
    """Mise à jour partielle : seuls les champs présents sont modifiés.

    `null` est refusé explicitement : aucun de ces champs n'est facultatif en
    base, et un `null` silencieusement ignoré masquerait une erreur du client.
    """

    name: str | None = Field(default=None, min_length=1, max_length=MAX_NAME_LENGTH)
    url: str | None = Field(default=None, min_length=1, max_length=MAX_URL_LENGTH)
    feed_type: FeedType | None = None
    polling_interval: PollingInterval | None = None
    is_active: bool | None = None

    @model_validator(mode="after")
    def _reject_explicit_null(self) -> Self:
        nulls = sorted(f for f in self.model_fields_set if getattr(self, f) is None)
        if nulls:
            raise ValueError(f"Valeur null interdite pour : {', '.join(nulls)}.")
        if not self.model_fields_set:
            raise ValueError("Aucun champ à modifier.")
        return self


class FeedRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    url: str
    feed_type: FeedType
    polling_interval: int
    is_active: bool
    status: FeedStatus
    last_successful_run: datetime | None
    last_error: str | None
    created_at: datetime
    updated_at: datetime


class FeedPage(BaseModel):
    items: list[FeedRead]
    total: int
    limit: int
    offset: int


REDACTED_ERROR = "Échec de la dernière collecte (détail réservé aux administrateurs)."


def _for_viewer(feed: object, user: User) -> FeedRead:
    """Le détail d'erreur d'un flux peut citer une adresse du réseau interne refusée
    (protection SSRF) : il n'est montré en clair qu'aux administrateurs."""
    read = FeedRead.model_validate(feed)
    if read.last_error and user.role != UserRole.ADMIN:
        return read.model_copy(update={"last_error": REDACTED_ERROR})
    return read


class FeedHealthRead(BaseModel):
    """Santé d'une source : état de sa collecte, jamais la dangerosité de ses IOC."""

    model_config = ConfigDict(from_attributes=True)

    feed_id: UUID
    name: str
    feed_type: FeedType
    status: FeedStatus
    is_active: bool
    last_successful_run: datetime | None
    last_error: str | None
    last_attempt_at: datetime | None
    last_duration_ms: int | None
    last_inserted: int | None
    last_updated: int | None
    last_rejected: int | None
    errors_7d: int
    runs_7d: int


class CollectionRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    feed_id: UUID
    started_at: datetime
    duration_ms: int
    succeeded: bool
    status: FeedStatus
    inserted: int
    updated: int
    rejected: int
    error: str | None
    warning: str | None


REDACTED_RUN_ERROR = "Échec de la collecte (détail réservé aux administrateurs)."


def _health_for(item: run_journal.FeedHealth, user: User) -> FeedHealthRead:
    read = FeedHealthRead.model_validate(item)
    if read.last_error and user.role != UserRole.ADMIN:
        return read.model_copy(update={"last_error": REDACTED_ERROR})
    return read


def _run_for(run: object, user: User) -> CollectionRunRead:
    read = CollectionRunRead.model_validate(run)
    if read.error and user.role != UserRole.ADMIN:
        return read.model_copy(update={"error": REDACTED_RUN_ERROR})
    return read


# --- Erreurs -------------------------------------------------------------------


def _not_found(feed_id: UUID) -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, detail=f"Flux {feed_id} introuvable.")


def _conflict(exc: FeedNameConflictError) -> HTTPException:
    return HTTPException(status.HTTP_409_CONFLICT, detail=str(exc))


def _unprocessable(exc: UnsafeFeedURLError) -> HTTPException:
    """Règle croisée URL ↔ format (ex. flux OTX hors de l'API OTX)."""
    return HTTPException(422, detail=str(exc))


# --- Routes --------------------------------------------------------------------


@router.get("", response_model=FeedPage, summary="Lister les sources de flux")
async def list_feeds(
    session: DbSession,
    user: CurrentUser,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
    offset: Annotated[int, Query(ge=0)] = 0,
    is_active: bool | None = None,
    status_filter: Annotated[FeedStatus | None, Query(alias="status")] = None,
    feed_type: FeedType | None = None,
) -> FeedPage:
    page = await service.list_feeds(
        session,
        limit=limit,
        offset=offset,
        is_active=is_active,
        status=status_filter,
        feed_type=feed_type,
    )
    return FeedPage(
        items=[_for_viewer(feed, user) for feed in page.items],
        total=page.total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/health",
    response_model=list[FeedHealthRead],
    summary="Santé de toutes les sources (écran Sources CTI)",
    description=(
        "Pour chaque source : dernière tentative et dernier succès, volumes de la dernière "
        "collecte (nouveaux, mis à jour, rejetés), nombre de collectes et d'échecs sur 7 jours."
    ),
)
async def feeds_health(session: DbSession, user: CurrentUser) -> list[FeedHealthRead]:
    return [_health_for(item, user) for item in await run_journal.feeds_health(session)]


@router.get(
    "/{feed_id}/runs",
    response_model=list[CollectionRunRead],
    summary="Journal des collectes d'une source",
)
async def feed_runs(
    feed_id: UUID,
    session: DbSession,
    user: CurrentUser,
    limit: Annotated[int, Query(ge=1, le=run_journal.MAX_RUNS_PAGE)] = 20,
) -> list[CollectionRunRead]:
    try:
        await service.get_feed(session, feed_id)
    except FeedNotFoundError:
        raise _not_found(feed_id) from None
    return [
        _run_for(run, user) for run in await run_journal.list_runs(session, feed_id, limit=limit)
    ]


@router.get("/{feed_id}", response_model=FeedRead, summary="Consulter une source de flux")
async def read_feed(feed_id: UUID, session: DbSession, user: CurrentUser) -> FeedRead:
    try:
        feed = await service.get_feed(session, feed_id)
    except FeedNotFoundError:
        raise _not_found(feed_id) from None
    return _for_viewer(feed, user)


@router.post(
    "",
    response_model=FeedRead,
    status_code=status.HTTP_201_CREATED,
    summary="Enregistrer une source de flux (ADMIN)",
)
async def create_feed(
    payload: FeedCreate, session: DbSession, admin: AdminUser, response: Response, audit: Audit
) -> FeedRead:
    try:
        feed = await service.create_feed(session, **payload.model_dump())
    except FeedNameConflictError as exc:
        raise _conflict(exc) from None
    except UnsafeFeedURLError as exc:
        await audit.record(
            "feed.create",
            AuditOutcome.FAILURE,
            actor=admin,
            detail={"reason": "unsafe_url", "url": str(payload.url), "error": str(exc)},
        )
        raise _unprocessable(exc) from None
    await audit.record(
        "feed.create",
        actor=admin,
        target_type="feed",
        target_id=feed.id,
        detail={"name": feed.name, "url": feed.url, "feed_type": feed.feed_type},
    )
    response.headers["Location"] = f"{get_settings().api_v1_prefix}{router.prefix}/{feed.id}"
    return FeedRead.model_validate(feed)


@router.patch("/{feed_id}", response_model=FeedRead, summary="Modifier une source (ADMIN)")
async def update_feed(
    feed_id: UUID, payload: FeedUpdate, session: DbSession, admin: AdminUser, audit: Audit
) -> FeedRead:
    changes = payload.model_dump(exclude_unset=True)
    try:
        feed = await service.update_feed(session, feed_id, **changes)
    except FeedNotFoundError:
        raise _not_found(feed_id) from None
    except FeedNameConflictError as exc:
        raise _conflict(exc) from None
    except UnsafeFeedURLError as exc:
        await audit.record(
            "feed.update",
            AuditOutcome.FAILURE,
            actor=admin,
            target_type="feed",
            target_id=feed_id,
            detail={"reason": "unsafe_url", "error": str(exc)},
        )
        raise _unprocessable(exc) from None
    await audit.record(
        "feed.update",
        actor=admin,
        target_type="feed",
        target_id=feed.id,
        detail={key: str(value) for key, value in changes.items()},
    )
    return FeedRead.model_validate(feed)


@router.delete(
    "/{feed_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Supprimer une source (ADMIN)",
    description=(
        "Suppression définitive de la source. Les IOC déjà collectés sont conservés, "
        "sans rattachement. Pour suspendre une collecte, préférer `PATCH` avec "
        '`{"is_active": false}`.'
    ),
)
async def delete_feed(
    feed_id: UUID, session: DbSession, admin: AdminUser, audit: Audit
) -> Response:
    try:
        await service.delete_feed(session, feed_id)
    except FeedNotFoundError:
        raise _not_found(feed_id) from None
    await audit.record("feed.delete", actor=admin, target_type="feed", target_id=feed_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
