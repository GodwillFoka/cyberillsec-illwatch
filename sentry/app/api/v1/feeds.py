"""Routes de gestion des sources de flux — `/api/v1/feeds` (RF-04, T2.2).

Contrôle d'accès :

| Opération                  | ADMIN | ANALYST | VIEWER |
|----------------------------|:-----:|:-------:|:------:|
| Lister / consulter         |   ✅  |   ✅    |   ✅   |
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

from sentry.app.api.deps import CurrentUser, DbSession, require_roles
from sentry.app.config import get_settings
from sentry.app.models import User
from sentry.modules.threat_feeds import service
from sentry.modules.threat_feeds.service import (
    MAX_NAME_LENGTH,
    MAX_POLLING_INTERVAL,
    MAX_URL_LENGTH,
    MIN_POLLING_INTERVAL,
    FeedNameConflictError,
    FeedNotFoundError,
    UnsafeFeedURLError,
)
from sentry.shared.enums import FeedStatus, FeedType, UserRole

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
        try:
            return service.validate_feed_url(value)
        except UnsafeFeedURLError as exc:
            raise ValueError(str(exc)) from exc


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


# --- Erreurs -------------------------------------------------------------------


def _not_found(feed_id: UUID) -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, detail=f"Flux {feed_id} introuvable.")


def _conflict(exc: FeedNameConflictError) -> HTTPException:
    return HTTPException(status.HTTP_409_CONFLICT, detail=str(exc))


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
    payload: FeedCreate, session: DbSession, _: AdminUser, response: Response
) -> FeedRead:
    try:
        feed = await service.create_feed(session, **payload.model_dump())
    except FeedNameConflictError as exc:
        raise _conflict(exc) from None
    response.headers["Location"] = f"{get_settings().api_v1_prefix}{router.prefix}/{feed.id}"
    return FeedRead.model_validate(feed)


@router.patch("/{feed_id}", response_model=FeedRead, summary="Modifier une source (ADMIN)")
async def update_feed(
    feed_id: UUID, payload: FeedUpdate, session: DbSession, _: AdminUser
) -> FeedRead:
    try:
        feed = await service.update_feed(session, feed_id, **payload.model_dump(exclude_unset=True))
    except FeedNotFoundError:
        raise _not_found(feed_id) from None
    except FeedNameConflictError as exc:
        raise _conflict(exc) from None
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
async def delete_feed(feed_id: UUID, session: DbSession, _: AdminUser) -> Response:
    try:
        await service.delete_feed(session, feed_id)
    except FeedNotFoundError:
        raise _not_found(feed_id) from None
    return Response(status_code=status.HTTP_204_NO_CONTENT)
