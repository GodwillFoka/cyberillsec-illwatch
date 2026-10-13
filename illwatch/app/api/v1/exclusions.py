"""Liste d'exclusion des IOC — `/api/v1/exclusions` (M9, ADR-022, tâche 3.6).

| Opération                                   | ADMIN | ANALYST | VIEWER |
|---------------------------------------------|:-----:|:-------:|:------:|
| Consulter la liste                          |   ✅  |   ✅    |   ✅   |
| Exclure une valeur (faux positif qualifié)  |   ✅  |   ✅    |   ❌   |
| Retirer une exclusion                       |   ✅  |   ❌    |   ❌   |

Exclure n'efface rien : l'IOC reste en base avec sa provenance ; il cesse d'être actif (ni
compté, ni chassé, ni corrélé). Chaque exclusion et chaque retrait sont journalisés.
"""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field

from illwatch.app.api.deps import Audit, CurrentUser, DbSession, require_roles
from illwatch.app.models import Exclusion, User
from illwatch.modules.soc import exclusions as service
from illwatch.shared.enums import IndicatorType, UserRole

router = APIRouter(prefix="/exclusions", tags=["exclusions"])

Contributor = Annotated[User, Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST))]
AdminUser = Annotated[User, Depends(require_roles(UserRole.ADMIN))]


class ExclusionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    indicator_type: IndicatorType
    value: str
    reason: str
    created_by: UUID | None
    created_at: datetime
    expires_at: datetime | None
    incident_id: UUID | None


class ExclusionWrite(BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: str = Field(min_length=1, max_length=2048, description="IP, plage, domaine, URL…")
    reason: str = Field(min_length=5, max_length=service.MAX_REASON_LENGTH)
    incident_id: UUID | None = Field(
        default=None, description="Incident qui a établi le faux positif (chronologie)."
    )
    days: int | None = Field(
        default=None,
        ge=1,
        le=service.MAX_DAYS,
        description="Réexamen après N jours ; vide = sans fin.",
    )


def _read(exclusion: Exclusion) -> ExclusionRead:
    return ExclusionRead.model_validate(exclusion)


@router.get("", response_model=list[ExclusionRead], summary="Liste d'exclusion")
async def list_exclusions(
    session: DbSession,
    _: CurrentUser,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> list[ExclusionRead]:
    return [_read(e) for e in await service.list_exclusions(session, limit=limit)]


@router.post(
    "",
    response_model=ExclusionRead,
    status_code=status.HTTP_201_CREATED,
    summary="Exclure une valeur (faux positif) — ADMIN, ANALYST",
)
async def create_exclusion(
    payload: ExclusionWrite, session: DbSession, user: Contributor, audit: Audit
) -> ExclusionRead:
    try:
        exclusion = await service.create_exclusion(
            session,
            value=payload.value,
            reason=payload.reason,
            author_id=user.id,
            incident_id=payload.incident_id,
            days=payload.days,
        )
    except service.ExclusionExistsError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from None
    except service.ExclusionError as exc:
        raise HTTPException(422, detail=str(exc)) from None
    await audit.record(
        "exclusion.create",
        actor=user,
        target_type="exclusion",
        target_id=exclusion.id,
        detail={
            "type": exclusion.indicator_type,
            "value": exclusion.value[:200],
            "reason": exclusion.reason[:200],
        },
    )
    return _read(exclusion)


@router.delete(
    "/{exclusion_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Retirer une exclusion — ADMIN",
)
async def delete_exclusion(
    exclusion_id: UUID, session: DbSession, user: AdminUser, audit: Audit
) -> None:
    try:
        exclusion = await service.delete_exclusion(session, exclusion_id)
    except service.ExclusionNotFoundError:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, detail=f"Exclusion {exclusion_id} introuvable."
        ) from None
    await audit.record(
        "exclusion.delete",
        actor=user,
        target_type="exclusion",
        target_id=exclusion_id,
        detail={"type": exclusion.indicator_type, "value": exclusion.value[:200]},
    )
