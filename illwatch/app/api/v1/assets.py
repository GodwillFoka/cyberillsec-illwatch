"""Inventaire d'actifs — `/api/v1/assets` (M8, ADR-020).

| Opération              | ADMIN | ANALYST | VIEWER |
|------------------------|:-----:|:-------:|:------:|
| Lister                 |   ✅  |   ✅    |   ✅   |
| Créer / modifier       |   ✅  |   ✅    |   ❌   |
| Supprimer              |   ✅  |   ❌    |   ❌   |

Chaque écriture est consignée au journal d'audit (`asset.*`).
"""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field

from illwatch.app.api.deps import Audit, CurrentUser, DbSession, require_roles
from illwatch.app.models import Asset, User
from illwatch.modules.correlation import assets as service
from illwatch.shared.enums import Severity, UserRole

router = APIRouter(prefix="/assets", tags=["corrélation"])

Contributor = Annotated[User, Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST))]
AdminUser = Annotated[User, Depends(require_roles(UserRole.ADMIN))]


class AssetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    product: str
    vendor: str | None
    version: str | None
    criticality: Severity
    addresses: list[str]
    domains: list[str]
    notes: str | None
    is_active: bool
    created_at: datetime
    updated_at: datetime


class AssetWrite(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    product: str = Field(
        min_length=3,
        max_length=120,
        description="Nom du produit tel qu'il apparaît dans les avis (« FortiOS »).",
    )
    vendor: str | None = Field(default=None, max_length=120)
    version: str | None = Field(default=None, max_length=60)
    criticality: Severity = Severity.MEDIUM
    addresses: list[str] = Field(default_factory=list, max_length=service.MAX_ENTRIES)
    domains: list[str] = Field(default_factory=list, max_length=service.MAX_ENTRIES)
    notes: str | None = Field(default=None, max_length=2000)
    is_active: bool = True


def _input(payload: AssetWrite) -> service.AssetInput:
    return service.AssetInput(
        **{
            **payload.model_dump(),
            "addresses": tuple(payload.addresses),
            "domains": tuple(payload.domains),
        }
    )


def _read(asset: Asset) -> AssetRead:
    return AssetRead.model_validate(asset)


@router.get("", response_model=list[AssetRead], summary="Inventaire d'actifs")
async def list_assets(session: DbSession, _: CurrentUser) -> list[AssetRead]:
    return [_read(a) for a in await service.list_assets(session)]


@router.post(
    "",
    response_model=AssetRead,
    status_code=status.HTTP_201_CREATED,
    summary="Déclarer un actif (ADMIN, ANALYST)",
)
async def create_asset(
    payload: AssetWrite, session: DbSession, user: Contributor, audit: Audit
) -> AssetRead:
    try:
        asset = await service.create_asset(session, _input(payload))
    except service.AssetExistsError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from None
    except service.AssetError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from None
    await audit.record(
        "asset.create",
        actor=user,
        target_type="asset",
        target_id=asset.id,
        detail={"name": asset.name, "product": asset.product},
    )
    return _read(asset)


@router.put("/{asset_id}", response_model=AssetRead, summary="Modifier un actif (ADMIN, ANALYST)")
async def update_asset(
    asset_id: UUID, payload: AssetWrite, session: DbSession, user: Contributor, audit: Audit
) -> AssetRead:
    try:
        asset = await service.update_asset(session, asset_id, _input(payload))
    except service.AssetNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from None
    except service.AssetExistsError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from None
    except service.AssetError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from None
    await audit.record(
        "asset.update",
        actor=user,
        target_type="asset",
        target_id=asset.id,
        detail={"name": asset.name, "product": asset.product, "active": asset.is_active},
    )
    return _read(asset)


@router.delete(
    "/{asset_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Supprimer un actif et ses évènements corrélés (ADMIN)",
)
async def delete_asset(
    asset_id: UUID, session: DbSession, user: AdminUser, audit: Audit
) -> Response:
    try:
        asset = await service.delete_asset(session, asset_id)
    except service.AssetNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from None
    await audit.record(
        "asset.delete",
        actor=user,
        target_type="asset",
        target_id=asset_id,
        detail={"name": asset.name},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
