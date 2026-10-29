"""Inventaire d'actifs: `/api/v1/assets` (M8, ADR-020).

| Opération              | ADMIN | ANALYST | VIEWER |
|------------------------|:-----:|:-------:|:------:|
| Lister                 |   ✅  |   ✅    |   ✅   |
| Créer / modifier       |   ✅  |   ✅    |   ❌   |
| Supprimer              |   ✅  |   ❌    |   ❌   |
| Importer, exporter     |   ✅  |   ✅    |   ❌   |
| Modèle de fichier      |   ✅  |   ✅    |   ✅   |

Chaque écriture est consignée au journal d'audit (`asset.*`), chaque export aussi
(`data.export`) : l'inventaire décrit la surface exposée de l'organisation.
"""

from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, File, HTTPException, Query, Response, UploadFile, status
from pydantic import BaseModel, ConfigDict, Field

from illwatch.app.api.deps import Audit, CurrentUser, DbSession, require_roles
from illwatch.app.models import Asset, User
from illwatch.modules.correlation import assets as service
from illwatch.modules.correlation import inventory_file
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
    platform: str | None
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
    platform: str | None = Field(
        default=None,
        max_length=80,
        description="Système hôte (« Debian 12 ») : tranche les CVE propres à une plateforme.",
    )
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


# --- Import et export en fichier (ADR-028) ---------------------------------------------------


class AssetImportRowRead(BaseModel):
    line: int = Field(description="Numéro de ligne dans le fichier (l'en-tête est la ligne 1).")
    name: str
    action: Literal["create", "update"] | None = Field(
        description="Action prévue ou faite ; vide si la ligne est refusée."
    )
    error: str | None = Field(description="Motif du refus, à corriger dans le fichier.")


class AssetImportRead(BaseModel):
    applied: bool = Field(description="Faux pour un aperçu, ou si une ligne est refusée.")
    created: int
    updated: int
    rejected: int
    columns: list[str] = Field(description="Colonnes reconnues dans l'en-tête.")
    rows: list[AssetImportRowRead]


FileFormat = Annotated[Literal["xlsx", "csv"], Query(alias="format")]


def _file_response(content: bytes, fmt: str, stem: str) -> Response:
    stamp = datetime.now(UTC).strftime("%Y%m%d")
    media = inventory_file.XLSX_MEDIA_TYPE if fmt == "xlsx" else "text/csv; charset=utf-8"
    return Response(
        content,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{stem}-{stamp}.{fmt}"'},
    )


@router.post(
    "/import",
    response_model=AssetImportRead,
    summary="Importer un inventaire Excel ou CSV : aperçu puis import (ADMIN, ANALYST)",
)
async def import_assets(
    session: DbSession,
    user: Contributor,
    audit: Audit,
    file: Annotated[UploadFile, File(description="Fichier .xlsx ou .csv, une ligne par actif.")],
    apply: Annotated[
        bool, Query(description="Faux : aperçu sans écriture. Vrai : import, tout ou rien.")
    ] = False,
) -> AssetImportRead:
    content = await file.read(inventory_file.MAX_FILE_BYTES + 1)
    if len(content) > inventory_file.MAX_FILE_BYTES:
        raise HTTPException(
            status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"Fichier trop volumineux : {inventory_file.MAX_FILE_BYTES // (1024 * 1024)} Mo "
            "au plus.",
        )
    try:
        parsed = inventory_file.read_inventory(content, file.filename or "")
        report = await inventory_file.import_inventory(session, parsed, apply=apply)
    except inventory_file.InventoryFileError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from None
    if report.applied:
        await audit.record(
            "asset.import",
            actor=user,
            target_type="asset",
            detail={
                "file": (file.filename or "")[:120],
                "created": report.created,
                "updated": report.updated,
            },
        )
    return AssetImportRead(
        applied=report.applied,
        created=report.created,
        updated=report.updated,
        rejected=report.rejected,
        columns=[c for c in inventory_file.COLUMNS if c in parsed.columns],
        rows=[
            AssetImportRowRead(
                line=r.line,
                name=r.name,
                action="create" if r.action == "create" else "update" if r.action else None,
                error=r.error,
            )
            for r in report.rows
        ],
    )


@router.get(
    "/export",
    summary="Exporter l'inventaire en Excel ou CSV, réimportable (ADMIN, ANALYST)",
    response_class=Response,
)
async def export_assets(
    session: DbSession, user: Contributor, audit: Audit, fmt: FileFormat = "xlsx"
) -> Response:
    assets = await service.list_assets(session)
    await audit.record(
        "data.export",
        actor=user,
        target_type="dataset",
        target_id="assets",
        detail={"format": fmt, "rows": len(assets)},
    )
    content = (
        inventory_file.inventory_xlsx(assets)
        if fmt == "xlsx"
        else inventory_file.inventory_csv(assets)
    )
    return _file_response(content, fmt, "illwatch-inventaire")


@router.get(
    "/template",
    summary="Modèle de fichier d'inventaire à remplir (Excel ou CSV)",
    response_class=Response,
)
async def inventory_template(_: CurrentUser, fmt: FileFormat = "xlsx") -> Response:
    content = inventory_file.template_xlsx() if fmt == "xlsx" else inventory_file.template_csv()
    return _file_response(content, fmt, "illwatch-modele-inventaire")
