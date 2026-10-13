"""Inventaire d'actifs — M8, ADR-020. Saisi par les analystes (API, écran Inventaire, CLI).

Chaque champ est normalisé à l'écriture : la corrélation compare ensuite des valeurs propres
(adresses IP canoniques, domaines en minuscules sans point final).
"""

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import Asset
from illwatch.modules.threat_feeds.validators import InvalidIndicatorError, normalize_indicator
from illwatch.shared.enums import IndicatorType, Severity

MIN_PRODUCT_LENGTH = 3
MAX_ENTRIES = 200


class AssetError(ValueError):
    """Saisie refusée (message destiné à l'analyste)."""


class AssetNotFoundError(LookupError):
    pass


class AssetExistsError(AssetError):
    pass


@dataclass(frozen=True)
class AssetInput:
    name: str
    product: str
    vendor: str | None = None
    version: str | None = None
    criticality: Severity = Severity.MEDIUM
    addresses: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    notes: str | None = None
    is_active: bool = True


def _clean(text: str | None, limit: int) -> str | None:
    value = " ".join((text or "").split())
    return value[:limit] or None


def normalize_addresses(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    for raw in values:
        value = str(raw).strip()
        if not value:
            continue
        try:
            canonical = str(ipaddress.ip_address(value))
        except ValueError:
            raise AssetError(f"« {value} » n'est pas une adresse IP.") from None
        if canonical not in out:
            out.append(canonical)
    if len(out) > MAX_ENTRIES:
        raise AssetError(f"{MAX_ENTRIES} adresses au plus par actif.")
    return out


def normalize_domains(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    for raw in values:
        value = str(raw).strip()
        if not value:
            continue
        try:
            kind, canonical = normalize_indicator(value)
        except (InvalidIndicatorError, ValueError):
            raise AssetError(f"« {value} » n'est pas un nom de domaine.") from None
        if kind is not IndicatorType.DOMAIN:
            raise AssetError(f"« {value} » n'est pas un nom de domaine.")
        if canonical not in out:
            out.append(canonical)
    if len(out) > MAX_ENTRIES:
        raise AssetError(f"{MAX_ENTRIES} domaines au plus par actif.")
    return out


def _apply(asset: Asset, data: AssetInput) -> None:
    name = _clean(data.name, 120)
    product = _clean(data.product, 120)
    if not name:
        raise AssetError("Nom de l'actif obligatoire.")
    if not product or len(product) < MIN_PRODUCT_LENGTH:
        raise AssetError(
            f"Produit obligatoire ({MIN_PRODUCT_LENGTH} caractères au moins), tel qu'il apparaît "
            f"dans les avis de sécurité : « FortiOS », « Exchange Server », « Confluence »."
        )
    asset.name = name
    asset.product = product
    asset.vendor = _clean(data.vendor, 120)
    asset.version = _clean(data.version, 60)
    asset.criticality = Severity(data.criticality).value
    asset.addresses = normalize_addresses(data.addresses)
    asset.domains = normalize_domains(data.domains)
    asset.notes = (data.notes or "").strip()[:2000] or None
    asset.is_active = data.is_active


async def list_assets(session: AsyncSession) -> list[Asset]:
    return list((await session.scalars(select(Asset).order_by(Asset.name))).all())


async def get_asset(session: AsyncSession, asset_id: UUID) -> Asset:
    asset = await session.get(Asset, asset_id)
    if asset is None:
        raise AssetNotFoundError(f"Actif {asset_id} introuvable.")
    return asset


async def find_asset(session: AsyncSession, name: str) -> Asset | None:
    return await session.scalar(select(Asset).where(Asset.name == " ".join(name.split())))


async def create_asset(session: AsyncSession, data: AssetInput) -> Asset:
    asset = Asset()
    _apply(asset, data)
    if await find_asset(session, asset.name) is not None:
        raise AssetExistsError(f"Un actif nommé « {asset.name} » existe déjà.")
    session.add(asset)
    try:
        await session.flush()
    except IntegrityError:
        raise AssetExistsError(f"Un actif nommé « {asset.name} » existe déjà.") from None
    return asset


async def update_asset(session: AsyncSession, asset_id: UUID, data: AssetInput) -> Asset:
    asset = await get_asset(session, asset_id)
    # Doublon vérifié AVANT de modifier l'objet : sinon la requête de contrôle déclencherait
    # l'écriture du nouveau nom et l'erreur d'unicité de la base au lieu d'un refus lisible.
    other = await find_asset(session, data.name)
    if other is not None and other.id != asset.id:
        raise AssetExistsError(f"Un actif nommé « {' '.join(data.name.split())} » existe déjà.")
    _apply(asset, data)
    await session.flush()
    return asset


async def delete_asset(session: AsyncSession, asset_id: UUID) -> Asset:
    """Supprime l'actif et ses évènements corrélés (les incidents ouverts restent)."""
    asset = await get_asset(session, asset_id)
    await session.delete(asset)
    await session.flush()
    return asset
