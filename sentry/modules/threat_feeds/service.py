"""Service de gestion des sources de flux — RF-04 (CRUD), MOD-02.

Logique métier pure : aucune dépendance à HTTP ni à la CLI, pour que l'API
(`/api/v1/feeds`) et la future commande `sentry feeds` (T2.7) partagent
exactement les mêmes règles.

Sécurité : l'URL d'un flux est une adresse que le serveur ira lui-même
contacter (T2.3). Enregistrer une URL revient donc à piloter une requête
sortante depuis l'infrastructure SENTRY : c'est la surface d'attaque SSRF
(Server-Side Request Forgery). La validation ci-dessous refuse tout ce qui
vise le réseau interne *tel qu'écrit dans l'URL*. Elle ne suffit pas seule :
un nom de domaine public peut résoudre vers une adresse privée (DNS
rebinding). Le collecteur de T2.3 devra revérifier l'adresse IP résolue au
moment de chaque requête.
"""

import ipaddress
import re
from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit
from uuid import UUID

from sqlalchemy import ColumnElement, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app.models import ThreatFeed
from sentry.modules.threat_feeds.secrets import KNOWN_PLACEHOLDERS, placeholders
from sentry.shared.enums import FeedStatus, FeedType

MIN_POLLING_INTERVAL = 60
MAX_POLLING_INTERVAL = 7 * 24 * 3600
MAX_NAME_LENGTH = 100  # threat_feeds.name VARCHAR(100)
MAX_URL_LENGTH = 500  # threat_feeds.url VARCHAR(500)
ALLOWED_URL_SCHEMES = frozenset({"https"})

# L'API OTX reçoit la clé OTX_API_KEY en en-tête : un flux OTX ne peut viser que cet hôte,
# sinon un administrateur (ou un compte ADMIN compromis) pourrait exfiltrer la clé.
OTX_HOST = "otx.alienvault.com"

_FORBIDDEN_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa")
_HOST_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class FeedNotFoundError(LookupError):
    """Aucun flux ne porte cet identifiant."""


class FeedNameConflictError(ValueError):
    """Un flux porte déjà ce nom (comparaison insensible à la casse)."""


class UnsafeFeedURLError(ValueError):
    """URL refusée : schéma non autorisé, identifiants embarqués ou cible interne."""


@dataclass(frozen=True, slots=True)
class FeedPage:
    """Page de résultats d'une liste de flux."""

    items: Sequence[ThreatFeed]
    total: int


# --- Validation ----------------------------------------------------------------


_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def is_internal_ip(host: str) -> bool:
    """Vrai pour toute adresse qui n'est pas routable publiquement sur Internet.

    Liste blanche plutôt que liste noire : seule une adresse `is_global` est admise.
    Cela couvre aussi les plages oubliées par `is_private`, dont 100.64.0.0/10 (CGNAT,
    où Alibaba Cloud expose ses métadonnées en 100.100.100.200). Les adresses IPv4
    embarquées dans de l'IPv6 (::ffff:a.b.c.d, NAT64 64:ff9b::/96, 6to4 2002::/16) sont
    jugées sur l'adresse IPv4 qu'elles désignent réellement.
    """
    try:
        addr: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        elif addr in _NAT64:
            addr = ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
        elif addr.sixtofour is not None:
            addr = addr.sixtofour
    return not addr.is_global or addr.is_multicast


def validate_feed_url(url: str, *, max_length: int = MAX_URL_LENGTH) -> str:
    """Valide et normalise l'URL d'un flux. Retourne l'URL nettoyée.

    Règles :
      * HTTPS uniquement : un flux en clair peut être falsifié en transit
        (injection de faux IOC) — RNF-SEC-01 ;
      * aucun identifiant dans l'URL (`https://user:pass@…`) : un secret n'a
        rien à faire dans une colonne lisible par tous les rôles ;
      * hôte public : pas d'IP privée, de loopback, de link-local (dont
        169.254.169.254, service de métadonnées cloud), ni de nom local ;
      * nom d'hôte bien formé avec un TLD alphabétique : bloque les formes
        numériques ambiguës (`2130706433`, `0x7f.1`) que les résolveurs
        convertissent en 127.0.0.1.

    Raises:
        UnsafeFeedURLError: au premier critère non respecté.
    """
    candidate = url.strip()
    if not candidate:
        raise UnsafeFeedURLError("URL vide.")
    if len(candidate) > max_length:
        raise UnsafeFeedURLError(f"URL trop longue (> {max_length} caractères).")

    try:
        parts = urlsplit(candidate)
        hostname = parts.hostname
        _ = parts.port  # lève ValueError si le port est invalide
    except ValueError as exc:
        raise UnsafeFeedURLError(f"URL malformée : {exc}") from exc

    if parts.scheme.lower() not in ALLOWED_URL_SCHEMES:
        raise UnsafeFeedURLError("Seules les URL HTTPS sont acceptées.")
    if parts.username is not None or parts.password is not None:
        raise UnsafeFeedURLError("Les identifiants ne doivent pas figurer dans l'URL.")
    if not hostname:
        raise UnsafeFeedURLError("URL sans nom d'hôte.")

    host = hostname.rstrip(".").lower()
    if is_internal_ip(host):
        raise UnsafeFeedURLError("Adresse IP interne ou réservée interdite.")
    if host == "localhost" or host.endswith(_FORBIDDEN_HOST_SUFFIXES):
        raise UnsafeFeedURLError("Nom d'hôte local interdit.")

    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if (
            len(labels) < 2
            or not all(_HOST_LABEL_RE.match(label) for label in labels)
            or not labels[-1].isalpha()
        ):
            raise UnsafeFeedURLError("Nom d'hôte invalide.") from None

    unknown = sorted(set(placeholders(candidate)) - KNOWN_PLACEHOLDERS)
    if unknown:
        raise UnsafeFeedURLError(
            f"Paramètre d'URL inconnu : {', '.join('{' + u + '}' for u in unknown)}. "
            f"Autorisés : {', '.join('{' + k + '}' for k in sorted(KNOWN_PLACEHOLDERS))}."
        )
    return candidate


def normalize_feed_name(name: str) -> str:
    cleaned = " ".join(name.split())
    if not cleaned:
        raise ValueError("Le nom du flux est obligatoire.")
    if len(cleaned) > MAX_NAME_LENGTH:
        raise ValueError(f"Le nom du flux dépasse {MAX_NAME_LENGTH} caractères.")
    return cleaned


# --- Accès aux données ---------------------------------------------------------


async def _ensure_name_available(
    session: AsyncSession, name: str, *, exclude_id: UUID | None = None
) -> None:
    query = select(ThreatFeed.id).where(func.lower(ThreatFeed.name) == name.lower())
    if exclude_id is not None:
        query = query.where(ThreatFeed.id != exclude_id)
    if (await session.execute(query)).first() is not None:
        raise FeedNameConflictError(f"Un flux nommé « {name} » existe déjà.")


async def _flush_or_conflict(
    session: AsyncSession, name: str, *, new: ThreatFeed | None = None
) -> None:
    """Flush dans un point de sauvegarde : une violation d'unicité concurrente
    (deux créations simultanées du même nom) devient un conflit métier propre
    sans invalider la transaction de la requête.

    Le nouvel objet est ajouté *dans* le point de sauvegarde : `begin_nested()`
    vide la session avant de l'ouvrir, un objet ajouté avant serait inséré hors
    de sa protection et l'échec ferait avorter toute la transaction.
    """
    try:
        async with session.begin_nested():
            if new is not None:
                session.add(new)
            await session.flush()
    except IntegrityError as exc:
        raise FeedNameConflictError(f"Un flux nommé « {name} » existe déjà.") from exc


async def get_feed(session: AsyncSession, feed_id: UUID) -> ThreatFeed:
    # populate_existing : jamais d'objet partiellement périmé (colonnes recalculées par la base)
    feed = await session.get(ThreatFeed, feed_id, populate_existing=True)
    if feed is None:
        raise FeedNotFoundError(str(feed_id))
    return feed


async def list_feeds(
    session: AsyncSession,
    *,
    limit: int,
    offset: int,
    is_active: bool | None = None,
    status: FeedStatus | None = None,
    feed_type: FeedType | None = None,
) -> FeedPage:
    """Liste paginée, triée par nom, avec filtres optionnels."""
    conditions: list[ColumnElement[bool]] = []
    if is_active is not None:
        conditions.append(ThreatFeed.is_active.is_(is_active))
    if status is not None:
        conditions.append(ThreatFeed.status == status)
    if feed_type is not None:
        conditions.append(ThreatFeed.feed_type == feed_type)

    total = await session.scalar(select(func.count()).select_from(ThreatFeed).where(*conditions))
    result = await session.execute(
        select(ThreatFeed)
        .where(*conditions)
        .order_by(func.lower(ThreatFeed.name), ThreatFeed.id)
        .limit(limit)
        .offset(offset)
    )
    return FeedPage(items=result.scalars().all(), total=total or 0)


def ensure_url_fits_type(url: str, feed_type: FeedType) -> None:
    """Règles propres à un format : un flux OTX ne peut viser que l'API OTX officielle.

    Raises:
        UnsafeFeedURLError: URL incompatible avec le format déclaré.
    """
    if FeedType(feed_type) is FeedType.OTX and urlsplit(url).hostname != OTX_HOST:
        raise UnsafeFeedURLError(
            f"Un flux OTX doit viser https://{OTX_HOST}/ (la clé API y est envoyée)."
        )


async def create_feed(
    session: AsyncSession,
    *,
    name: str,
    url: str,
    feed_type: FeedType,
    polling_interval: int = 3600,
    is_active: bool = True,
) -> ThreatFeed:
    """Enregistre une source. L'état de santé est fixé par le serveur (`PENDING`)."""
    clean_name = normalize_feed_name(name)
    clean_url = validate_feed_url(url)
    ensure_url_fits_type(clean_url, feed_type)
    await _ensure_name_available(session, clean_name)

    feed = ThreatFeed(
        name=clean_name,
        url=clean_url,
        feed_type=FeedType(feed_type),
        polling_interval=polling_interval,
        is_active=is_active,
        status=FeedStatus.PENDING,
    )
    await _flush_or_conflict(session, clean_name, new=feed)
    await session.refresh(feed)  # récupère created_at / updated_at générés par la base
    return feed


async def update_feed(
    session: AsyncSession,
    feed_id: UUID,
    *,
    name: str | None = None,
    url: str | None = None,
    feed_type: FeedType | None = None,
    polling_interval: int | None = None,
    is_active: bool | None = None,
) -> ThreatFeed:
    """Mise à jour partielle. `None` signifie « champ inchangé ».

    Changer d'URL ou de format invalide l'état de santé connu : le flux repasse
    en `PENDING` et la dernière erreur est effacée, jusqu'à la prochaine collecte.
    """
    feed = await get_feed(session, feed_id)

    # Validation complète avant toute modification : un refus laisse l'objet intact.
    clean_url = validate_feed_url(url) if url is not None else feed.url
    ensure_url_fits_type(clean_url, FeedType(feed_type or feed.feed_type))

    if name is not None:
        clean_name = normalize_feed_name(name)
        if clean_name != feed.name:
            await _ensure_name_available(session, clean_name, exclude_id=feed.id)
            feed.name = clean_name

    source_changed = False
    if url is not None:
        source_changed |= clean_url != feed.url
        feed.url = clean_url
    if feed_type is not None:
        source_changed |= FeedType(feed_type) != feed.feed_type
        feed.feed_type = FeedType(feed_type)
    if polling_interval is not None:
        feed.polling_interval = polling_interval
    if is_active is not None:
        feed.is_active = is_active

    if source_changed:
        feed.status = FeedStatus.PENDING
        feed.last_error = None

    await _flush_or_conflict(session, feed.name)
    await session.refresh(feed)  # récupère updated_at recalculé par la base
    return feed


async def delete_feed(session: AsyncSession, feed_id: UUID) -> None:
    """Supprime une source. Les IOC déjà collectés sont conservés (`feed_id` passe à NULL)."""
    feed = await get_feed(session, feed_id)
    await session.delete(feed)
    await session.flush()
