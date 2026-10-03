"""Récupération HTTP des flux — T2.3, UC-01 (étapes 2-3, scénarios 2a et 3a).

Sécurité (SSRF) : `validate_feed_url` vérifie l'URL *telle qu'écrite* à l'enregistrement.
Ici, on revérifie au moment de la requête, là où l'attaque se produit réellement :

1. l'URL est revalidée (elle a pu être écrite en base par un autre chemin) ;
2. le nom d'hôte est **résolu** et *toutes* les adresses obtenues doivent être
   publiques : un domaine public qui résout vers 10.0.0.5 ou 169.254.169.254 est refusé ;
3. les redirections ne sont **pas suivies automatiquement** : chaque saut est revalidé
   selon les mêmes règles (sinon `https://public.example → http://127.0.0.1` passerait) ;
4. la taille de réponse est plafonnée (`FEED_MAX_BYTES`) pendant la lecture en flux.

Risque résiduel assumé : entre notre résolution DNS et celle de httpx, un attaquant
contrôlant le DNS pourrait changer la réponse (TTL nul). Fermer complètement ce
risque demande d'épingler l'IP résolue dans la connexion (proxy de sortie ou transport
dédié) : à traiter avant tout déploiement multi-tenant.

Résilience (UC-01) : erreurs réseau, délais dépassés et réponses 5xx sont retentés avec
un backoff exponentiel (`HTTP_MAX_RETRIES`). Un 429 n'est **pas** retenté dans le cycle :
la source demande d'attendre, la collecte est reportée au cycle suivant.
"""

import asyncio
import socket
import time
from collections.abc import Awaitable, Callable, Mapping
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin, urlsplit

import httpx

from sentry import __version__
from sentry.app.config import Settings, get_settings
from sentry.modules.threat_feeds.secrets import MissingFeedSecretError, resolve_feed_url
from sentry.modules.threat_feeds.service import (
    UnsafeFeedURLError,
    is_internal_ip,
    validate_feed_url,
)

MAX_REDIRECTS = 3
DEFAULT_RETRY_AFTER_SECONDS = 60
USER_AGENT = f"SENTRY/{__version__} (CyberillSec Threat Intelligence Platform)"

Resolver = Callable[[str, int], Awaitable[list[str]]]


class FetchError(Exception):
    """Échec de récupération d'un flux (message destiné à `threat_feeds.last_error`)."""


class UnsafeDestinationError(FetchError):
    """La destination réelle de la requête est interne ou non autorisée."""


class RateLimitedError(FetchError):
    """La source a répondu 429 : collecte reportée au cycle suivant."""

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__(
            f"Limite de débit atteinte (HTTP 429) : nouvelle tentative dans "
            f"{retry_after_seconds} s au plus tôt."
        )
        self.retry_after_seconds = retry_after_seconds


class _RetryableError(Exception):
    """Erreur transitoire : réseau, délai dépassé ou 5xx."""


async def resolve_host(host: str, port: int) -> list[str]:
    """Résout un nom d'hôte en adresses IP (toutes familles)."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({str(info[4][0]) for info in infos})


async def assert_public_destination(url: str, resolver: Resolver = resolve_host) -> None:
    """Refuse une URL non conforme ou dont **une** des adresses résolues n'est pas publique.

    Partagée par tous les clients HTTP de SENTRY (fetcher maison, client TAXII) : la règle
    SSRF ne doit pas dépendre de la bibliothèque qui émet la requête.
    """
    try:
        validate_feed_url(url)
    except UnsafeFeedURLError as exc:
        raise UnsafeDestinationError(f"URL refusée : {exc}") from exc

    parts = urlsplit(url)
    host = parts.hostname or ""
    try:
        addresses = await resolver(host, parts.port or 443)
    except OSError as exc:
        raise FetchError(f"Résolution DNS impossible pour {host} : {exc}") from exc
    if not addresses:
        raise FetchError(f"Aucune adresse pour {host}.")
    internal = [a for a in addresses if is_internal_ip(a)]
    if internal:
        raise UnsafeDestinationError(
            f"{host} résout vers une adresse interne ({', '.join(internal)}) : requête refusée."
        )


def _retry_after(response: httpx.Response) -> int:
    return retry_after_seconds(response.headers.get("Retry-After", ""))


def retry_after_seconds(raw: str) -> int:
    """Délai demandé par un en-tête `Retry-After` (secondes ou date HTTP)."""
    header = raw.strip()
    if header.isdigit():
        return int(header)
    if header:
        try:
            delay = parsedate_to_datetime(header).timestamp() - time.time()
            return max(int(delay), 1)
        except (TypeError, ValueError):
            pass
    return DEFAULT_RETRY_AFTER_SECONDS


async def _read_capped(response: httpx.Response, max_bytes: int) -> bytes:
    declared = response.headers.get("Content-Length")
    if declared and declared.isdigit() and int(declared) > max_bytes:
        raise FetchError(f"Réponse trop volumineuse ({declared} octets > {max_bytes}).")
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.aiter_bytes():
        size += len(chunk)
        if size > max_bytes:
            raise FetchError(f"Réponse trop volumineuse (> {max_bytes} octets) : lecture stoppée.")
        chunks.append(chunk)
    return b"".join(chunks)


async def _single_attempt(
    client: httpx.AsyncClient,
    url: str,
    resolver: Resolver,
    max_bytes: int,
    headers: Mapping[str, str] | None = None,
) -> bytes:
    current = url
    origin = urlsplit(url).hostname
    for _ in range(MAX_REDIRECTS + 1):
        await assert_public_destination(current, resolver)
        try:
            async with client.stream("GET", current, headers=headers) as response:
                if response.is_redirect:
                    location = response.headers.get("Location")
                    if not location:
                        raise FetchError(f"Redirection {response.status_code} sans Location.")
                    current = urljoin(current, location)
                    # Des en-têtes d'authentification ne suivent jamais un changement d'hôte :
                    # une redirection ne doit pas pouvoir exfiltrer une clé d'API.
                    if headers and urlsplit(current).hostname != origin:
                        raise UnsafeDestinationError(
                            "Redirection vers un autre hôte refusée pour une requête authentifiée."
                        )
                    continue
                if response.status_code == 429:
                    raise RateLimitedError(_retry_after(response))
                if response.status_code >= 500:
                    raise _RetryableError(f"HTTP {response.status_code} renvoyé par la source.")
                if response.status_code >= 400:
                    raise FetchError(f"HTTP {response.status_code} renvoyé par la source.")
                return await _read_capped(response, max_bytes)
        except httpx.TransportError as exc:  # délai, réseau, protocole, proxy : transitoire
            raise _RetryableError(f"{type(exc).__name__} : {exc}") from exc
        except httpx.HTTPError as exc:  # ex. contenu compressé corrompu : pas de nouvel essai
            raise FetchError(f"{type(exc).__name__} : {exc}") from exc
    raise FetchError(f"Plus de {MAX_REDIRECTS} redirections : abandon.")


async def fetch_feed_content(
    url: str,
    *,
    settings: Settings | None = None,
    client: httpx.AsyncClient | None = None,
    resolver: Resolver = resolve_host,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    headers: Mapping[str, str] | None = None,
) -> bytes:
    """Télécharge le contenu brut d'un flux, avec les garde-fous décrits en tête de module.

    `headers` : en-têtes supplémentaires (ex. clé d'API OTX). Ils ne sont jamais
    transmis à un autre hôte que celui de l'URL demandée.

    Raises:
        UnsafeDestinationError: destination interne ou URL non conforme.
        RateLimitedError: la source impose une attente (HTTP 429).
        FetchError: tout autre échec, après épuisement des tentatives.
    """
    cfg = settings or get_settings()
    try:
        url = resolve_feed_url(url, cfg)
    except MissingFeedSecretError as exc:
        raise FetchError(str(exc)) from exc
    owns_client = client is None
    http = client or httpx.AsyncClient(
        timeout=cfg.http_timeout_seconds,
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
    )
    try:
        attempts = cfg.http_max_retries + 1
        for attempt in range(1, attempts + 1):
            try:
                return await _single_attempt(http, url, resolver, cfg.feed_max_bytes, headers)
            except _RetryableError as exc:
                if attempt == attempts:
                    raise FetchError(f"{exc} ({attempts} tentatives).") from exc
                await sleep(min(2 ** (attempt - 1), 30))
        raise AssertionError("inatteignable")  # pragma: no cover
    finally:
        if owns_client:
            await http.aclose()
