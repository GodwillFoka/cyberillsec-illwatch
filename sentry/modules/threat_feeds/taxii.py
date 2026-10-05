"""Connecteur TAXII 2.1 — tâche 1.8, client de référence `taxii2-client` (OASIS).

    SENTRY ─▶ fetch_taxii ─┬─▶ taxii2-client (production) ─▶ Collection.get_objects()
                           └─▶ fetcher injecté (tests, TAXII_CLIENT=builtin)
                 ─▶ enveloppe {more, next, objects} ─▶ parse_stix_objects ─▶ Observation

L'URL d'un flux TAXII est celle du point `objects/` d'une collection
(`<api-root>/collections/<id>/objects/`). Le client de bibliothèque reçoit l'URL de la
collection (`…/collections/<id>/`) et ses métadonnées connues d'avance : aucune requête de
découverte supplémentaire n'est émise à chaque collecte.

Garanties conservées par rapport au transport maison (aucune régression de sécurité) :

- **SSRF** : avant toute requête, l'URL est validée et le nom d'hôte résolu ; une seule
  adresse non publique suffit à refuser (`assert_public_destination`, règle partagée).
- **Redirections refusées** : `requests` suit les redirections par défaut, ce qui
  contournerait le contrôle précédent. La session est réglée à `max_redirects = 0`.
- **Identifiants par hôte** (`TAXII_AUTH`) : Basic, Bearer ou en-tête dédié (`x-api-key`),
  attachés uniquement à la session de l'hôte nommé ; jamais en base, masqués dans les erreurs.
- **Délai et taille bornés** : `HTTP_TIMEOUT_SECONDS` par requête (`requests` n'en a aucun par
  défaut : une source muette bloquerait le worker) et `FEED_MAX_BYTES` par réponse, lue en flux.
- **Erreurs typées** : réseau, HTTP, contenu → `FetchError` / `RateLimitedError` /
  `FeedParseError` ; aucune exception de `requests` ou `taxii2-client` ne sort du module.
- **Incrémental** : `added_after` = dernier succès moins 15 min ; pagination `more`/`next`
  bornée par `TAXII_MAX_PAGES` (au-delà : collecte signalée tronquée).
- **Boucle async libre** : `taxii2-client` est synchrone (`requests`) ; chaque page est lue
  dans un thread (`asyncio.to_thread`).
"""

import asyncio
import base64
import json
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import partial
from typing import Any, Literal
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import requests
from requests.adapters import BaseAdapter
from taxii2client.common import _HTTPConnection
from taxii2client.exceptions import InvalidJSONError, TAXIIServiceException
from taxii2client.v21 import Collection

from sentry.app.config import Settings
from sentry.modules.threat_feeds.fetcher import (
    USER_AGENT,
    FetchError,
    RateLimitedError,
    Resolver,
    UnsafeDestinationError,
    assert_public_destination,
    resolve_host,
    retry_after_seconds,
)
from sentry.modules.threat_feeds.otx import HeaderFetcher
from sentry.modules.threat_feeds.parsers import FeedParseError, ParseResult, parse_stix_objects

TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"
SINCE_OVERLAP = timedelta(minutes=15)
_COLLECTION_TITLE = "SENTRY"  # exigé par taxii2-client, sans incidence sur la requête

Sleep = Callable[[float], Awaitable[None]]


class TaxiiConfigError(ValueError):
    """`TAXII_AUTH` ou URL de collection mal formés."""


# --- Identifiants -----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TaxiiCredential:
    """Identifiants d'un hôte TAXII.

    `scheme` : `basic` (utilisateur, mot de passe), `bearer` (jeton) ou `header` (en-tête
    nommé, ex. `x-api-key` de CrowdSec).
    """

    scheme: Literal["basic", "bearer", "header"]
    secret: str
    user: str = ""
    header: str = ""

    def headers(self) -> dict[str, str]:
        if self.scheme == "basic":
            token = base64.b64encode(f"{self.user}:{self.secret}".encode()).decode()
            return {"Authorization": f"Basic {token}"}
        if self.scheme == "bearer":
            return {"Authorization": f"Bearer {self.secret}"}
        return {self.header: self.secret}

    def requests_auth(self) -> requests.auth.AuthBase:
        if self.scheme == "basic":
            return requests.auth.HTTPBasicAuth(self.user, self.secret)
        return _HeaderAuth(self.headers())


class _HeaderAuth(requests.auth.AuthBase):
    def __init__(self, headers: Mapping[str, str]) -> None:
        self._headers = dict(headers)

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        request.headers.update(self._headers)
        return request


def _credential(entry: str) -> tuple[str, TaxiiCredential]:
    host, sep, spec = entry.partition("=")
    host = host.strip().lower()
    if not (sep and host and spec):
        raise TaxiiConfigError(
            "TAXII_AUTH attendu : hote=utilisateur:motdepasse, hote=bearer:JETON ou "
            "hote=header:NOM-EN-TETE:VALEUR (séparés par « ; »)."
        )
    kind, _, rest = spec.partition(":")
    if kind.lower() == "bearer" and rest:
        return host, TaxiiCredential("bearer", rest)
    if kind.lower() == "header":
        name, _, value = rest.partition(":")
        if name and value:
            return host, TaxiiCredential("header", value, header=name)
    if kind.lower() == "basic" and ":" in rest:
        user, _, password = rest.partition(":")
        return host, TaxiiCredential("basic", password, user=user)
    user, sep2, password = spec.partition(":")
    if not (sep2 and user):
        raise TaxiiConfigError(f"TAXII_AUTH : entrée illisible pour l'hôte {host}.")
    return host, TaxiiCredential("basic", password, user=user)


def parse_taxii_auth(raw: str) -> dict[str, TaxiiCredential]:
    """`"hote=user:pass;hote2=bearer:JETON"` → {hote: TaxiiCredential}."""
    return dict(_credential(part.strip()) for part in raw.split(";") if part.strip())


def taxii_secrets(settings: Settings) -> list[str]:
    """Secrets TAXII configurés (pour le masquage des messages)."""
    try:
        creds = parse_taxii_auth(settings.taxii_auth.get_secret_value())
    except TaxiiConfigError:
        return []
    return [c.secret for c in creds.values() if c.secret]


def credential_for(url: str, settings: Settings) -> TaxiiCredential | None:
    """Identifiants de l'hôte exact de `url`, ou `None` (collection publique)."""
    host = (urlsplit(url).hostname or "").lower()
    return parse_taxii_auth(settings.taxii_auth.get_secret_value()).get(host)


# --- URL ----------------------------------------------------------------------------


def _with_params(url: str, **params: str) -> str:
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query) if k not in params]
    query.extend(params.items())
    return urlunsplit(parts._replace(query=urlencode(query)))


def collection_endpoint(url: str) -> tuple[str, str]:
    """`…/collections/<id>/objects/` → (`…/collections/<id>/`, `<id>`).

    Accepte aussi l'URL de la collection elle-même. La requête (`?…`) est ignorée : les
    filtres sont recalculés à chaque collecte.
    """
    parts = urlsplit(url)
    segments = [s for s in parts.path.split("/") if s]
    if segments and segments[-1] == "objects":
        segments = segments[:-1]
    if len(segments) < 2 or segments[-2] != "collections":
        raise TaxiiConfigError(
            f"URL TAXII inattendue ({parts.path}) : …/collections/<id>/objects/ attendu."
        )
    path = "/" + "/".join(segments) + "/"
    return urlunsplit(parts._replace(path=path, query="", fragment="")), segments[-1]


def _added_after(since: datetime) -> str:
    return (since - SINCE_OVERLAP).strftime("%Y-%m-%dT%H:%M:%S.000Z")


# --- Enveloppe ------------------------------------------------------------------------


def _envelope(document: Any) -> tuple[list[Any], str | None]:
    if not isinstance(document, dict):
        raise FeedParseError("TAXII : enveloppe attendue (objet JSON).")
    if document.get("type") == "bundle":  # serveur TAXII 2.0 : bundle STIX direct
        return list(document.get("objects") or []), None
    objects = document.get("objects", [])
    if not isinstance(objects, list):
        raise FeedParseError("TAXII : `objects` doit être une liste.")
    token = document.get("next")
    more = document.get("more") is True
    return objects, str(token) if more and token else None


def parse_envelope(content: bytes) -> tuple[list[Any], str | None]:
    """Enveloppe TAXII 2.1 (octets) → (objets, jeton `next` s'il reste des pages)."""
    try:
        document: Any = json.loads(content.decode("utf-8-sig", errors="replace"))
    except json.JSONDecodeError as exc:
        raise FeedParseError(f"TAXII : JSON invalide : {exc}") from exc
    return _envelope(document)


# --- Transport taxii2-client durci -------------------------------------------------------


class _GuardedConnection(_HTTPConnection):  # type: ignore[misc]
    """Connexion `taxii2-client` aux garde-fous SENTRY (redirections, délai, taille)."""

    def __init__(
        self,
        *,
        settings: Settings,
        auth: requests.auth.AuthBase | None,
        transport: BaseAdapter | None = None,
    ) -> None:
        super().__init__(version="2.1", auth=auth, user_agent=USER_AGENT)
        session: requests.Session = self.session
        session.max_redirects = 0
        if transport is not None:
            session.mount("https://", transport)
        # Chaque requête : délai borné et lecture en flux (taille vérifiée par le hook).
        session.request = partial(  # type: ignore[method-assign]
            session.request, timeout=settings.http_timeout_seconds, stream=True
        )
        self._max_bytes = settings.feed_max_bytes
        session.hooks["response"].append(self._read_capped)

    def _read_capped(self, response: requests.Response, *_: Any, **__: Any) -> None:
        declared = response.headers.get("Content-Length", "")
        if declared.isdigit() and int(declared) > self._max_bytes:
            response.close()
            raise FetchError(f"Réponse trop volumineuse ({declared} octets > {self._max_bytes}).")
        chunks: list[bytes] = []
        size = 0
        for chunk in response.iter_content(64 * 1024):
            size += len(chunk)
            if size > self._max_bytes:
                response.close()
                raise FetchError(f"Réponse trop volumineuse (> {self._max_bytes} octets).")
            chunks.append(chunk)
        response._content = b"".join(chunks)  # lu une fois, servi ensuite par .json()


class _TransientError(Exception):
    """Erreur passagère : réseau, délai, 5xx."""


def _get_page(collection: Collection, filters: dict[str, Any]) -> Any:
    """Une page `Get Objects` ; traduit toutes les erreurs en exceptions SENTRY."""
    return _call(lambda: collection.get_objects(**filters))


def _call(operation: Callable[[], Any]) -> Any:
    """Exécute un appel `taxii2-client` et traduit ses erreurs en exceptions SENTRY."""
    try:
        return operation()
    except requests.TooManyRedirects as exc:
        raise UnsafeDestinationError(
            "Redirection refusée : un serveur TAXII doit répondre sans redirection "
            "(protection SSRF et identifiants)."
        ) from exc
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else 0
        if status == 429:
            # Pas de `if exc.response` : une Response en erreur est « fausse » (__bool__ = ok).
            header = exc.response.headers.get("Retry-After", "") if exc.response is not None else ""
            raise RateLimitedError(retry_after_seconds(header)) from exc
        if status >= 500:
            raise _TransientError(f"HTTP {status} renvoyé par le serveur TAXII.") from exc
        hint = " : vérifiez TAXII_AUTH pour cet hôte" if status in (401, 403) else ""
        raise FetchError(f"HTTP {status} renvoyé par le serveur TAXII{hint}.") from exc
    except (requests.ConnectionError, requests.Timeout) as exc:
        raise _TransientError(f"{type(exc).__name__} : {exc}") from exc
    except requests.RequestException as exc:
        raise FetchError(f"{type(exc).__name__} : {exc}") from exc
    except InvalidJSONError as exc:
        raise FeedParseError(f"TAXII : JSON invalide ({exc}).") from exc
    except TAXIIServiceException as exc:
        # Ex. Content-Type différent de application/taxii+json;version=2.1.
        first_line = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
        raise FeedParseError(f"TAXII : réponse non conforme ({first_line}).") from exc


async def _fetch_with_library(
    url: str,
    *,
    settings: Settings,
    since: datetime | None,
    resolver: Resolver,
    transport: BaseAdapter | None,
    sleep: Sleep,
) -> tuple[ParseResult, int, bool]:
    try:
        collection_url, collection_id = collection_endpoint(url)
        credential = credential_for(url, settings)
    except TaxiiConfigError as exc:
        raise FetchError(str(exc)) from exc
    await assert_public_destination(collection_url, resolver)

    conn = _GuardedConnection(
        settings=settings,
        auth=credential.requests_auth() if credential else None,
        transport=transport,
    )
    collection = Collection(
        collection_url,
        conn=conn,
        collection_info={
            "id": collection_id,
            "title": _COLLECTION_TITLE,
            "can_read": True,
            "can_write": False,
        },
    )
    base: dict[str, Any] = {}
    if since is not None:
        base["added_after"] = _added_after(since)

    result = ParseResult()
    pages = 0
    token: str | None = None
    attempts = settings.http_max_retries + 1
    try:
        while True:
            if pages >= settings.taxii_max_pages:
                return result, pages, True
            filters = {**base, **({"next": token} if token else {})}
            for attempt in range(1, attempts + 1):
                try:
                    document = await asyncio.to_thread(_get_page, collection, filters)
                    break
                except _TransientError as exc:
                    if attempt == attempts:
                        raise FetchError(f"{exc} ({attempts} tentatives).") from exc
                    await sleep(min(2 ** (attempt - 1), 30))
            objects, token = _envelope(document)
            pages += 1
            parsed = parse_stix_objects(objects)
            result.observations.extend(parsed.observations)
            result.skipped += parsed.skipped
            if token is None:
                return result, pages, False
    finally:
        collection.close()


# --- Transport injectable (tests, repli TAXII_CLIENT=builtin) ---------------------------


async def _fetch_with_fetcher(
    url: str, *, settings: Settings, fetch: HeaderFetcher, since: datetime | None
) -> tuple[ParseResult, int, bool]:
    try:
        credential = credential_for(url, settings)
    except TaxiiConfigError as exc:
        raise FetchError(str(exc)) from exc
    headers = {"Accept": TAXII_MEDIA_TYPE, **(credential.headers() if credential else {})}
    base = url if since is None else _with_params(url, added_after=_added_after(since))

    result = ParseResult()
    pages = 0
    page_url: str | None = base
    while page_url is not None:
        if pages >= settings.taxii_max_pages:
            return result, pages, True
        objects, token = parse_envelope(await fetch(page_url, headers=headers))
        pages += 1
        parsed = parse_stix_objects(objects)
        result.observations.extend(parsed.observations)
        result.skipped += parsed.skipped
        page_url = _with_params(base, next=token) if token else None
    return result, pages, False


async def fetch_taxii(
    url: str,
    *,
    settings: Settings,
    fetch: HeaderFetcher | None = None,
    since: datetime | None = None,
    resolver: Resolver = resolve_host,
    transport: BaseAdapter | None = None,
    sleep: Sleep = asyncio.sleep,
) -> tuple[ParseResult, int, bool]:
    """Parcourt une collection TAXII 2.1 : (observations, pages lues, tronqué ?).

    `fetch=None` (production) : client `taxii2-client` durci. Un `fetch` fourni (tests,
    ou `TAXII_CLIENT=builtin`) passe par le fetcher HTTP maison, mêmes règles.

    Raises:
        FetchError: configuration invalide, destination refusée, échec réseau ou HTTP.
        RateLimitedError: HTTP 429 (collecte reportée).
        FeedParseError: réponse illisible ou non conforme à TAXII 2.1.
    """
    if fetch is not None:
        return await _fetch_with_fetcher(url, settings=settings, fetch=fetch, since=since)
    return await _fetch_with_library(
        url, settings=settings, since=since, resolver=resolver, transport=transport, sleep=sleep
    )


# --- Découverte : vérifier une source avant de l'intégrer ---------------------------------


@dataclass(frozen=True, slots=True)
class DiscoveredCollection:
    api_root: str
    id: str
    title: str
    can_read: bool
    objects_url: str


@dataclass(slots=True)
class Discovery:
    title: str = ""
    api_roots: list[str] = field(default_factory=list)
    collections: list[DiscoveredCollection] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)  # API root → erreur


async def discover(
    url: str,
    *,
    settings: Settings,
    resolver: Resolver = resolve_host,
    transport: BaseAdapter | None = None,
) -> Discovery:
    """Interroge un point de découverte TAXII 2.1 (ou une API root) et liste les collections.

    Chaque API root annoncée est revalidée (SSRF) avant d'être contactée : un serveur de
    découverte ne peut pas faire viser une adresse interne. Une API root en échec est
    signalée sans empêcher l'inventaire des autres.
    """
    target = url if url.endswith("/") else url + "/"
    await assert_public_destination(target, resolver)
    credential = credential_for(target, settings)
    conn = _GuardedConnection(
        settings=settings,
        auth=credential.requests_auth() if credential else None,
        transport=transport,
    )
    result = Discovery()
    try:
        document = await asyncio.to_thread(_call, partial(conn.get, target))
        if not isinstance(document, dict):
            raise FeedParseError("TAXII : réponse de découverte inattendue.")
        result.title = str(document.get("title") or "")
        roots = document.get("api_roots")
        # Une API root peut être annoncée en chemin relatif (« /api/v21/ », serveur MITRE
        # ATT&CK) : elle se résout par rapport à l'URL de découverte, puis est revalidée.
        result.api_roots = (
            [urljoin(target, str(r)) for r in roots] if isinstance(roots, list) else [target]
        )
        for root in result.api_roots:
            root_url = root if root.endswith("/") else root + "/"
            try:
                await assert_public_destination(root_url, resolver)
                if urlsplit(root_url).hostname != urlsplit(target).hostname:
                    raise UnsafeDestinationError(
                        "API root sur un autre hôte : identifiants non transmis, à interroger "
                        "séparément."
                    )
                listing = await asyncio.to_thread(
                    _call, partial(conn.get, root_url + "collections/")
                )
            except (FetchError, FeedParseError, _TransientError) as exc:
                result.errors[root_url] = str(exc)
                continue
            for item in listing.get("collections", []) if isinstance(listing, dict) else []:
                if not isinstance(item, dict) or not item.get("id"):
                    continue
                result.collections.append(
                    DiscoveredCollection(
                        api_root=root_url,
                        id=str(item["id"]),
                        title=str(item.get("title") or ""),
                        can_read=bool(item.get("can_read")),
                        objects_url=f"{root_url}collections/{item['id']}/objects/",
                    )
                )
    except _TransientError as exc:
        raise FetchError(str(exc)) from exc
    finally:
        conn.close()
    return result
