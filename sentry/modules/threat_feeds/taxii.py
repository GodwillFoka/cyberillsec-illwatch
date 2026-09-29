"""Connecteur TAXII 2.1 — tâche 1.8 (collection d'objets STIX 2.1).

    GET <api-root>/collections/<id>/objects/?added_after=…&next=…
    Accept: application/taxii+json;version=2.1
    Authorization: Basic …   (si l'hôte figure dans TAXII_AUTH)

L'URL d'un flux TAXII est celle du point `objects/` d'une collection. La réponse est une
enveloppe `{"more": bool, "next": "…", "objects": [...]}` ; les objets sont analysés par
le même code que les bundles STIX (`parse_stix_objects`).

- **Identifiants** : `TAXII_AUTH` (`.env`), par hôte, jamais en base. Envoyés seulement à
  l'hôte nommé ; le fetcher refuse toute redirection inter-hôtes d'une requête authentifiée.
- **Incrémental** : `added_after` = dernier succès moins 15 min. Le serveur peut ignorer ce
  filtre ; la déduplication absorbe alors les répétitions.
- **Bornes** : `TAXII_MAX_PAGES` pages au plus ; au-delà, collecte signalée tronquée.
"""

import base64
import json
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sentry.app.config import Settings
from sentry.modules.threat_feeds.fetcher import FetchError
from sentry.modules.threat_feeds.otx import HeaderFetcher
from sentry.modules.threat_feeds.parsers import FeedParseError, ParseResult, parse_stix_objects

TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"
SINCE_OVERLAP = timedelta(minutes=15)


class TaxiiConfigError(ValueError):
    """`TAXII_AUTH` mal formé."""


def parse_taxii_auth(raw: str) -> dict[str, tuple[str, str]]:
    """`"hote=user:pass;hote2=user:pass"` → {hote: (user, pass)}."""
    credentials: dict[str, tuple[str, str]] = {}
    for entry in filter(None, (part.strip() for part in raw.split(";"))):
        host, sep, pair = entry.partition("=")
        user, sep2, password = pair.partition(":")
        if not (sep and sep2 and host.strip() and user):
            raise TaxiiConfigError(
                "TAXII_AUTH attendu sous la forme hote=utilisateur:motdepasse[;…]."
            )
        credentials[host.strip().lower()] = (user, password)
    return credentials


def taxii_secrets(settings: Settings) -> list[str]:
    """Mots de passe TAXII configurés (pour le masquage des messages)."""
    try:
        creds = parse_taxii_auth(settings.taxii_auth.get_secret_value())
    except TaxiiConfigError:
        return []
    return [password for _, password in creds.values() if password]


def _headers(url: str, settings: Settings) -> dict[str, str]:
    headers = {"Accept": TAXII_MEDIA_TYPE}
    host = (urlsplit(url).hostname or "").lower()
    creds = parse_taxii_auth(settings.taxii_auth.get_secret_value()).get(host)
    if creds is not None:
        token = base64.b64encode(f"{creds[0]}:{creds[1]}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    return headers


def _with_params(url: str, **params: str) -> str:
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query) if k not in params]
    query.extend(params.items())
    return urlunsplit(parts._replace(query=urlencode(query)))


def parse_envelope(content: bytes) -> tuple[list[Any], str | None]:
    """Enveloppe TAXII 2.1 → (objets, jeton `next` s'il reste des pages)."""
    try:
        document: Any = json.loads(content.decode("utf-8-sig", errors="replace"))
    except json.JSONDecodeError as exc:
        raise FeedParseError(f"TAXII : JSON invalide : {exc}") from exc
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


async def fetch_taxii(
    url: str,
    *,
    settings: Settings,
    fetch: HeaderFetcher,
    since: datetime | None = None,
) -> tuple[ParseResult, int, bool]:
    """Parcourt la collection : (observations, pages lues, tronqué ?).

    Raises:
        FetchError: configuration invalide, échec réseau.
        FeedParseError: réponse illisible.
    """
    try:
        headers = _headers(url, settings)
    except TaxiiConfigError as exc:
        raise FetchError(str(exc)) from exc
    base = url
    if since is not None:
        base = _with_params(
            url, added_after=(since - SINCE_OVERLAP).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        )

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
