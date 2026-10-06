"""Connecteur AlienVault OTX — T2.9 (pulses abonnés).

    GET https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50&modified_since=…
    En-tête : X-OTX-API-KEY: <OTX_API_KEY>

Un *pulse* OTX est un bulletin (campagne, malware, acteur) qui regroupe des IOC. Le
compte OTX « s'abonne » à des auteurs ou des pulses ; l'API renvoie ces pulses par
pages de 50 avec un lien `next`.

Règles :

- **Clé** : lue dans `OTX_API_KEY` (`.env`), transmise en en-tête, jamais en base ni
  dans l'URL. Elle n'est envoyée qu'à `otx.alienvault.com` : l'URL du flux est
  contrôlée à l'enregistrement (`service.ensure_url_fits_type`), revérifiée ici, et
  chaque lien `next` l'est aussi. Le fetcher refuse toute redirection vers un autre hôte.
- **Incrémental** : `modified_since` = dernier succès moins une marge de 15 min (horloges
  décalées, pulses modifiés pendant la collecte). Les IOC re-rapportés sont dédupliqués.
- **Bornes et reprise** : au plus `OTX_MAX_PAGES` pages par collecte. Au-delà, la collecte
  réussit mais est signalée **tronquée** ; une page en échec après la première arrête la
  collecte sans perdre les pages déjà lues (**interrompue**). Dans les deux cas, le curseur
  `modified_since` n'avance pas : la collecte suivante reprend à la page non lue
  (`start_page`, géré par le collecteur), jusqu'à épuisement de la fenêtre.
- **Types** : seuls les types d'IOC gérés par SENTRY sont retenus ; les autres (CVE,
  YARA, CIDR, mutex, chemins…) sont comptés comme ignorés, pas comme rejetés.
"""

import json
from collections.abc import Awaitable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sentry.app.config import Settings
from sentry.modules.threat_feeds.fetcher import FetchError
from sentry.modules.threat_feeds.indicators import Observation
from sentry.modules.threat_feeds.parsers import (
    FeedParseError,
    ParseResult,
    _description,
    _parse_date,
)
from sentry.modules.threat_feeds.service import OTX_HOST
from sentry.shared.enums import IndicatorType, Severity

API_KEY_HEADER = "X-OTX-API-KEY"
SINCE_OVERLAP = timedelta(minutes=15)

OTX_TYPES: dict[str, IndicatorType] = {
    "IPv4": IndicatorType.IPV4,
    "IPv6": IndicatorType.IPV6,
    "domain": IndicatorType.DOMAIN,
    "hostname": IndicatorType.DOMAIN,
    "URL": IndicatorType.URL,
    "FileHash-MD5": IndicatorType.HASH_MD5,
    "FileHash-SHA1": IndicatorType.HASH_SHA1,
    "FileHash-SHA256": IndicatorType.HASH_SHA256,
    "email": IndicatorType.EMAIL,
}


class HeaderFetcher(Protocol):
    def __call__(
        self, url: str, *, headers: Mapping[str, str] | None = None
    ) -> Awaitable[bytes]: ...


@dataclass(slots=True)
class OTXResult:
    parsed: ParseResult = field(default_factory=ParseResult)
    pages: int = 0
    pulses: int = 0
    truncated: bool = False
    # Erreur survenue après au moins une page lue : les pages lues restent exploitables.
    interrupted: str | None = None

    @property
    def complete(self) -> bool:
        """Toute la fenêtre a été lue : le curseur peut avancer."""
        return not self.truncated and self.interrupted is None


def _ensure_otx_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname != OTX_HOST:
        raise FetchError(
            f"URL OTX refusée ({parts.scheme}://{parts.hostname}) : seul "
            f"https://{OTX_HOST}/ reçoit la clé API."
        )


def with_modified_since(url: str, since: datetime | None) -> str:
    """Ajoute (ou remplace) `modified_since` dans l'URL du flux."""
    if since is None:
        return url
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query) if k != "modified_since"]
    query.append(("modified_since", (since - SINCE_OVERLAP).strftime("%Y-%m-%dT%H:%M:%S")))
    return urlunsplit(parts._replace(query=urlencode(query)))


def with_page(url: str, page: int) -> str:
    """Positionne le paramètre `page` (1 = première page, paramètre omis)."""
    if page <= 1:
        return url
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query) if k != "page"]
    query.append(("page", str(page)))
    return urlunsplit(parts._replace(query=urlencode(query)))


def parse_otx_page(
    content: bytes, *, default_severity: Severity = Severity.MEDIUM
) -> tuple[ParseResult, int, str | None]:
    """Analyse une page de l'API : (observations, nombre de pulses, lien `next`)."""
    try:
        document: Any = json.loads(content.decode("utf-8-sig", errors="replace"))
    except json.JSONDecodeError as exc:
        raise FeedParseError(f"OTX : JSON invalide : {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("results"), list):
        raise FeedParseError("OTX : réponse inattendue (clé `results` absente).")

    result = ParseResult()
    pulses = 0
    for pulse in document["results"]:
        if not isinstance(pulse, dict):
            continue
        pulses += 1
        name = _description(pulse.get("name"))
        pulse_date = _parse_date(pulse.get("modified") or pulse.get("created"))
        for item in pulse.get("indicators") or []:
            if not isinstance(item, dict):
                result.skipped += 1
                continue
            ioc_type = OTX_TYPES.get(str(item.get("type")))
            value = item.get("indicator")
            if ioc_type is None or not isinstance(value, str) or not value.strip():
                result.skipped += 1
                continue
            if item.get("is_active") in (0, False):
                result.skipped += 1
                continue
            result.observations.append(
                Observation(
                    value=value.strip(),
                    type=ioc_type,
                    severity=default_severity,
                    description=name,
                    observed_at=_parse_date(item.get("created")) or pulse_date,
                )
            )
    next_url = document.get("next")
    return result, pulses, next_url if isinstance(next_url, str) and next_url else None


async def fetch_otx(
    url: str,
    *,
    settings: Settings,
    fetch: HeaderFetcher,
    since: datetime | None = None,
    start_page: int = 1,
) -> OTXResult:
    """Parcourt les pages de pulses abonnés et agrège les observations.

    `start_page` > 1 reprend une collecte précédente tronquée ou interrompue. Une erreur
    réseau ou de lecture après la première page lue n'annule pas la collecte : elle
    s'arrête là et le signale (`interrupted`).

    Raises:
        FetchError: clé absente, URL ou lien `next` hors de l'API OTX, échec réseau sur la
            première page.
        FeedParseError: première page illisible.
    """
    key = settings.otx_api_key.get_secret_value() if settings.otx_api_key else ""
    if not key:
        raise FetchError(
            "Secret OTX_API_KEY non configuré : renseignez-le dans .env pour collecter ce flux."
        )
    headers = {API_KEY_HEADER: key, "Accept": "application/json"}

    outcome = OTXResult()
    page_url: str | None = with_modified_since(with_page(url, start_page), since)
    while page_url is not None:
        if outcome.pages >= settings.otx_max_pages:
            outcome.truncated = True
            break
        # Hors du `try` : une destination refusée est une faute de sécurité, jamais tolérée.
        _ensure_otx_url(page_url)
        try:
            content = await fetch(page_url, headers=headers)
            parsed, pulses, page_url = parse_otx_page(content)
        except (FetchError, FeedParseError) as exc:
            if outcome.pages == 0:
                raise
            outcome.interrupted = str(exc)
            break
        outcome.pages += 1
        outcome.pulses += pulses
        outcome.parsed.observations.extend(parsed.observations)
        outcome.parsed.skipped += parsed.skipped
    return outcome
