"""Sonde de source — « vérifier qu'une API existe et répond avant de l'intégrer ».

Une sonde exécute **une** collecte d'essai (une page au plus pour TAXII et OTX), analyse la
réponse et classe les IOC obtenus, **sans rien écrire en base**. Elle répond aux questions
qu'on se pose avant d'ajouter une source au seed ou à la production :

- l'hôte est-il joignable, et la règle SSRF l'accepte-t-elle ?
- les identifiants (`TAXII_AUTH`, `OTX_API_KEY`, `ABUSECH_AUTH_KEY`) sont-ils acceptés ?
- le format est-il celui annoncé, et produit-il des IOC exploitables (et combien) ?

Une collection TAXII peut répondre correctement et ne contenir **aucun IOC** : c'est le cas
de MITRE ATT&CK (techniques, groupes, logiciels). La sonde le montre avant qu'une source
« saine » mais vide ne fausse un critère de jalon.
"""

import time
from collections import Counter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from requests.adapters import BaseAdapter

from sentry.app.config import Settings
from sentry.modules.threat_feeds.fetcher import (
    FetchError,
    Resolver,
    fetch_feed_content,
    resolve_host,
)
from sentry.modules.threat_feeds.otx import HeaderFetcher, fetch_otx
from sentry.modules.threat_feeds.parsers import FeedParseError, ParseResult, parse_feed
from sentry.modules.threat_feeds.secrets import mask_secrets
from sentry.modules.threat_feeds.taxii import fetch_taxii
from sentry.modules.threat_feeds.validators import InvalidIndicatorError, normalize_indicator
from sentry.shared.enums import FeedType

MAX_SAMPLES = 5


@dataclass(slots=True)
class ProbeReport:
    url: str
    feed_type: FeedType
    reachable: bool = False
    duration_ms: int = 0
    pages: int = 0
    truncated: bool = False
    observations: int = 0
    skipped: int = 0
    by_type: dict[str, int] = field(default_factory=dict)
    rejected: int = 0
    samples: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def usable(self) -> bool:
        """Joignable, lisible et porteuse d'au moins un IOC valide."""
        return self.reachable and self.error is None and sum(self.by_type.values()) > 0


async def probe_source(
    url: str,
    feed_type: FeedType,
    *,
    settings: Settings,
    fetch: HeaderFetcher | None = None,
    taxii_transport: BaseAdapter | None = None,
    resolver: Resolver = resolve_host,
    clock: Callable[[], float] = time.perf_counter,
) -> ProbeReport:
    """Collecte d'essai d'une source, sans écriture. Ne lève jamais pour une source en échec."""
    report = ProbeReport(url=url, feed_type=FeedType(feed_type))
    one_page = settings.model_copy(update={"taxii_max_pages": 1, "otx_max_pages": 1})
    started = clock()
    try:
        parsed = await _collect(
            url,
            report,
            settings=one_page,
            fetch=fetch,
            transport=taxii_transport,
            resolver=resolver,
        )
        report.reachable = True
        _classify(parsed, report)
    except (FetchError, FeedParseError) as exc:
        report.reachable = isinstance(exc, FeedParseError)  # l'hôte a répondu
        report.error = mask_secrets(str(exc), settings)[:500]
    report.duration_ms = int((clock() - started) * 1000)
    return report


async def _collect(
    url: str,
    report: ProbeReport,
    *,
    settings: Settings,
    fetch: HeaderFetcher | None,
    transport: BaseAdapter | None,
    resolver: Resolver,
) -> ParseResult:
    kind = report.feed_type
    if kind is FeedType.TAXII:
        parsed, report.pages, report.truncated = await fetch_taxii(
            url, settings=settings, fetch=fetch, resolver=resolver, transport=transport
        )
        return parsed
    getter: Callable[..., Awaitable[bytes]] = fetch or fetch_feed_content
    if kind is FeedType.OTX:
        outcome = await fetch_otx(url, settings=settings, fetch=getter)
        report.pages, report.truncated = outcome.pages, outcome.truncated
        return outcome.parsed
    content = await getter(url)
    report.pages = 1
    return parse_feed(content, kind)


def _classify(parsed: ParseResult, report: ProbeReport) -> None:
    report.observations = len(parsed.observations)
    report.skipped = parsed.skipped
    counts: Counter[str] = Counter()
    for observation in parsed.observations:
        try:
            ioc_type, value = normalize_indicator(observation.value)
        except InvalidIndicatorError:
            report.rejected += 1
            continue
        counts[str(ioc_type)] += 1
        if len(report.samples) < MAX_SAMPLES:
            report.samples.append(value)
    report.by_type = dict(counts.most_common())
