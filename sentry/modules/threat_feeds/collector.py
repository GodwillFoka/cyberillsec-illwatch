"""Orchestration d'une collecte — UC-01 (ingestion automatisée d'un flux), T2.3.

    flux actif et échu → récupération → analyse → ingestion dédupliquée → état du flux

Règles :

- **Isolation (RSK-02)** : chaque flux est collecté dans son propre point de sauvegarde.
  L'échec d'un flux est enregistré sur ce flux seul ; il n'interrompt ni les autres
  collectes, ni la transaction, ni l'API.
- **État** : succès → `HEALTHY`, `last_successful_run` à l'heure de fin, `last_error`
  vidé. Échec → `DEGRADED` et message d'erreur. Limite de débit (429) → erreur notée,
  **statut inchangé** : la source va bien, elle demande seulement d'attendre.
- **Échéance** : un flux est dû si actif et jamais réussi, ou si son dernier succès date
  de plus de `polling_interval` secondes. Un flux en échec est donc retenté à chaque cycle.
"""

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app.config import get_settings
from sentry.app.models import ThreatFeed
from sentry.modules.threat_feeds.fetcher import FetchError, RateLimitedError, fetch_feed_content
from sentry.modules.threat_feeds.indicators import ingest_indicators
from sentry.modules.threat_feeds.parsers import FeedParseError, parse_feed
from sentry.modules.threat_feeds.secrets import mask_secrets
from sentry.shared.enums import FeedStatus, FeedType

MAX_ERROR_LENGTH = 1000

Fetcher = Callable[[str], Awaitable[bytes]]


@dataclass(slots=True)
class CollectionReport:
    feed_id: str
    feed_name: str
    status: FeedStatus
    fetched_bytes: int = 0
    parsed: int = 0
    skipped: int = 0
    inserted: int = 0
    updated: int = 0
    rejected: int = 0
    error: str | None = None
    rejected_samples: list[str] = field(default_factory=list)

    @property
    def succeeded(self) -> bool:
        return self.error is None


def _safe_message(message: str) -> str:
    """Message d'erreur stockable : secrets masqués, longueur bornée."""
    return mask_secrets(message, get_settings())[:MAX_ERROR_LENGTH]


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


def is_due(feed: ThreatFeed, now: datetime) -> bool:
    last = _as_utc(feed.last_successful_run)
    return feed.is_active and (
        last is None or last + timedelta(seconds=feed.polling_interval) <= now
    )


async def due_feeds(session: AsyncSession, now: datetime) -> Sequence[ThreatFeed]:
    active = (
        (await session.execute(select(ThreatFeed).where(ThreatFeed.is_active.is_(True))))
        .scalars()
        .all()
    )
    return [f for f in active if is_due(f, now)]


async def collect_feed(
    session: AsyncSession,
    feed: ThreatFeed,
    *,
    fetch: Fetcher = fetch_feed_content,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> CollectionReport:
    """Collecte un flux et met à jour son état. Ne lève jamais pour un échec de collecte."""
    report = CollectionReport(
        feed_id=str(feed.id), feed_name=feed.name, status=FeedStatus(feed.status)
    )
    try:
        content = await fetch(feed.url)
        report.fetched_bytes = len(content)
        parsed = parse_feed(content, FeedType(feed.feed_type))
        report.parsed, report.skipped = len(parsed.observations), parsed.skipped

        async with session.begin_nested():
            result = await ingest_indicators(
                session, parsed.observations, feed_id=feed.id, now=clock()
            )
        report.inserted, report.updated = result.inserted, result.updated
        report.rejected = len(result.rejected)
        report.rejected_samples = [r.value for r in result.rejected[:5]]

        feed.status = FeedStatus.HEALTHY
        feed.last_successful_run = clock()
        feed.last_error = None
    except RateLimitedError as exc:
        report.error = feed.last_error = _safe_message(str(exc))
    except (FetchError, FeedParseError) as exc:
        report.error = feed.last_error = _safe_message(str(exc))
        feed.status = FeedStatus.DEGRADED
    except Exception as exc:  # noqa: BLE001 - RSK-02 : un flux ne doit jamais bloquer les autres
        report.error = feed.last_error = _safe_message(
            f"Erreur inattendue ({type(exc).__name__}) : {exc}"
        )
        feed.status = FeedStatus.DEGRADED

    report.status = FeedStatus(feed.status)
    await session.flush()
    return report


async def collect_due_feeds(
    session: AsyncSession,
    *,
    force: bool = False,
    fetch: Fetcher = fetch_feed_content,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> list[CollectionReport]:
    """Collecte tous les flux échus (ou tous les flux actifs si `force`), l'un après l'autre."""
    now = clock()
    if force:
        feeds = (
            (await session.execute(select(ThreatFeed).where(ThreatFeed.is_active.is_(True))))
            .scalars()
            .all()
        )
    else:
        feeds = await due_feeds(session, now)
    reports = []
    for feed in sorted(feeds, key=lambda f: f.name.lower()):
        reports.append(await collect_feed(session, feed, fetch=fetch, clock=clock))
    return reports
