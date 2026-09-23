"""Amorçage des données de référence — `sentry seed` (RF-03).

Idempotent : relancer la commande ne crée aucun doublon. Seules des sources
publiques, gratuites et sans clé d'API sont semées ; les connecteurs à clé
(AlienVault OTX, NVD) sont configurés par variables d'environnement.
"""

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app.models import ThreatFeed
from sentry.shared.enums import FeedType


@dataclass(frozen=True, slots=True)
class FeedSeed:
    name: str
    url: str
    feed_type: FeedType
    polling_interval: int


REFERENCE_FEEDS: tuple[FeedSeed, ...] = (
    FeedSeed(
        name="abuse.ch URLhaus — URL malveillantes récentes",
        url="https://urlhaus.abuse.ch/downloads/csv_recent/",
        feed_type=FeedType.CSV,
        polling_interval=3600,
    ),
    FeedSeed(
        name="abuse.ch Feodo Tracker — serveurs C2 botnet",
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        feed_type=FeedType.CSV,
        polling_interval=3600,
    ),
)


async def seed_reference_feeds(session: AsyncSession) -> list[str]:
    """Insère les flux de référence absents. Retourne les noms réellement créés."""
    result = await session.execute(select(ThreatFeed.name))
    existing = set(result.scalars().all())

    created: list[str] = []
    for feed in REFERENCE_FEEDS:
        if feed.name in existing:
            continue
        session.add(
            ThreatFeed(
                name=feed.name,
                url=feed.url,
                feed_type=feed.feed_type,
                polling_interval=feed.polling_interval,
            )
        )
        created.append(feed.name)

    await session.flush()
    return created
