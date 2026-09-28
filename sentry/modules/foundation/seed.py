"""Amorçage des données de référence — `sentry seed` (RF-03).

Idempotent : relancer la commande ne crée aucun doublon. Seules des sources
publiques et gratuites sont semées. Les clés éventuelles (ABUSECH_AUTH_KEY pour
URLhaus, OTX_API_KEY pour AlienVault OTX) ne sont jamais en base : elles sont lues
dans l'environnement. Sans clé, la source concernée passe en DEGRADED avec un message
explicite au lieu de bloquer les autres.
"""

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app.models import ThreatFeed
from sentry.shared.enums import FeedStatus, FeedType


@dataclass(frozen=True, slots=True)
class FeedSeed:
    name: str
    url: str
    feed_type: FeedType
    polling_interval: int


REFERENCE_FEEDS: tuple[FeedSeed, ...] = (
    FeedSeed(
        name="abuse.ch URLhaus — URL malveillantes récentes",
        # Depuis 2025, abuse.ch exige une clé (Auth-Key) dans l'URL de téléchargement.
        url="https://urlhaus-api.abuse.ch/v2/files/exports/{ABUSECH_AUTH_KEY}/recent.csv",
        feed_type=FeedType.CSV,
        polling_interval=3600,
    ),
    FeedSeed(
        name="abuse.ch Feodo Tracker — serveurs C2 botnet",
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        feed_type=FeedType.CSV,
        polling_interval=3600,
    ),
    FeedSeed(
        name="AlienVault OTX — pulses abonnés",
        # Clé OTX_API_KEY envoyée en en-tête ; `modified_since` ajouté à chaque collecte.
        url="https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50",
        feed_type=FeedType.OTX,
        polling_interval=3600,
    ),
)


# URL publiées par d'anciennes versions de `sentry seed` et devenues invalides :
# remplacées au prochain `sentry seed`, sans toucher aux URL modifiées à la main.
OBSOLETE_URLS: dict[str, str] = {
    "https://urlhaus.abuse.ch/downloads/csv_recent/": (
        "https://urlhaus-api.abuse.ch/v2/files/exports/{ABUSECH_AUTH_KEY}/recent.csv"
    ),
}


async def seed_reference_feeds(session: AsyncSession) -> list[str]:
    """Insère les flux de référence absents et corrige les URL de référence obsolètes.

    Retourne les noms des flux créés ou mis à jour.
    """
    result = await session.execute(select(ThreatFeed))
    existing = {feed.name: feed for feed in result.scalars().all()}

    created: list[str] = []
    for current in existing.values():
        replacement = OBSOLETE_URLS.get(current.url)
        if replacement is not None:
            current.url = replacement
            current.status = FeedStatus.PENDING
            current.last_error = None
            created.append(f"{current.name} (URL mise à jour)")

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
