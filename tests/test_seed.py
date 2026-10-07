"""Tests de l'amorçage des données de référence — `illwatch seed`."""

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import ThreatFeed
from illwatch.modules.foundation.seed import REFERENCE_FEEDS, seed_reference_feeds


async def test_seed_est_idempotent(db_session: AsyncSession) -> None:
    first = await seed_reference_feeds(db_session)
    second = await seed_reference_feeds(db_session)

    assert len(first) == len(REFERENCE_FEEDS)
    assert second == []

    count = await db_session.scalar(select(func.count()).select_from(ThreatFeed))
    assert count == len(REFERENCE_FEEDS)


def test_sources_de_reference_conformes_aux_regles_de_l_api() -> None:
    """Le seed écrit directement en base : ses URL doivent passer les mêmes contrôles
    que celles saisies par un administrateur (SSRF, OTX limité à l'API OTX…)."""
    from illwatch.modules.threat_feeds.secrets import placeholders
    from illwatch.modules.threat_feeds.service import ensure_url_fits_type, validate_feed_url

    for feed in REFERENCE_FEEDS:
        url = feed.url
        for name in placeholders(url):
            url = url.replace("{" + name + "}", "cle")
        assert validate_feed_url(url) == url, feed.name
        ensure_url_fits_type(url, feed.feed_type)
        assert len(feed.name) <= 100
    assert len({f.name.lower() for f in REFERENCE_FEEDS}) == len(REFERENCE_FEEDS)
