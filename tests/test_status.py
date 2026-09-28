"""État d'avancement mesuré (`sentry status`) : indicateurs et critères du jalon M2."""

from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app.models import ThreatFeed
from sentry.modules.foundation.status import compute_status
from sentry.modules.threat_feeds.indicators import Observation, ingest_indicators
from sentry.shared.enums import FeedStatus, FeedType

NOW = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)


async def test_base_vide(db_session: AsyncSession) -> None:
    state = await compute_status(db_session, now=NOW)
    assert (state.feeds_total, state.iocs_total) == (0, 0)
    assert not state.m2_reached
    assert [c.met for c in state.m2] == [False, False, False, False]


async def test_criteres_m2_atteints(db_session: AsyncSession) -> None:
    feeds = [
        ThreatFeed(name="URLhaus", url="https://u.example.org/f", feed_type=FeedType.CSV),
        ThreatFeed(
            name="OTX",
            url="https://otx.alienvault.com/api/v1/pulses/subscribed",
            feed_type=FeedType.OTX,
        ),
        ThreatFeed(name="CERT", url="https://c.example.org/b.json", feed_type=FeedType.STIX),
        ThreatFeed(name="Panne", url="https://p.example.org/f", feed_type=FeedType.CSV),
    ]
    for feed in feeds[:3]:
        feed.status = FeedStatus.HEALTHY
    feeds[3].status = FeedStatus.DEGRADED
    db_session.add_all(feeds)
    await db_session.flush()

    await ingest_indicators(
        db_session,
        [Observation(f"ioc-{i}.example.com") for i in range(500)],
        feed_id=feeds[0].id,
        now=NOW - timedelta(days=1),
    )
    await ingest_indicators(
        db_session,
        [Observation(f"ioc-{i}.example.com") for i in range(3)],
        feed_id=feeds[1].id,
        now=NOW - timedelta(hours=1),
    )
    await ingest_indicators(db_session, [Observation("198.51.100.1")], now=NOW - timedelta(days=60))

    state = await compute_status(db_session, now=NOW)
    assert state.feeds_by_status == {"HEALTHY": 3, "DEGRADED": 1}
    assert state.iocs_total == 501
    assert state.iocs_from_feeds == 500
    assert state.iocs_multi_source == 3  # rapportés par URLhaus puis par OTX
    assert state.iocs_active == 500  # l'IP observée il y a 60 j a expiré (30 j)
    assert state.iocs_by_type == {"DOMAIN": 500, "IPV4": 1}
    assert state.m2_reached
