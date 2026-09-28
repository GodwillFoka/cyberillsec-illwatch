"""Provenance multi-sources des IOC — `indicator_sources` (ADR-006, Sprint 3 tâche 1.3)."""

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app.models import Indicator, IndicatorSource, ThreatFeed
from sentry.app.security import create_access_token
from sentry.modules.foundation.users import create_user
from sentry.modules.threat_feeds.indicators import (
    Observation,
    get_indicator,
    ingest_indicators,
    list_indicators,
)
from sentry.shared.enums import FeedType, UserRole

NOW = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


async def _feeds(session: AsyncSession, *names: str) -> list[ThreatFeed]:
    feeds = [
        ThreatFeed(name=n, url=f"https://{n.lower()}.example.org/f", feed_type=FeedType.CSV)
        for n in names
    ]
    session.add_all(feeds)
    await session.flush()
    return feeds


async def test_un_ioc_vu_par_deux_flux_liste_les_deux(db_session: AsyncSession) -> None:
    urlhaus, otx = await _feeds(db_session, "URLhaus", "OTX")
    await ingest_indicators(
        db_session, [Observation("evil.example.com")], feed_id=urlhaus.id, now=NOW - timedelta(2)
    )
    await ingest_indicators(db_session, [Observation("EVIL.example.com")], feed_id=otx.id, now=NOW)
    await ingest_indicators(db_session, [Observation("evil.example.com")], feed_id=otx.id, now=NOW)

    ioc = (await db_session.execute(select(Indicator))).scalar_one()
    assert ioc.hit_count == 3
    assert ioc.feed_id == urlhaus.id  # première source connue, inchangée

    loaded = await get_indicator(db_session, ioc.id)
    by_feed = {s.feed_id: s for s in loaded.sources}
    assert set(by_feed) == {urlhaus.id, otx.id}
    assert by_feed[urlhaus.id].hit_count == 1
    assert by_feed[otx.id].hit_count == 2
    assert _utc(by_feed[urlhaus.id].first_seen) == NOW - timedelta(2)
    assert _utc(by_feed[otx.id].first_seen) == NOW
    assert [s.feed_id for s in loaded.sources] == [urlhaus.id, otx.id]  # ordre chronologique


async def test_ingestion_manuelle_sans_source(db_session: AsyncSession) -> None:
    await ingest_indicators(db_session, [Observation("203.0.113.5")], now=NOW)
    assert (await db_session.execute(select(IndicatorSource))).first() is None


async def test_filtre_par_flux_couvre_toutes_les_sources(db_session: AsyncSession) -> None:
    first, second = await _feeds(db_session, "Premier", "Second")
    await ingest_indicators(db_session, [Observation("a.example.com")], feed_id=first.id, now=NOW)
    await ingest_indicators(
        db_session,
        [Observation("a.example.com"), Observation("b.example.com")],
        feed_id=second.id,
        now=NOW,
    )
    page = await list_indicators(db_session, limit=10, offset=0, feed_id=second.id, now=NOW)
    assert {i.value for i in page.items} == {"a.example.com", "b.example.com"}
    page = await list_indicators(db_session, limit=10, offset=0, feed_id=first.id, now=NOW)
    assert {i.value for i in page.items} == {"a.example.com"}


@pytest.mark.postgres
async def test_suppression_d_un_flux_efface_sa_provenance(db_session: AsyncSession) -> None:
    first, second = await _feeds(db_session, "Premier", "Second")
    for feed in (first, second):
        await ingest_indicators(db_session, [Observation("c.example.com")], feed_id=feed.id)
    first_id, second_id = first.id, second.id
    await db_session.execute(delete(ThreatFeed).where(ThreatFeed.id == first_id))
    db_session.expire_all()

    sources = (await db_session.execute(select(IndicatorSource))).scalars().all()
    assert [s.feed_id for s in sources] == [second_id]
    ioc = (await db_session.execute(select(Indicator))).scalar_one()
    assert ioc.feed_id is None  # l'IOC est conservé, sa première source a disparu


Headers = dict[str, str]


@pytest.fixture
def viewer(db_session: AsyncSession) -> Callable[[], Awaitable[Headers]]:
    async def _make() -> Headers:
        name = f"viewer-{uuid4().hex[:8]}"
        user = await create_user(
            db_session,
            username=name,
            email=f"{name}@cyberill.test",
            password="mot-de-passe-robuste-2026",
            role=UserRole.VIEWER,
        )
        return {"Authorization": f"Bearer {create_access_token(user.id, user.role)}"}

    return _make


async def test_api_detail_expose_la_provenance(
    client: AsyncClient,
    db_session: AsyncSession,
    viewer: Callable[[], Awaitable[Headers]],
) -> None:
    first, second = await _feeds(db_session, "Premier", "Second")
    for feed in (first, second):
        await ingest_indicators(db_session, [Observation("d.example.com")], feed_id=feed.id)
    ioc = (await db_session.execute(select(Indicator))).scalar_one()

    body = (await client.get(f"/api/v1/indicators/{ioc.id}", headers=await viewer())).json()
    assert body["source_count"] == 2
    assert {s["feed_name"] for s in body["sources"]} == {"Premier", "Second"}
    assert all(s["hit_count"] == 1 for s in body["sources"])

    listing = (await client.get("/api/v1/indicators", headers=await viewer())).json()
    assert listing["items"][0]["source_count"] == 2
    assert "sources" not in listing["items"][0]  # détail seulement : liste légère
