"""Orchestration de la collecte — UC-01, isolation des pannes (RSK-02)."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import Indicator, ThreatFeed
from illwatch.modules.threat_feeds.collector import collect_due_feeds, collect_feed, is_due
from illwatch.modules.threat_feeds.fetcher import FetchError, RateLimitedError
from illwatch.shared.enums import FeedStatus, FeedType

FIXTURES = Path(__file__).parent / "fixtures" / "feeds"
NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)


def _clock() -> datetime:
    return NOW


def _serving(payloads: dict[str, bytes | Exception]) -> Callable[[str], object]:
    async def fetch(url: str) -> bytes:
        outcome = payloads[url]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    return fetch


async def _feed(session: AsyncSession, name: str, feed_type: FeedType, **kw: object) -> ThreatFeed:
    feed = ThreatFeed(
        name=name, url=f"https://{name.lower()}.example.org/feed", feed_type=feed_type, **kw
    )
    session.add(feed)
    await session.flush()
    return feed


async def test_collecte_reussie(db_session: AsyncSession) -> None:
    feed = await _feed(db_session, "URLhaus", FeedType.CSV)
    feed.last_error = "ancienne erreur"
    fetch = _serving({feed.url: (FIXTURES / "urlhaus_recent.csv").read_bytes()})

    report = await collect_feed(db_session, feed, fetch=fetch, clock=_clock)  # type: ignore[arg-type]

    assert report.succeeded
    assert report.parsed == 4
    assert report.inserted == 2  # deux graphies de la même URL + une valeur invalide
    assert report.rejected == 1
    assert report.rejected_samples == ["not a url at all"]
    assert feed.status == FeedStatus.HEALTHY
    assert feed.last_successful_run == NOW
    assert feed.last_error is None

    iocs = (await db_session.execute(select(Indicator))).scalars().all()
    assert {i.feed_id for i in iocs} == {feed.id}


async def test_echec_reseau_degrade_le_flux_sans_rien_ingerer(db_session: AsyncSession) -> None:
    feed = await _feed(db_session, "Panne", FeedType.CSV)
    fetch = _serving({feed.url: FetchError("HTTP 502 renvoyé par la source. (3 tentatives).")})

    report = await collect_feed(db_session, feed, fetch=fetch, clock=_clock)  # type: ignore[arg-type]

    assert not report.succeeded
    assert feed.status == FeedStatus.DEGRADED
    assert feed.last_error is not None and "502" in feed.last_error
    assert feed.last_successful_run is None


async def test_contenu_illisible_degrade_le_flux(db_session: AsyncSession) -> None:
    feed = await _feed(db_session, "Corrompu", FeedType.JSON)
    fetch = _serving({feed.url: b"<html>maintenance</html>"})
    report = await collect_feed(db_session, feed, fetch=fetch, clock=_clock)  # type: ignore[arg-type]
    assert feed.status == FeedStatus.DEGRADED
    assert report.error is not None and "JSON" in report.error


async def test_limite_de_debit_ne_change_pas_le_statut(db_session: AsyncSession) -> None:
    feed = await _feed(db_session, "Limité", FeedType.CSV, status=FeedStatus.HEALTHY)
    fetch = _serving({feed.url: RateLimitedError(300)})
    report = await collect_feed(db_session, feed, fetch=fetch, clock=_clock)  # type: ignore[arg-type]
    assert not report.succeeded
    assert feed.status == FeedStatus.HEALTHY
    assert feed.last_error is not None and "300 s" in feed.last_error


async def test_erreur_inattendue_isolee(db_session: AsyncSession) -> None:
    feed = await _feed(db_session, "Bug", FeedType.CSV)
    fetch = _serving({feed.url: RuntimeError("boom")})
    report = await collect_feed(db_session, feed, fetch=fetch, clock=_clock)  # type: ignore[arg-type]
    assert feed.status == FeedStatus.DEGRADED
    assert report.error is not None and "RuntimeError" in report.error


async def test_une_panne_n_empeche_pas_les_autres_flux(db_session: AsyncSession) -> None:
    good = await _feed(db_session, "Bon", FeedType.CSV)
    bad = await _feed(db_session, "Mauvais", FeedType.CSV)
    stix = await _feed(db_session, "Stix", FeedType.STIX)
    fetch = _serving(
        {
            good.url: (FIXTURES / "feodo_ipblocklist.csv").read_bytes(),
            bad.url: FetchError("timeout"),
            stix.url: (FIXTURES / "stix_bundle.json").read_bytes(),
        }
    )

    reports = await collect_due_feeds(db_session, fetch=fetch, clock=_clock)  # type: ignore[arg-type]

    assert [r.feed_name for r in reports] == ["Bon", "Mauvais", "Stix"]
    assert [r.succeeded for r in reports] == [True, False, True]
    assert (good.status, bad.status, stix.status) == (
        FeedStatus.HEALTHY,
        FeedStatus.DEGRADED,
        FeedStatus.HEALTHY,
    )
    count = await db_session.scalar(select(func.count()).select_from(Indicator))
    assert count == 3 + 4


async def test_echeance_des_flux(db_session: AsyncSession) -> None:
    never = await _feed(db_session, "Jamais", FeedType.CSV)
    recent = await _feed(
        db_session, "Récent", FeedType.CSV, last_successful_run=NOW - timedelta(minutes=10)
    )
    old = await _feed(
        db_session, "Ancien", FeedType.CSV, last_successful_run=NOW - timedelta(hours=2)
    )
    off = await _feed(db_session, "Inactif", FeedType.CSV, is_active=False)

    assert is_due(never, NOW) and is_due(old, NOW)
    assert not is_due(recent, NOW) and not is_due(off, NOW)

    fetch = _serving({f.url: b"1.2.3.4\n" for f in (never, recent, old, off)})
    due = await collect_due_feeds(db_session, fetch=fetch, clock=_clock)  # type: ignore[arg-type]
    assert {r.feed_name for r in due} == {"Jamais", "Ancien"}

    forced = await collect_due_feeds(db_session, force=True, fetch=fetch, clock=_clock)  # type: ignore[arg-type]
    assert {r.feed_name for r in forced} == {"Jamais", "Récent", "Ancien"}
