"""État d'avancement mesuré (`illwatch status`) : indicateurs et critères du jalon M2."""

from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import ThreatFeed
from illwatch.modules.foundation.status import compute_status
from illwatch.modules.threat_feeds.indicators import Observation, ingest_indicators
from illwatch.shared.enums import FeedStatus, FeedType

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


async def test_jalons_m4_m6(db_session: AsyncSession) -> None:
    from illwatch.app.config import Settings
    from illwatch.modules.incidents import service as incidents
    from illwatch.modules.threat_hunting import engine
    from illwatch.shared.enums import IncidentStatus, Severity

    before = await compute_status(db_session, now=NOW)
    assert [c.met for c in before.later] == [False, False]

    incident = await incidents.create_incident(
        db_session, title="x", description="x", severity=Severity.LOW, author_id=None
    )
    for target in ("ANALYSE", "CONFINEMENT", "ERADICATION", "RECUPERATION"):
        await incidents.transition(db_session, incident.id, IncidentStatus(target), author_id=None)
    await incidents.transition(
        db_session, incident.id, IncidentStatus.CLOTURE, author_id=None, closure_summary="ok"
    )

    async def no_tor(url: str) -> bytes:
        return b""

    await engine.run_hunt(
        db_session,
        settings=Settings(secret_key="k" * 64),
        fetch=no_tor,
        observables=["c2.duckdns.org"],
    )
    after = await compute_status(db_session, now=NOW)
    assert [c.met for c in after.later] == [True, True]


async def test_alerte_epss_perime(db_session: AsyncSession) -> None:
    from illwatch.app.models import CVE, CollectorState

    # Identifiant propre au test : d'autres tests (CLI) valident de vraies CVE en base, et
    # peuvent y laisser l'état de synchronisation « epss ».
    db_session.add(
        CVE(
            id="CVE-2099-0001",
            description="CVE de test",
            is_kev=True,
            has_ransomware_campaign=True,
            published_date=NOW,
            last_modified_date=NOW,
        )
    )
    state = await db_session.get(CollectorState, "epss")
    if state is None:
        state = CollectorState(name="epss", items=1)
        db_session.add(state)
    state.last_success_at = None
    await db_session.flush()
    never = await compute_status(db_session, now=NOW)
    assert any("EPSS jamais synchronisé" in w for w in never.warnings)

    state.last_success_at = NOW - timedelta(hours=72)
    await db_session.flush()
    stale = await compute_status(db_session, now=NOW)
    assert any("non synchronisé depuis 72 h" in w for w in stale.warnings)

    fresh = await compute_status(db_session, now=NOW - timedelta(hours=60))
    assert fresh.warnings == []
