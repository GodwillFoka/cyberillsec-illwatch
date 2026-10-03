"""Cycle de vie des IOC — ingestion dédupliquée (RF-08, ADR-005)."""

import time
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app.models import Indicator, ThreatFeed
from sentry.modules.threat_feeds.indicators import (
    Observation,
    ingest_indicators,
    list_indicators,
)
from sentry.shared.enums import FeedType, IndicatorType, Severity

T0 = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)


def _utc(value: datetime | None) -> datetime | None:
    """SQLite rend des dates naïves (en UTC) ; PostgreSQL des dates avec fuseau."""
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


async def _one(session: AsyncSession, value: str) -> Indicator:
    return (await session.execute(select(Indicator).where(Indicator.value == value))).scalar_one()


async def test_premiere_ingestion(db_session: AsyncSession) -> None:
    result = await ingest_indicators(
        db_session, [Observation("198.51.100.7", severity=Severity.HIGH)], now=T0
    )
    assert (result.received, result.inserted, result.updated) == (1, 1, 0)

    ioc = await _one(db_session, "198.51.100.7")
    assert ioc.type == IndicatorType.IPV4
    assert ioc.hit_count == 1
    assert _utc(ioc.first_seen) == _utc(ioc.last_seen) == T0
    assert _utc(ioc.expires_at) == T0 + timedelta(days=30)


async def test_reobservation_met_a_jour_sans_dupliquer(db_session: AsyncSession) -> None:
    await ingest_indicators(db_session, [Observation("evil.example.com")], now=T0)
    later = T0 + timedelta(days=10)
    result = await ingest_indicators(db_session, [Observation("EVIL.example.COM.")], now=later)

    assert (result.inserted, result.updated) == (0, 1)
    count = await db_session.scalar(select(func.count()).select_from(Indicator))
    assert count == 1
    ioc = await _one(db_session, "evil.example.com")
    assert ioc.hit_count == 2
    assert _utc(ioc.first_seen) == T0
    assert _utc(ioc.last_seen) == later
    assert _utc(ioc.expires_at) == later + timedelta(days=90)  # validité repoussée


async def test_doublons_d_un_meme_lot_comptent_une_seule_observation(
    db_session: AsyncSession,
) -> None:
    result = await ingest_indicators(
        db_session,
        [Observation("example[.]org"), Observation("Example.ORG"), Observation("example.org")],
        now=T0,
    )
    assert (result.inserted, result.duplicates_in_batch) == (1, 2)
    assert (await _one(db_session, "example.org")).hit_count == 1


async def test_la_severite_ne_baisse_jamais(db_session: AsyncSession) -> None:
    await ingest_indicators(db_session, [Observation("a" * 64, severity=Severity.CRITICAL)], now=T0)
    await ingest_indicators(db_session, [Observation("a" * 64, severity=Severity.LOW)], now=T0)
    assert (await _one(db_session, "a" * 64)).severity == Severity.CRITICAL

    await ingest_indicators(db_session, [Observation("b" * 64, severity=Severity.LOW)], now=T0)
    await ingest_indicators(db_session, [Observation("b" * 64, severity=Severity.HIGH)], now=T0)
    assert (await _one(db_session, "b" * 64)).severity == Severity.HIGH


async def test_observation_ancienne_rapportee_tardivement(db_session: AsyncSession) -> None:
    await ingest_indicators(db_session, [Observation("203.0.113.9")], now=T0)
    earlier = T0 - timedelta(days=5)
    await ingest_indicators(
        db_session, [Observation("203.0.113.9", observed_at=earlier)], now=T0 + timedelta(hours=1)
    )
    ioc = await _one(db_session, "203.0.113.9")
    assert _utc(ioc.first_seen) == earlier  # recule
    assert _utc(ioc.last_seen) == T0  # n'avance pas pour une observation plus ancienne
    assert ioc.hit_count == 2


async def test_date_future_ramenee_a_maintenant(db_session: AsyncSession) -> None:
    await ingest_indicators(
        db_session, [Observation("203.0.113.10", observed_at=T0 + timedelta(days=3))], now=T0
    )
    assert _utc((await _one(db_session, "203.0.113.10")).last_seen) == T0


async def test_hash_sans_expiration(db_session: AsyncSession) -> None:
    await ingest_indicators(db_session, [Observation("d41d8cd98f00b204e9800998ecf8427e")], now=T0)
    assert (await _one(db_session, "d41d8cd98f00b204e9800998ecf8427e")).expires_at is None


async def test_valeurs_invalides_rejetees_et_listees(db_session: AsyncSession) -> None:
    result = await ingest_indicators(
        db_session,
        [
            Observation("pas un ioc"),
            Observation("198.51.100.8", type=IndicatorType.DOMAIN),
            Observation("198.51.100.9"),
        ],
        now=T0,
    )
    assert result.inserted == 1
    assert [r.value for r in result.rejected] == ["pas un ioc", "198.51.100.8"]
    assert "type détecté" in result.rejected[1].reason


async def test_provenance_conserve_la_premiere_source(db_session: AsyncSession) -> None:
    first = ThreatFeed(name="A", url="https://a.example.org/f", feed_type=FeedType.CSV)
    second = ThreatFeed(name="B", url="https://b.example.org/f", feed_type=FeedType.CSV)
    db_session.add_all([first, second])
    await db_session.flush()

    await ingest_indicators(db_session, [Observation("x.example.net")], feed_id=first.id, now=T0)
    await ingest_indicators(db_session, [Observation("x.example.net")], feed_id=second.id, now=T0)
    assert (await _one(db_session, "x.example.net")).feed_id == first.id


async def test_expiration_et_filtre_actif(db_session: AsyncSession) -> None:
    await ingest_indicators(db_session, [Observation("198.51.100.20")], now=T0)
    await ingest_indicators(db_session, [Observation("c" * 64)], now=T0)

    later = T0 + timedelta(days=31)  # l'IP a expiré, le hash n'expire pas
    actives = await list_indicators(db_session, limit=10, offset=0, now=later, active=True)
    expired = await list_indicators(db_session, limit=10, offset=0, now=later, active=False)
    assert [i.value for i in actives.items] == ["c" * 64]
    assert [i.value for i in expired.items] == ["198.51.100.20"]

    # L'IOC expiré est conservé ; une ré-observation le réactive.
    await ingest_indicators(db_session, [Observation("198.51.100.20")], now=later)
    reactivated = await list_indicators(db_session, limit=10, offset=0, now=later, active=True)
    assert {i.value for i in reactivated.items} == {"198.51.100.20", "c" * 64}


async def test_recherche_par_valeur_normalisee(db_session: AsyncSession) -> None:
    await ingest_indicators(db_session, [Observation("hxxps://Evil.example.com/x")], now=T0)
    page = await list_indicators(
        db_session, limit=10, offset=0, now=T0, value="https://EVIL.example.com:443/x"
    )
    assert [i.value for i in page.items] == ["https://evil.example.com/x"]


@pytest.mark.postgres
async def test_performance_rnf_perf_02(db_session: AsyncSession) -> None:
    """RNF-PERF-02 : 1 000 IOC ingérés en moins de 5 secondes, puis réingérés (mises à jour)."""
    batch = [Observation(f"perf-{i}.example.com") for i in range(1000)]

    start = time.perf_counter()
    first = await ingest_indicators(db_session, batch, now=T0)
    insert_duration = time.perf_counter() - start

    start = time.perf_counter()
    second = await ingest_indicators(db_session, batch, now=T0 + timedelta(hours=1))
    update_duration = time.perf_counter() - start

    assert first.inserted == 1000
    assert second.updated == 1000
    assert insert_duration < 5.0, insert_duration
    assert update_duration < 5.0, update_duration


async def test_rejets_comptes_mais_echantillon_borne(db_session: AsyncSession) -> None:
    from sentry.modules.threat_feeds.indicators import MAX_REJECTION_SAMPLES

    garbage = [Observation(f"n'importe quoi {i}") for i in range(MAX_REJECTION_SAMPLES + 50)]
    result = await ingest_indicators(db_session, garbage, now=T0)
    assert result.rejected_count == MAX_REJECTION_SAMPLES + 50
    assert len(result.rejected) == MAX_REJECTION_SAMPLES
