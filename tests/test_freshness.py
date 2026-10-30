"""Transparence du renseignement (ADR-031) : fraîcheur des IOC rapportée à la demi-vie de leur
type, sources visibles dans la liste, fraîcheur des catalogues NVD, KEV et EPSS."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import CollectorState, ThreatFeed
from illwatch.app.security import create_access_token
from illwatch.modules.foundation.users import create_user
from illwatch.modules.threat_feeds.freshness import catalogue_freshness, ioc_freshness
from illwatch.modules.threat_feeds.indicators import Observation, ingest_indicators
from illwatch.shared.enums import FeedType, UserRole

NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)


def test_fraicheur_selon_la_demi_vie_du_type() -> None:
    def status(ioc_type: str, days: float, expires: datetime | None = None) -> str:
        return ioc_freshness(
            ioc_type=ioc_type, last_seen=NOW - timedelta(days=days), expires_at=expires, now=NOW
        ).status

    # Adresse IP : demi-vie de 7 jours.
    assert status("IPV4", 3) == "fresh"
    assert status("IPV4", 10) == "aging"
    assert status("IPV4", 22) == "stale"
    # Empreinte : demi-vie de 180 jours ; dix jours, c'est récent.
    assert status("HASH_SHA256", 10) == "fresh"
    # Une date d'expiration passée l'emporte sur tout le reste.
    assert status("IPV4", 1, expires=NOW - timedelta(minutes=1)) == "expired"
    detail = ioc_freshness(
        ioc_type="DOMAIN", last_seen=NOW - timedelta(days=45), expires_at=None, now=NOW
    )
    assert (detail.age_days, detail.half_life_days, detail.status) == (45.0, 30.0, "aging")


async def test_fraicheur_des_catalogues(db_session: AsyncSession) -> None:
    db_session.add_all(
        [
            CollectorState(name="nvd", last_success_at=NOW - timedelta(hours=2), items=10),
            CollectorState(
                name="epss",
                last_success_at=NOW - timedelta(hours=72),
                items=5,
                last_error="HTTP 503",
            ),
        ]
    )
    await db_session.flush()
    rows = {c.key: c for c in await catalogue_freshness(db_session, NOW)}
    assert rows["nvd"].status == "fresh" and rows["nvd"].age_hours == 2.0
    assert rows["epss"].status == "stale" and rows["epss"].last_error == "HTTP 503"
    assert rows["kev"].status == "never" and rows["kev"].last_success_at is None
    assert [c.max_age_hours for c in rows.values()] == [24, 24, 48]


async def test_api_sources_et_fraicheur_visibles(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    sure = ThreatFeed(
        name="Source sûre", url="https://a.example/f.csv", feed_type=FeedType.CSV, reliability="A"
    )
    douteuse = ThreatFeed(
        name="Source douteuse",
        url="https://b.example/f.csv",
        feed_type=FeedType.CSV,
        reliability="E",
    )
    db_session.add_all([sure, douteuse])
    await db_session.flush()
    await ingest_indicators(db_session, [Observation("203.0.113.44")], feed_id=douteuse.id)
    await ingest_indicators(db_session, [Observation("203.0.113.44")], feed_id=sure.id)
    db_session.add(CollectorState(name="kev", last_success_at=datetime.now(UTC), items=1))
    await db_session.flush()
    name = f"viewer-{uuid4().hex[:8]}"
    viewer = await create_user(
        db_session,
        username=name,
        email=f"{name}@cyberill.test",
        password="mot-de-passe-robuste-2026",
        role=UserRole.VIEWER,
    )
    headers = {"Authorization": f"Bearer {create_access_token(viewer.id, viewer.role)}"}

    page = await client.get("/api/v1/indicators", params={"value": "203.0.113.44"}, headers=headers)
    assert page.status_code == 200
    item = page.json()["items"][0]
    assert item["freshness"]["status"] == "fresh" and item["freshness"]["half_life_days"] == 7.0
    assert [s["name"] for s in item["sources_preview"]] == ["Source sûre", "Source douteuse"]
    assert item["sources_preview"][0]["reliability"] == "A"

    detail = await client.get(f"/api/v1/indicators/{item['id']}", headers=headers)
    assert detail.json()["freshness"]["status"] == "fresh"
    assert detail.json()["sources_preview"][0]["name"] == "Source sûre"

    catalogues = await client.get("/api/v1/cves/freshness", headers=headers)
    assert catalogues.status_code == 200
    by_key = {c["key"]: c for c in catalogues.json()}
    assert by_key["kev"]["status"] == "fresh" and by_key["nvd"]["status"] == "never"
