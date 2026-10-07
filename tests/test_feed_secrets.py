"""Secrets de flux : gabarit en base, résolution à la requête, masquage (URLhaus Auth-Key)."""

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.config import Settings, get_settings
from illwatch.app.models import ThreatFeed
from illwatch.modules.foundation.seed import seed_reference_feeds
from illwatch.modules.threat_feeds.collector import collect_feed
from illwatch.modules.threat_feeds.fetcher import FetchError, fetch_feed_content
from illwatch.modules.threat_feeds.secrets import (
    MissingFeedSecretError,
    mask_secrets,
    resolve_feed_url,
)
from illwatch.modules.threat_feeds.service import UnsafeFeedURLError, validate_feed_url
from illwatch.shared.enums import FeedStatus, FeedType

TEMPLATE = "https://urlhaus-api.abuse.ch/v2/files/exports/{ABUSECH_AUTH_KEY}/recent.csv"
KEY = "s3cr3t/Key+42"
WITH_KEY = Settings(secret_key="k" * 64, abusech_auth_key=SecretStr(KEY))
WITHOUT_KEY = Settings(secret_key="k" * 64)


def test_resolution_encode_le_secret() -> None:
    assert resolve_feed_url(TEMPLATE, WITH_KEY) == (
        "https://urlhaus-api.abuse.ch/v2/files/exports/s3cr3t%2FKey%2B42/recent.csv"
    )


def test_secret_absent() -> None:
    with pytest.raises(MissingFeedSecretError, match="ABUSECH_AUTH_KEY"):
        resolve_feed_url(TEMPLATE, WITHOUT_KEY)


def test_masquage_brut_et_encode() -> None:
    text = f"échec sur .../exports/{KEY}/ et .../exports/s3cr3t%2FKey%2B42/"
    assert KEY not in mask_secrets(text, WITH_KEY)
    assert "s3cr3t%2FKey%2B42" not in mask_secrets(text, WITH_KEY)


def test_gabarit_accepte_a_l_enregistrement_parametre_inconnu_refuse() -> None:
    assert validate_feed_url(TEMPLATE) == TEMPLATE
    with pytest.raises(UnsafeFeedURLError, match="inconnu"):
        validate_feed_url("https://feeds.example.org/{DB_PASSWORD}/x.csv")


async def test_la_requete_part_avec_la_cle_resolue() -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return httpx.Response(200, content=b"1.2.3.4\n")

    async def resolver(host: str, port: int) -> list[str]:
        return ["93.184.216.34"]

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await fetch_feed_content(TEMPLATE, settings=WITH_KEY, client=client, resolver=resolver)
    assert requested == [resolve_feed_url(TEMPLATE, WITH_KEY)]


async def test_cle_absente_erreur_explicite() -> None:
    with pytest.raises(FetchError, match="non configuré"):
        await fetch_feed_content(TEMPLATE, settings=WITHOUT_KEY)


async def test_la_cle_n_apparait_jamais_dans_last_error(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ABUSECH_AUTH_KEY", KEY)
    get_settings.cache_clear()
    try:
        feed = ThreatFeed(name="URLhaus", url=TEMPLATE, feed_type=FeedType.CSV)
        db_session.add(feed)
        await db_session.flush()

        async def leaky_fetch(url: str) -> bytes:
            raise FetchError(f"HTTP 403 sur {resolve_feed_url(url, get_settings())}")

        report = await collect_feed(db_session, feed, fetch=leaky_fetch)
        assert feed.status == FeedStatus.DEGRADED
        assert feed.last_error is not None and KEY not in feed.last_error
        assert "s3cr3t%2FKey%2B42" not in feed.last_error
        assert "***" in feed.last_error and report.error == feed.last_error
    finally:
        get_settings.cache_clear()


async def test_seed_corrige_l_ancienne_url_urlhaus(db_session: AsyncSession) -> None:
    old = ThreatFeed(
        name="abuse.ch URLhaus — URL malveillantes récentes",
        url="https://urlhaus.abuse.ch/downloads/csv_recent/",
        feed_type=FeedType.CSV,
        status=FeedStatus.DEGRADED,
        last_error="HTTP 401",
    )
    custom = ThreatFeed(name="Perso", url="https://feeds.example.org/x.csv", feed_type=FeedType.CSV)
    db_session.add_all([old, custom])
    await db_session.flush()

    changed = await seed_reference_feeds(db_session)

    assert old.url == TEMPLATE
    assert old.status == FeedStatus.PENDING and old.last_error is None
    assert custom.url == "https://feeds.example.org/x.csv"
    assert any("URL mise à jour" in name for name in changed)
