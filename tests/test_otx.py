"""Connecteur AlienVault OTX (T2.9) : analyse, pagination, clé API, garde-fous."""

from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app.config import Settings, get_settings
from sentry.app.models import Indicator, ThreatFeed
from sentry.modules.threat_feeds.collector import collect_feed
from sentry.modules.threat_feeds.fetcher import FetchError
from sentry.modules.threat_feeds.otx import (
    API_KEY_HEADER,
    fetch_otx,
    parse_otx_page,
    with_modified_since,
)
from sentry.modules.threat_feeds.parsers import FeedParseError
from sentry.shared.enums import FeedStatus, FeedType, IndicatorType

FIXTURES = Path(__file__).parent / "fixtures" / "feeds"
FEED_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50"
PAGE2 = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50&page=2"
KEY = "otx-cle-de-test-0123456789abcdef"
NOW = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)


def _settings(**kw: object) -> Settings:
    return Settings(secret_key="k" * 64, otx_api_key=SecretStr(KEY), **kw)  # type: ignore[arg-type]


class _Server:
    """Faux serveur OTX : enregistre les URL et en-têtes reçus."""

    def __init__(self, pages: dict[str, bytes]) -> None:
        self.pages = pages
        self.calls: list[tuple[str, Mapping[str, str] | None]] = []

    async def __call__(self, url: str, *, headers: Mapping[str, str] | None = None) -> bytes:
        self.calls.append((url, headers))
        return self.pages[url.split("&modified_since")[0]]


def _two_pages() -> _Server:
    return _Server(
        {
            FEED_URL: (FIXTURES / "otx_page1.json").read_bytes(),
            PAGE2: (FIXTURES / "otx_page2.json").read_bytes(),
        }
    )


def test_analyse_d_une_page() -> None:
    parsed, pulses, next_url = parse_otx_page((FIXTURES / "otx_page1.json").read_bytes())
    assert pulses == 2
    assert next_url == PAGE2
    assert [(o.value, o.type) for o in parsed.observations] == [
        ("203.0.113.10", IndicatorType.IPV4),
        ("c2-qakbot[.]example[.]net", IndicatorType.DOMAIN),
        ("https://login-banque.example.org/verify", IndicatorType.URL),
        ("44d88612fea8a8f36de82e1278abb02f", IndicatorType.HASH_MD5),
    ]
    assert parsed.skipped == 3  # CVE, CIDR, indicateur inactif
    assert parsed.observations[0].description == "Campagne QakBot — infrastructure C2"
    # Sans date propre, l'IOC prend la date de modification du pulse.
    assert parsed.observations[2].observed_at == datetime(2026, 9, 27, 9, 0, tzinfo=UTC)


@pytest.mark.parametrize("content", [b"{pas du json", b'{"detail": "Authentication required"}'])
def test_reponse_illisible(content: bytes) -> None:
    with pytest.raises(FeedParseError):
        parse_otx_page(content)


def test_modified_since_ajoute_avec_marge() -> None:
    url = with_modified_since(FEED_URL + "&modified_since=ancien", NOW)
    assert url.endswith("limit=50&modified_since=2026-09-28T11%3A45%3A00")
    assert with_modified_since(FEED_URL, None) == FEED_URL


async def test_pagination_complete_et_cle_en_en_tete() -> None:
    server = _two_pages()
    outcome = await fetch_otx(FEED_URL, settings=_settings(), fetch=server)
    assert (outcome.pages, outcome.pulses, outcome.truncated) == (2, 3, False)
    assert len(outcome.parsed.observations) == 6
    assert [url for url, _ in server.calls] == [FEED_URL, PAGE2]
    assert all(h is not None and h[API_KEY_HEADER] == KEY for _, h in server.calls)
    assert all(KEY not in url for url, _ in server.calls)  # jamais dans l'URL


async def test_pagination_plafonnee() -> None:
    outcome = await fetch_otx(FEED_URL, settings=_settings(otx_max_pages=1), fetch=_two_pages())
    assert (outcome.pages, outcome.truncated) == (1, True)


async def test_cle_absente() -> None:
    settings = Settings(secret_key="k" * 64)
    with pytest.raises(FetchError, match="OTX_API_KEY"):
        await fetch_otx(FEED_URL, settings=settings, fetch=_two_pages())


@pytest.mark.parametrize(
    "url",
    ["https://evil.example.org/api/v1/pulses/subscribed", "http://otx.alienvault.com/api/v1/x"],
)
async def test_la_cle_ne_part_jamais_ailleurs(url: str) -> None:
    server = _two_pages()
    with pytest.raises(FetchError, match="refusée"):
        await fetch_otx(url, settings=_settings(), fetch=server)
    assert server.calls == []


async def test_lien_next_hors_otx_refuse() -> None:
    page = b'{"results": [], "next": "https://collecteur.attaquant.example/steal"}'
    server = _Server({FEED_URL: page})
    with pytest.raises(FetchError, match="refusée"):
        await fetch_otx(FEED_URL, settings=_settings(), fetch=server)
    assert len(server.calls) == 1


async def test_collecte_otx_de_bout_en_bout(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OTX_API_KEY", KEY)
    get_settings.cache_clear()
    try:
        feed = ThreatFeed(name="OTX", url=FEED_URL, feed_type=FeedType.OTX)
        feed.last_successful_run = datetime(2026, 9, 27, 0, 0, tzinfo=UTC)
        db_session.add(feed)
        await db_session.flush()
        server = _two_pages()

        report = await collect_feed(db_session, feed, fetch=server, clock=lambda: NOW)

        assert report.succeeded, report.error
        assert feed.status == FeedStatus.HEALTHY
        assert report.parsed == 6 and report.inserted == 5  # 203.0.113.10 vu deux fois
        assert "modified_since=2026-09-26T23%3A45%3A00" in server.calls[0][0]
        iocs = (await db_session.execute(select(Indicator))).scalars().all()
        assert "c2-qakbot.example.net" in {i.value for i in iocs}
    finally:
        get_settings.cache_clear()


async def test_erreur_otx_ne_divulgue_pas_la_cle(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OTX_API_KEY", KEY)
    get_settings.cache_clear()
    try:
        feed = ThreatFeed(name="OTX", url=FEED_URL, feed_type=FeedType.OTX)
        db_session.add(feed)
        await db_session.flush()

        async def leaky(url: str, *, headers: Mapping[str, str] | None = None) -> bytes:
            raise FetchError(f"HTTP 403 pour la clé {KEY}")

        report = await collect_feed(db_session, feed, fetch=leaky, clock=lambda: NOW)
        assert feed.status == FeedStatus.DEGRADED
        assert report.error is not None and KEY not in report.error and "***" in report.error
    finally:
        get_settings.cache_clear()
