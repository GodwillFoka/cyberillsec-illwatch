"""Connecteur AlienVault OTX (T2.9) : analyse, pagination, clé API, garde-fous."""

from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.config import Settings, get_settings
from illwatch.app.models import CollectorState, Indicator, ThreatFeed
from illwatch.modules.threat_feeds.collector import OTX_STATE_PREFIX, collect_feed
from illwatch.modules.threat_feeds.fetcher import FetchError
from illwatch.modules.threat_feeds.otx import (
    API_KEY_HEADER,
    fetch_otx,
    parse_otx_page,
    with_modified_since,
    with_page,
)
from illwatch.modules.threat_feeds.parsers import FeedParseError
from illwatch.shared.enums import FeedStatus, FeedType, IndicatorType

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


# --- Reprise : collecte tronquée ou interrompue (06/10) ---------------------------------------


def test_with_page() -> None:
    assert with_page(FEED_URL, 1) == FEED_URL
    assert with_page(FEED_URL, 2) == PAGE2
    assert with_page(PAGE2, 3).endswith("page=3") and "page=2" not in with_page(PAGE2, 3)


async def test_erreur_apres_la_premiere_page_garde_l_acquis() -> None:
    server = _two_pages()
    server.pages[PAGE2] = b"pas du json"
    outcome = await fetch_otx(FEED_URL, settings=_settings(), fetch=server)
    assert outcome.pages == 1 and outcome.interrupted is not None and not outcome.complete
    assert len(outcome.parsed.observations) == 4


async def test_reprise_a_une_page_donnee() -> None:
    server = _two_pages()
    outcome = await fetch_otx(FEED_URL, settings=_settings(), fetch=server, start_page=2)
    assert [c[0] for c in server.calls] == [PAGE2] and outcome.complete


async def _otx_feed(session: AsyncSession) -> ThreatFeed:
    feed = ThreatFeed(name="OTX", url=FEED_URL, feed_type=FeedType.OTX)
    feed.last_successful_run = datetime(2026, 9, 27, 0, 0, tzinfo=UTC)
    session.add(feed)
    await session.flush()
    return feed


async def test_collecte_tronquee_reprend_a_la_page_suivante(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Le curseur n'avance qu'une fois la fenêtre épuisée : aucune page n'est perdue."""
    monkeypatch.setenv("OTX_API_KEY", KEY)
    monkeypatch.setenv("OTX_MAX_PAGES", "1")
    get_settings.cache_clear()
    try:
        feed = await _otx_feed(db_session)
        first = await collect_feed(db_session, feed, fetch=_two_pages(), clock=lambda: NOW)
        assert first.succeeded and first.inserted == 4
        assert first.warning is not None and "page 2" in first.warning
        state = await db_session.get(CollectorState, f"{OTX_STATE_PREFIX}{feed.id}")
        assert state is not None and state.items == 1
        assert state.cursor == datetime(2026, 9, 27, 0, 0, tzinfo=UTC)  # inchangé

        later = datetime(2026, 9, 28, 13, 0, tzinfo=UTC)
        server = _two_pages()
        second = await collect_feed(db_session, feed, fetch=server, clock=lambda: later)
        assert server.calls[0][0].startswith(PAGE2)  # reprise, pas de relecture
        assert "modified_since=2026-09-26T23%3A45%3A00" in server.calls[0][0]
        assert second.succeeded and second.warning is None and second.inserted == 1
        # Fenêtre épuisée : le curseur prend le début de la fenêtre (1re collecte).
        assert state.items == 0 and state.cursor == NOW and state.last_success_at is None
    finally:
        get_settings.cache_clear()


async def test_collecte_interrompue_garde_les_pages_lues(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Un ReadTimeout page 2 n'annule plus la page 1 (fin du « tout ou rien »)."""
    monkeypatch.setenv("OTX_API_KEY", KEY)
    get_settings.cache_clear()
    try:
        feed = await _otx_feed(db_session)
        pages = _two_pages().pages

        async def flaky(url: str, *, headers: Mapping[str, str] | None = None) -> bytes:
            key = url.split("&modified_since")[0]
            if key == PAGE2:
                raise FetchError(f"ReadTimeout (clé {KEY})")
            return pages[key]

        report = await collect_feed(db_session, feed, fetch=flaky, clock=lambda: NOW)
        assert report.succeeded and feed.status == FeedStatus.HEALTHY
        assert report.inserted == 4
        assert report.warning is not None and "interrompue page 2" in report.warning
        assert KEY not in report.warning
        state = await db_session.get(CollectorState, f"{OTX_STATE_PREFIX}{feed.id}")
        assert state is not None and state.items == 1
        assert state.cursor == datetime(2026, 9, 27, 0, 0, tzinfo=UTC)
    finally:
        get_settings.cache_clear()


def test_rythme_nvd_annonce_selon_la_cle(monkeypatch: pytest.MonkeyPatch) -> None:
    from illwatch.cli.cves import _nvd_pace

    monkeypatch.delenv("NVD_API_KEY", raising=False)
    get_settings.cache_clear()
    try:
        assert "sans clé" in _nvd_pace(("kev", "nvd"))
        assert _nvd_pace(("epss",)) == ""
        monkeypatch.setenv("NVD_API_KEY", "cle-nvd-de-test")
        get_settings.cache_clear()
        assert "avec clé" in _nvd_pace(("nvd",))
    finally:
        get_settings.cache_clear()


async def test_reprise_annoncee_seulement_si_l_avancement_est_enregistre(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Une ingestion en échec n'annonce pas « reprise à la page N » (boucle du 07/10)."""
    from illwatch.modules.threat_feeds import collector

    monkeypatch.setenv("OTX_API_KEY", KEY)
    monkeypatch.setenv("OTX_MAX_PAGES", "1")
    get_settings.cache_clear()
    try:
        feed = await _otx_feed(db_session)

        async def broken(*args: object, **kwargs: object) -> None:
            raise RuntimeError("ingestion impossible")

        monkeypatch.setattr(collector, "ingest_indicators", broken)
        report = await collect_feed(db_session, feed, fetch=_two_pages(), clock=lambda: NOW)
        assert not report.succeeded and feed.status == FeedStatus.DEGRADED
        assert report.warning is None
        state = await db_session.get(CollectorState, f"{OTX_STATE_PREFIX}{feed.id}")
        assert state is not None and state.items == 0  # rien d'enregistré, rien d'annoncé
    finally:
        get_settings.cache_clear()


async def test_url_a_port_invalide_n_empeche_pas_le_lot(db_session: AsyncSession) -> None:
    from illwatch.modules.threat_feeds.indicators import Observation, ingest_indicators

    result = await ingest_indicators(
        db_session,
        [
            Observation(value="http://hote.example:99999/x", type=IndicatorType.URL),
            Observation(value="https://valide.example/x", type=IndicatorType.URL),
        ],
        feed_id=None,
        now=NOW,
    )
    assert result.inserted == 1 and result.rejected_count == 1
