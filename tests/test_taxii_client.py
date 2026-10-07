"""Backend TAXII 2.1 `taxii2-client` (T3 à T8, T10, T11) — sans réseau.

Un adaptateur `requests` factice joue le serveur TAXII : on vérifie ce que la bibliothèque
envoie réellement (en-têtes, paramètres, délai) et comment ILLWATCH traduit ses réponses.
"""

import io
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import requests
from pydantic import SecretStr
from requests.adapters import BaseAdapter
from requests.structures import CaseInsensitiveDict
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.config import Settings, get_settings
from illwatch.app.models import ThreatFeed
from illwatch.modules.threat_feeds import collector, taxii
from illwatch.modules.threat_feeds.fetcher import (
    USER_AGENT,
    FetchError,
    RateLimitedError,
    UnsafeDestinationError,
    fetch_feed_content,
)
from illwatch.modules.threat_feeds.parsers import FeedParseError
from illwatch.modules.threat_feeds.taxii import TAXII_MEDIA_TYPE, collection_endpoint, fetch_taxii
from illwatch.shared.enums import FeedStatus, FeedType

FIXTURES = Path(__file__).parent / "fixtures" / "feeds"
OBJECTS = (
    "https://osint.digitalside.it/taxii2reports/collections/"
    "c1f43330-103b-11ee-9ee3-4b022e286589/objects/"
)
PUBLIC = "https://taxii.example.org/api/collections/abc/objects/"
NOW = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)

Reply = tuple[int, dict[str, str], bytes]


def _taxii(body: bytes, status: int = 200, **headers: str) -> Reply:
    return status, {"Content-Type": f"{TAXII_MEDIA_TYPE}", **headers}, body


class FakeServer(BaseAdapter):
    """Adaptateur `requests` : enregistre les requêtes et sert des réponses scénarisées."""

    def __init__(self, handler: Callable[[requests.PreparedRequest], Reply]) -> None:
        super().__init__()
        self.handler = handler
        self.requests: list[requests.PreparedRequest] = []
        self.timeouts: list[Any] = []
        self.closed = False

    def send(  # type: ignore[override]
        self, request: requests.PreparedRequest, stream: bool = False, timeout: Any = None, **_: Any
    ) -> requests.Response:
        self.requests.append(request)
        self.timeouts.append(timeout)
        status, headers, body = self.handler(request)
        response = requests.Response()
        response.status_code = status
        response.headers = CaseInsensitiveDict(headers)
        response.raw = io.BytesIO(body)
        response.url = request.url or ""
        response.request = request
        response.reason = "test"
        response.encoding = "utf-8"
        return response

    def close(self) -> None:
        self.closed = True


def _pages(request: requests.PreparedRequest) -> Reply:
    name = "taxii_page2.json" if "next=page-2-token" in (request.url or "") else "taxii_page1.json"
    return _taxii((FIXTURES / name).read_bytes())


async def _public(host: str, port: int) -> list[str]:
    return ["93.184.216.34"]


async def _no_sleep(_: float) -> None:
    return None


def _settings(**kw: Any) -> Settings:
    kw.setdefault("taxii_auth", SecretStr("osint.digitalside.it=guest:guest"))
    kw.setdefault("http_max_retries", 2)
    return Settings(secret_key="k" * 64, **kw)


async def _run(url: str, server: FakeServer, *, since: datetime | None = None, **kw: Any) -> Any:
    return await fetch_taxii(
        url,
        settings=_settings(**kw),
        since=since,
        resolver=_public,
        transport=server,
        sleep=_no_sleep,
    )


# --- T3, T4, T5, T6 : collecte nominale ------------------------------------------------


async def test_pagination_auth_basic_et_incremental() -> None:
    server = FakeServer(_pages)
    parsed, pages, truncated = await _run(OBJECTS, server, since=NOW)

    assert (pages, truncated) == (2, False)
    assert [o.value for o in parsed.observations] == [
        "198.51.100.23",
        "http://evil-dl.example.net/x86.bin",
        "c2.evil-dl.example.net",
    ]
    first, second = server.requests
    assert first.url is not None and second.url is not None
    assert first.url.startswith(OBJECTS)  # …/objects/ recalculé depuis …/collections/<id>/
    assert "added_after=2026-10-03T11%3A45%3A00.000Z" in first.url  # marge de 15 min
    assert "next=page-2-token" in second.url and "added_after" in second.url
    for request in server.requests:
        assert request.headers["Accept"] == TAXII_MEDIA_TYPE
        assert request.headers["User-Agent"] == USER_AGENT
        assert request.headers["Authorization"] == "Basic Z3Vlc3Q6Z3Vlc3Q="  # guest:guest
    assert server.timeouts == [15.0, 15.0]  # requests n'a aucun délai par défaut
    assert server.closed  # Collection.close() toujours appelé


async def test_collection_publique_sans_identifiants() -> None:
    server = FakeServer(_pages)
    await _run(PUBLIC, server)
    assert all("Authorization" not in r.headers for r in server.requests)
    assert all("added_after" not in (r.url or "") for r in server.requests)


async def test_jeton_bearer_et_en_tete_api_key() -> None:
    bearer = FakeServer(_pages)
    await _run(PUBLIC, bearer, taxii_auth=SecretStr("taxii.example.org=bearer:rdi_123"))
    assert bearer.requests[0].headers["Authorization"] == "Bearer rdi_123"

    api_key = FakeServer(_pages)
    await _run(PUBLIC, api_key, taxii_auth=SecretStr("taxii.example.org=header:x-api-key:K"))
    assert api_key.requests[0].headers["x-api-key"] == "K"
    assert "Authorization" not in api_key.requests[0].headers


async def test_taxii_max_pages() -> None:
    server = FakeServer(_pages)
    parsed, pages, truncated = await _run(OBJECTS, server, taxii_max_pages=1)
    assert (pages, truncated, len(server.requests)) == (1, True, 1)
    assert len(parsed.observations) == 2
    assert server.closed


def test_url_de_collection() -> None:
    assert collection_endpoint(OBJECTS) == (
        OBJECTS.removesuffix("objects/"),
        "c1f43330-103b-11ee-9ee3-4b022e286589",
    )
    assert collection_endpoint(PUBLIC + "?added_after=x")[0] == (
        "https://taxii.example.org/api/collections/abc/"
    )
    assert collection_endpoint("https://h.example/api/collections/abc")[1] == "abc"


async def test_url_de_collection_invalide() -> None:
    server = FakeServer(_pages)
    with pytest.raises(FetchError, match="collections/<id>/objects"):
        await _run("https://taxii.example.org/taxii2/", server)
    assert server.requests == []


# --- T11 : sécurité et erreurs -----------------------------------------------------------


async def test_destination_interne_refusee_avant_toute_requete() -> None:
    server = FakeServer(_pages)

    async def internal(host: str, port: int) -> list[str]:
        return ["10.0.0.8"]

    with pytest.raises(UnsafeDestinationError, match="adresse interne"):
        await fetch_taxii(
            OBJECTS, settings=_settings(), resolver=internal, transport=server, sleep=_no_sleep
        )
    assert server.requests == []


async def test_redirection_refusee_et_jamais_suivie() -> None:
    server = FakeServer(
        lambda r: (302, {"Location": "https://collecteur.attaquant.example/x"}, b"")
    )
    with pytest.raises(UnsafeDestinationError, match="Redirection refusée"):
        await _run(OBJECTS, server)
    assert len(server.requests) == 1
    assert server.closed


async def test_401_message_sans_secret() -> None:
    server = FakeServer(lambda r: _taxii(b'{"title": "Unauthorized"}', status=401))
    with pytest.raises(FetchError, match="TAXII_AUTH") as caught:
        await _run(OBJECTS, server, taxii_auth=SecretStr("osint.digitalside.it=u:motdepasse-42"))
    assert "motdepasse-42" not in str(caught.value)
    assert server.closed


async def test_429_report_de_collecte() -> None:
    server = FakeServer(lambda r: _taxii(b"{}", status=429, **{"Retry-After": "120"}))
    with pytest.raises(RateLimitedError) as caught:
        await _run(OBJECTS, server)
    assert caught.value.retry_after_seconds == 120


async def test_5xx_retente_puis_succes() -> None:
    calls = {"n": 0}

    def flaky(request: requests.PreparedRequest) -> Reply:
        calls["n"] += 1
        if calls["n"] <= 2:
            return _taxii(b"{}", status=503)
        return _taxii(b'{"more": false, "objects": []}')

    parsed, pages, _ = await _run(OBJECTS, FakeServer(flaky))
    assert (calls["n"], pages, parsed.observations) == (3, 1, [])


async def test_panne_persistante_et_erreur_reseau() -> None:
    with pytest.raises(FetchError, match="3 tentatives"):
        await _run(OBJECTS, FakeServer(lambda r: _taxii(b"{}", status=502)))

    def unreachable(request: requests.PreparedRequest) -> Reply:
        raise requests.ConnectTimeout("délai de connexion dépassé")

    with pytest.raises(FetchError, match="ConnectTimeout"):
        await _run(OBJECTS, FakeServer(unreachable))


async def test_taille_bornee_avec_et_sans_content_length() -> None:
    big = b'{"objects": [' + b'{"type": "identity"},' * 2000 + b'{"type": "identity"}]}'
    declared = FakeServer(lambda r: _taxii(big, **{"Content-Length": str(len(big))}))
    with pytest.raises(FetchError, match="trop volumineuse"):
        await _run(OBJECTS, declared, feed_max_bytes=4096)

    streamed = FakeServer(lambda r: _taxii(big))  # transfert sans longueur annoncée
    with pytest.raises(FetchError, match="trop volumineuse"):
        await _run(OBJECTS, streamed, feed_max_bytes=4096)


@pytest.mark.parametrize(
    ("reply", "motif"),
    [
        ((200, {"Content-Type": "application/json"}, b"{}"), "non conforme"),
        ((200, {"Content-Type": TAXII_MEDIA_TYPE}, b"<html>"), "JSON invalide"),
        ((200, {"Content-Type": TAXII_MEDIA_TYPE}, b"[1, 2]"), "enveloppe attendue"),
    ],
)
async def test_reponses_non_conformes(reply: Reply, motif: str) -> None:
    with pytest.raises(FeedParseError, match=motif):
        await _run(OBJECTS, FakeServer(lambda r: reply))


# --- T8 : branchement du collecteur --------------------------------------------------------


class _Spy:
    def __init__(self) -> None:
        self.fetch: Any = "non appelé"

    async def __call__(self, url: str, **kwargs: Any) -> Any:
        self.fetch = kwargs["fetch"]
        return taxii.ParseResult(), 1, False


async def _collect(session: AsyncSession, fetch: Any) -> ThreatFeed:
    feed = ThreatFeed(name=f"TAXII-{id(fetch)}", url=OBJECTS, feed_type=FeedType.TAXII)
    session.add(feed)
    await session.flush()
    await collector.collect_feed(session, feed, fetch=fetch, clock=lambda: NOW)
    return feed


async def test_production_utilise_taxii2_client(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    spy = _Spy()
    monkeypatch.setattr(collector, "fetch_taxii", spy)
    await _collect(db_session, fetch_feed_content)
    assert spy.fetch is None  # None = client taxii2-client


async def test_fetcher_injecte_et_repli_builtin(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    spy = _Spy()
    monkeypatch.setattr(collector, "fetch_taxii", spy)

    async def fake(url: str, **_: Any) -> bytes:
        return b""

    await _collect(db_session, fake)
    assert spy.fetch is fake  # tests : transport injecté conservé

    monkeypatch.setenv("TAXII_CLIENT", "builtin")
    get_settings.cache_clear()
    try:
        await _collect(db_session, fetch_feed_content)
    finally:
        get_settings.cache_clear()
    assert spy.fetch is fetch_feed_content


async def test_chaine_complete_jusqu_a_la_base(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """collector → taxii2-client → enveloppe → STIX → IOC → PostgreSQL/SQLite (T9 hors ligne)."""
    server = FakeServer(_pages)
    original = taxii._fetch_with_library

    async def offline(url: str, **kwargs: Any) -> Any:
        kwargs.update(resolver=_public, transport=server)
        return await original(url, **kwargs)

    monkeypatch.setattr(taxii, "_fetch_with_library", offline)
    feed = ThreatFeed(name="DigitalSide", url=OBJECTS, feed_type=FeedType.TAXII)
    db_session.add(feed)
    await db_session.flush()

    report = await collector.collect_feed(
        db_session, feed, fetch=fetch_feed_content, clock=lambda: NOW
    )
    assert report.succeeded, report.error
    assert feed.status == FeedStatus.HEALTHY
    assert report.inserted == 3 and len(server.requests) == 2
    assert server.requests[0].headers["Authorization"].startswith("Basic ")
    body = json.loads((FIXTURES / "taxii_page1.json").read_text())
    assert body["more"] is True


# --- Découverte et sonde (« vérifier avant d'intégrer ») -----------------------------------

DISCOVERY = {
    "title": "MITRE ATT&CK TAXII 2.1",
    "api_roots": ["https://taxii.example.org/api/v21/", "https://ailleurs.example.net/api/"],
}
COLLECTIONS = {
    "collections": [
        {"id": "x-mitre-collection--1f5f", "title": "Enterprise ATT&CK", "can_read": True},
        {"title": "sans identifiant"},
    ]
}


def _discovery(request: requests.PreparedRequest) -> Reply:
    url = request.url or ""
    if url.endswith("/taxii2/"):
        return _taxii(json.dumps(DISCOVERY).encode())
    if url.endswith("/api/v21/collections/"):
        return _taxii(json.dumps(COLLECTIONS).encode())
    return _taxii(b"{}", status=404)


async def test_decouverte_des_collections() -> None:
    server = FakeServer(_discovery)
    found = await taxii.discover(
        "https://taxii.example.org/taxii2", settings=_settings(), resolver=_public, transport=server
    )
    assert found.title == "MITRE ATT&CK TAXII 2.1"
    assert [c.id for c in found.collections] == ["x-mitre-collection--1f5f"]
    assert found.collections[0].objects_url == (
        "https://taxii.example.org/api/v21/collections/x-mitre-collection--1f5f/objects/"
    )
    # API root d'un autre hôte : signalée, jamais contactée avec ces identifiants.
    assert list(found.errors) == ["https://ailleurs.example.net/api/"]
    assert all("ailleurs" not in (r.url or "") for r in server.requests)
    assert server.closed


async def test_decouverte_api_root_relative() -> None:
    """Constat du 06/10 sur le serveur MITRE ATT&CK : API roots annoncées en chemin relatif."""
    relative = {"title": "MITRE ATT&CK TAXII 2.1", "api_roots": ["/api/v21/", "api/v21"]}

    def handler(request: requests.PreparedRequest) -> Reply:
        url = request.url or ""
        if url.endswith("/taxii2/"):
            return _taxii(json.dumps(relative).encode())
        return _discovery(request)

    server = FakeServer(handler)
    found = await taxii.discover(
        "https://taxii.example.org/taxii2/",
        settings=_settings(),
        resolver=_public,
        transport=server,
    )
    assert found.api_roots == [
        "https://taxii.example.org/api/v21/",
        "https://taxii.example.org/taxii2/api/v21",
    ]
    assert found.collections[0].objects_url == (
        "https://taxii.example.org/api/v21/collections/x-mitre-collection--1f5f/objects/"
    )
    assert "https://taxii.example.org/api/v21/" not in found.errors


async def test_sonde_taxii_sans_ecriture() -> None:
    from illwatch.modules.threat_feeds.probe import probe_source

    server = FakeServer(_pages)
    report = await probe_source(
        OBJECTS, FeedType.TAXII, settings=_settings(), taxii_transport=server, resolver=_public
    )
    assert report.usable and report.pages == 1 and report.truncated  # une page au plus
    assert report.by_type == {"IPV4": 1, "URL": 1}
    assert len(server.requests) == 1


async def test_sonde_collection_sans_ioc_et_source_en_panne() -> None:
    from illwatch.modules.threat_feeds.probe import probe_source

    attack = b'{"more": false, "objects": [{"type": "attack-pattern", "name": "Phishing"}]}'
    empty = await probe_source(
        OBJECTS,
        FeedType.TAXII,
        settings=_settings(),
        taxii_transport=FakeServer(lambda r: _taxii(attack)),
        resolver=_public,
    )
    assert empty.reachable and not empty.usable and empty.by_type == {}

    def down(request: requests.PreparedRequest) -> Reply:
        raise requests.ConnectTimeout("délai dépassé")

    failed = await probe_source(
        OBJECTS,
        FeedType.TAXII,
        settings=_settings(http_max_retries=0),
        taxii_transport=FakeServer(down),
        resolver=_public,
    )
    assert not failed.reachable and failed.error and "ConnectTimeout" in failed.error


async def test_sonde_csv_reel_ipsum() -> None:
    from illwatch.modules.threat_feeds.probe import probe_source

    content = (FIXTURES / "ipsum_level5.txt").read_bytes()

    async def fetch(url: str, **_: Any) -> bytes:
        return content

    report = await probe_source(
        "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt",
        FeedType.CSV,
        settings=_settings(),
        fetch=fetch,
    )
    assert report.usable and report.by_type == {"IPV4": 30} and report.rejected == 0
