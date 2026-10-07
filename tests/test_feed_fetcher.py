"""Récupération HTTP des flux : protections SSRF, limites et résilience (T2.3, UC-01)."""

from collections.abc import Callable

import httpx
import pytest

from illwatch.app.config import Settings
from illwatch.modules.threat_feeds.fetcher import (
    USER_AGENT,
    FetchError,
    RateLimitedError,
    UnsafeDestinationError,
    fetch_feed_content,
)

SETTINGS = Settings(secret_key="k" * 64, http_max_retries=2, feed_max_bytes=1024)
PUBLIC = {"feeds.example.org": ["93.184.216.34"], "cdn.example.net": ["2606:4700::1111"]}


async def _resolver(host: str, _port: int) -> list[str]:
    return PUBLIC.get(host, ["10.0.0.8"])  # tout hôte inconnu « résout » en interne


async def _no_sleep(_: float) -> None:
    return None


def _client(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)


async def _fetch(url: str, handler: Callable[[httpx.Request], httpx.Response]) -> bytes:
    async with _client(handler) as client:
        return await fetch_feed_content(
            url, settings=SETTINGS, client=client, resolver=_resolver, sleep=_no_sleep
        )


async def test_recuperation_nominale() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=b"1.2.3.4\n")

    assert await _fetch("https://feeds.example.org/list.csv", handler) == b"1.2.3.4\n"
    assert len(seen) == 1


async def test_user_agent_par_defaut() -> None:
    captured: dict[str, str] = {}

    async def resolver(host: str, port: int) -> list[str]:
        return ["93.184.216.34"]

    def handler(request: httpx.Request) -> httpx.Response:
        captured["ua"] = request.headers["user-agent"]
        return httpx.Response(200, content=b"x")

    transport = httpx.MockTransport(handler)
    original = httpx.AsyncClient.__init__

    def patched(self: httpx.AsyncClient, **kwargs: object) -> None:
        original(self, transport=transport, **kwargs)  # type: ignore[arg-type]

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(httpx.AsyncClient, "__init__", patched)
        await fetch_feed_content(
            "https://feeds.example.org/x", settings=SETTINGS, resolver=resolver, sleep=_no_sleep
        )
    assert captured["ua"] == USER_AGENT


async def test_domaine_public_resolvant_en_interne_refuse() -> None:
    """DNS rebinding : l'URL est « publique » mais l'adresse réelle est interne."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    with pytest.raises(UnsafeDestinationError, match="adresse interne"):
        await _fetch("https://rebind.attacker.example/feed", handler)
    assert calls == []  # aucune requête n'est partie


@pytest.mark.parametrize(
    "location",
    [
        "http://127.0.0.1/admin",
        "https://169.254.169.254/latest/",
        "https://rebind.attacker.example/",
    ],
)
async def test_redirection_vers_l_interne_refusee(location: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": location})

    with pytest.raises(UnsafeDestinationError):
        await _fetch("https://feeds.example.org/start", handler)


async def test_redirection_publique_suivie_et_revalidee() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "feeds.example.org":
            return httpx.Response(301, headers={"Location": "https://cdn.example.net/list"})
        return httpx.Response(200, content=b"ok")

    assert await _fetch("https://feeds.example.org/list", handler) == b"ok"


async def test_boucle_de_redirections() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://feeds.example.org/loop"})

    with pytest.raises(FetchError, match="redirections"):
        await _fetch("https://feeds.example.org/loop", handler)


async def test_reponse_trop_volumineuse() -> None:
    def announced(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 2048)

    with pytest.raises(FetchError, match="volumineuse"):
        await _fetch("https://feeds.example.org/big", announced)

    def streamed(request: httpx.Request) -> httpx.Response:
        async def body():  # type: ignore[no-untyped-def]
            for _ in range(10):
                yield b"x" * 200

        return httpx.Response(200, content=body())

    with pytest.raises(FetchError, match="volumineuse"):
        await _fetch("https://feeds.example.org/stream", streamed)


async def test_erreurs_transitoires_retentees_puis_succes() -> None:
    attempts: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        if len(attempts) == 1:
            raise httpx.ConnectTimeout("délai dépassé", request=request)
        if len(attempts) == 2:
            return httpx.Response(503)
        return httpx.Response(200, content=b"ok")

    assert await _fetch("https://feeds.example.org/flaky", handler) == b"ok"
    assert len(attempts) == 3


async def test_erreurs_transitoires_epuisees() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(502)

    with pytest.raises(FetchError, match="3 tentatives"):
        await _fetch("https://feeds.example.org/down", handler)


async def test_erreur_client_non_retentee() -> None:
    attempts: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        return httpx.Response(404)

    with pytest.raises(FetchError, match="404"):
        await _fetch("https://feeds.example.org/missing", handler)
    assert len(attempts) == 1


@pytest.mark.parametrize(("header", "expected"), [("120", 120), (None, 60)])
async def test_limite_de_debit_reportee(header: str | None, expected: int) -> None:
    attempts: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        return httpx.Response(429, headers={"Retry-After": header} if header else {})

    with pytest.raises(RateLimitedError) as info:
        await _fetch("https://feeds.example.org/limited", handler)
    assert info.value.retry_after_seconds == expected
    assert len(attempts) == 1  # pas de nouvelle tentative dans le même cycle


async def test_url_non_https_refusee_avant_toute_requete() -> None:
    with pytest.raises(UnsafeDestinationError):
        await _fetch("http://feeds.example.org/list", lambda r: httpx.Response(200))


async def test_resolution_dns_reelle_de_localhost() -> None:
    from illwatch.modules.threat_feeds.fetcher import resolve_host

    assert "127.0.0.1" in await resolve_host("localhost", 443) or "::1" in await resolve_host(
        "localhost", 443
    )


async def test_retry_after_au_format_date() -> None:
    from datetime import UTC, datetime, timedelta
    from email.utils import format_datetime

    when = format_datetime(datetime.now(UTC) + timedelta(seconds=90), usegmt=True)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": when})

    with pytest.raises(RateLimitedError) as info:
        await _fetch("https://feeds.example.org/limited", handler)
    assert 60 <= info.value.retry_after_seconds <= 90


async def test_erreur_de_protocole_retentee() -> None:
    attempts: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        if len(attempts) == 1:
            raise httpx.RemoteProtocolError("connexion fermée", request=request)
        return httpx.Response(200, content=b"ok")

    assert await _fetch("https://feeds.example.org/proto", handler) == b"ok"
    assert len(attempts) == 2


async def test_destination_cgnat_refusee() -> None:
    async def resolver(host: str, port: int) -> list[str]:
        return ["100.100.100.200"]

    with pytest.raises(UnsafeDestinationError):
        await fetch_feed_content(
            "https://metadata.example.org/latest", settings=SETTINGS, resolver=resolver
        )
