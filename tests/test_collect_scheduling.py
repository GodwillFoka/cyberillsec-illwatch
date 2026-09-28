"""Planificateur et verrous de collecte (T2.6), journal JSON (UC-01 étape 8)."""

import asyncio
import io
import json
import logging
import os
from collections.abc import Mapping
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app.config import Settings
from sentry.app.models import ThreatFeed
from sentry.cli.feeds import run_worker
from sentry.modules.threat_feeds.collector import collect_due_feeds, collect_feed
from sentry.modules.threat_feeds.fetcher import UnsafeDestinationError, fetch_feed_content
from sentry.modules.threat_feeds.locks import LocalFeedLock, RedisFeedLock, open_feed_lock
from sentry.shared.enums import FeedType
from sentry.shared.logging import JsonFormatter, configure_logging, peak_rss_mb

NOW = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)
CSV = b"# ip\n203.0.113.20\n203.0.113.21\n"


async def _serve(url: str, *, headers: Mapping[str, str] | None = None) -> bytes:
    return CSV


# --- Verrous -------------------------------------------------------------------


async def test_verrou_local_exclusif_et_liberation_par_le_seul_detenteur() -> None:
    lock = LocalFeedLock()
    token = await lock.acquire("flux", 60)
    assert token is not None
    assert await lock.acquire("flux", 60) is None  # déjà tenu
    await lock.release("flux", "jeton-d-un-autre")
    assert await lock.acquire("flux", 60) is None  # un tiers ne libère pas
    await lock.release("flux", token)
    assert await lock.acquire("flux", 60) is not None


async def test_verrou_local_expire() -> None:
    lock = LocalFeedLock()
    assert await lock.acquire("flux", 0) is not None
    assert await lock.acquire("flux", 60) is not None  # TTL écoulé : verrou orphelin repris


async def test_redis_injoignable_repli_local(caplog: pytest.LogCaptureFixture) -> None:
    configure_logging("INFO", stream=io.StringIO())
    logging.getLogger("sentry").propagate = True
    try:
        with caplog.at_level(logging.WARNING, logger="sentry.collector"):
            lock = await open_feed_lock("redis://127.0.0.1:1/0")
        assert isinstance(lock, LocalFeedLock)
        assert "lock.redis_unavailable" in caplog.text
        await lock.close()
    finally:
        logging.getLogger("sentry").propagate = False


REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


async def test_verrou_redis_partage_entre_instances() -> None:
    first = await open_feed_lock(REDIS_URL)
    if not isinstance(first, RedisFeedLock):
        await first.close()
        pytest.skip("Redis injoignable")
    second = await open_feed_lock(REDIS_URL)
    name = f"test-{uuid4().hex}"
    try:
        token = await first.acquire(name, 30)
        assert token is not None
        assert await second.acquire(name, 30) is None  # autre « instance »
        await second.release(name, "faux-jeton")
        assert await second.acquire(name, 30) is None
        await first.release(name, token)
        other = await second.acquire(name, 30)
        assert other is not None
        await second.release(name, other)
    finally:
        await first.close()
        await second.close()


async def test_flux_verrouille_ailleurs_saute(db_session: AsyncSession) -> None:
    busy = ThreatFeed(name="Occupé", url="https://a.example.org/f", feed_type=FeedType.CSV)
    free = ThreatFeed(name="Libre", url="https://b.example.org/f", feed_type=FeedType.CSV)
    db_session.add_all([busy, free])
    await db_session.flush()
    lock = LocalFeedLock()
    held = await lock.acquire(str(busy.id), 60)
    assert held is not None

    reports = await collect_due_feeds(db_session, fetch=_serve, clock=lambda: NOW, lock=lock)

    assert [r.feed_name for r in reports] == ["Libre"]
    assert await lock.acquire(str(free.id), 60) is not None  # libéré après collecte


# --- Journal JSON --------------------------------------------------------------


def test_format_json_une_ligne_par_evenement() -> None:
    record = logging.LogRecord(
        "sentry.collector", logging.INFO, __file__, 1, "feed.collected", None, None
    )
    record.fields = {"inserted": 3, "succeeded": True, "error": None}
    line = JsonFormatter().format(record)
    assert "\n" not in line
    payload = json.loads(line)
    assert payload["event"] == "feed.collected"
    assert payload["inserted"] == 3 and payload["succeeded"] is True
    assert payload["ts"].endswith("+00:00")


def test_configuration_idempotente() -> None:
    first, second = io.StringIO(), io.StringIO()
    configure_logging("INFO", stream=first)
    configure_logging("INFO", stream=second)
    logging.getLogger("sentry.test").info("evt")
    assert first.getvalue() == ""
    assert len(second.getvalue().splitlines()) == 1


async def test_chaque_collecte_journalisee(db_session: AsyncSession) -> None:
    stream = io.StringIO()
    configure_logging("INFO", stream=stream)
    feed = ThreatFeed(name="Journal", url="https://j.example.org/f", feed_type=FeedType.CSV)
    db_session.add(feed)
    await db_session.flush()

    await collect_feed(db_session, feed, fetch=_serve, clock=lambda: NOW)

    events = [json.loads(line) for line in stream.getvalue().splitlines()]
    collected = [e for e in events if e["event"] == "feed.collected"]
    assert len(collected) == 1
    entry = collected[0]
    assert entry["feed_name"] == "Journal" and entry["inserted"] == 2
    assert entry["succeeded"] is True and entry["duration_ms"] >= 0
    assert entry["level"] == "INFO"


def test_mesure_memoire() -> None:
    value = peak_rss_mb()
    assert value is None or value > 0


# --- Fetcher : en-têtes d'authentification ------------------------------------

SETTINGS = Settings(secret_key="k" * 64, http_max_retries=0)


async def _resolver(host: str, _port: int) -> list[str]:
    return ["93.184.216.34"]


async def test_en_tetes_transmis_et_jamais_a_un_autre_hote() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/start":
            return httpx.Response(302, headers={"Location": "/page2"})
        if request.url.path == "/page2":
            return httpx.Response(200, content=b"ok")
        return httpx.Response(302, headers={"Location": "https://ailleurs.example.net/x"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        body = await fetch_feed_content(
            "https://api.example.org/start",
            settings=SETTINGS,
            client=client,
            resolver=_resolver,
            headers={"X-Api-Key": "secret"},
        )
        assert body == b"ok"
        assert all(r.headers["X-Api-Key"] == "secret" for r in seen)

        seen.clear()
        with pytest.raises(UnsafeDestinationError, match="autre hôte"):
            await fetch_feed_content(
                "https://api.example.org/bounce",
                settings=SETTINGS,
                client=client,
                resolver=_resolver,
                headers={"X-Api-Key": "secret"},
            )
        assert [r.url.host for r in seen] == ["api.example.org"]


# --- Worker --------------------------------------------------------------------


async def test_worker_survit_et_s_arrete() -> None:
    """Deux cycles : quelle que soit la base (vide ou absente), le worker ne meurt pas."""
    stream = io.StringIO()
    configure_logging("INFO", stream=stream)
    cycles = await run_worker(tick_seconds=0, max_cycles=2, lock=LocalFeedLock())
    assert cycles == 2
    events = [json.loads(line)["event"] for line in stream.getvalue().splitlines()]
    assert len([e for e in events if e.startswith("worker.cycle")]) == 2


async def test_worker_arret_demande() -> None:
    stop = asyncio.Event()
    stop.set()
    assert await run_worker(tick_seconds=60, stop=stop, lock=LocalFeedLock()) == 0
