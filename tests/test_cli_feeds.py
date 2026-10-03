"""CLI `sentry feeds` (T2.7) sur PostgreSQL réel, collecte simulée (aucun accès réseau)."""

import asyncio
from pathlib import Path

import pytest
from click.testing import CliRunner
from sqlalchemy import delete

from sentry.app.database import dispose_engine, get_engine
from sentry.app.models import Indicator, ThreatFeed
from sentry.cli import feeds as feeds_cli
from sentry.cli.main import cli

pytestmark = pytest.mark.postgres

FIXTURES = Path(__file__).parent / "fixtures" / "feeds"


async def _cleanup() -> None:
    async with get_engine().begin() as conn:
        await conn.execute(delete(Indicator))
        await conn.execute(delete(ThreatFeed))
    await dispose_engine()


@pytest.fixture
def runner() -> CliRunner:
    asyncio.run(_cleanup())
    yield CliRunner()  # type: ignore[misc]
    asyncio.run(_cleanup())


def test_parcours_feeds(runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    served = {
        "https://feodotracker.example.org/ipblocklist.csv": (
            FIXTURES / "feodo_ipblocklist.csv"
        ).read_bytes()
    }

    async def fake_fetch(url: str) -> bytes:
        if url not in served:
            raise feeds_cli.collector.FetchError("HTTP 503 renvoyé par la source.")
        return served[url]

    monkeypatch.setattr(feeds_cli, "fetch_feed_content", fake_fetch)

    empty = runner.invoke(cli, ["feeds", "list"])
    assert empty.exit_code == 0 and "Aucune source" in empty.output

    added = runner.invoke(
        cli,
        [
            "feeds",
            "add",
            "--name",
            "Feodo",
            "--type",
            "csv",
            "--url",
            "https://feodotracker.example.org/ipblocklist.csv",
        ],
    )
    assert added.exit_code == 0, added.output

    refused = runner.invoke(
        cli, ["feeds", "add", "--name", "Interne", "--type", "csv", "--url", "https://10.0.0.1/x"]
    )
    assert refused.exit_code == 1 and "interne" in refused.output

    fetched = runner.invoke(cli, ["feeds", "fetch", "feodo"])
    assert fetched.exit_code == 0, fetched.output
    assert "HEALTHY" in fetched.output

    nothing_due = runner.invoke(cli, ["feeds", "fetch-all"])
    assert nothing_due.exit_code == 0 and "rien à collecter" in nothing_due.output

    runner.invoke(
        cli,
        [
            "feeds",
            "add",
            "--name",
            "Cassé",
            "--type",
            "json",
            "--url",
            "https://down.example.org/f",
        ],
    )
    all_feeds = runner.invoke(cli, ["feeds", "fetch-all", "--force"])
    assert all_feeds.exit_code == 1  # une source en échec → code de sortie non nul
    assert "HTTP 503" in all_feeds.output

    listing = runner.invoke(cli, ["feeds", "list"])
    assert "DEGRADED" in listing.output and "HEALTHY" in listing.output

    missing = runner.invoke(cli, ["feeds", "fetch", "inconnue"])
    assert missing.exit_code == 1


def test_worker_un_cycle(runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch(url: str, **_: object) -> bytes:
        return (FIXTURES / "feodo_ipblocklist.csv").read_bytes()

    monkeypatch.setattr(feeds_cli, "fetch_feed_content", fake_fetch)
    added = runner.invoke(
        cli,
        ["feeds", "add", "--name", "Feodo", "--type", "csv", "--url", "https://f.example.org/x"],
    )
    assert added.exit_code == 0, added.output

    result = runner.invoke(
        cli, ["feeds", "worker", "--tick", "5", "--max-cycles", "1", "--no-cves", "--no-hunt"]
    )
    assert result.exit_code == 0, result.output
    assert "arrêté après 1 cycle" in result.output
    listing = runner.invoke(cli, ["feeds", "list"])
    assert "HEALTHY" in listing.output
