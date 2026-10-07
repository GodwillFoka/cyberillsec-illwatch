"""CLI `illwatch cves` (phase 3) sur PostgreSQL réel, sources simulées (aucun accès réseau)."""

import asyncio
from collections.abc import Mapping
from pathlib import Path

import pytest
from click.testing import CliRunner
from sqlalchemy import delete

from illwatch.app.config import get_settings
from illwatch.app.database import dispose_engine, get_engine
from illwatch.app.models import CVE, CollectorState
from illwatch.cli import cves as cves_cli
from illwatch.cli.main import cli

pytestmark = pytest.mark.postgres

FIXTURES = Path(__file__).parent / "fixtures" / "cve"


async def _cleanup() -> None:
    async with get_engine().begin() as conn:
        await conn.execute(delete(CVE))  # historique et alertes suivent (ON DELETE CASCADE)
        await conn.execute(delete(CollectorState))
    await dispose_engine()


@pytest.fixture
def runner(monkeypatch: pytest.MonkeyPatch) -> CliRunner:
    settings = get_settings()
    pages = {
        settings.kev_catalog_url: FIXTURES / "kev.json",
        settings.nvd_api_url: FIXTURES / "nvd_page.json",
        settings.epss_api_url: FIXTURES / "epss.json",
    }

    async def fetch(url: str, *, headers: Mapping[str, str] | None = None) -> bytes:
        return next(p.read_bytes() for prefix, p in pages.items() if url.startswith(prefix))

    async def no_sleep(_: float) -> None:
        return None

    monkeypatch.setattr(cves_cli, "fetch_feed_content", fetch)
    monkeypatch.setattr(cves_cli.asyncio, "sleep", no_sleep)
    asyncio.run(_cleanup())
    yield CliRunner()  # type: ignore[misc]
    asyncio.run(_cleanup())


def test_parcours_cves(runner: CliRunner) -> None:
    empty = runner.invoke(cli, ["cves", "list"])
    assert empty.exit_code == 0 and "Aucune CVE" in empty.output

    synced = runner.invoke(cli, ["cves", "sync"])
    assert synced.exit_code == 0, synced.output
    assert "ligne de base" in synced.output

    listing = runner.invoke(cli, ["cves", "list", "--kev"])
    assert listing.exit_code == 0 and "CVE-2021-44228" in listing.output
    assert "CVE-2025-20003" not in listing.output

    shown = runner.invoke(cli, ["cves", "show", "cve-2021-44228"])
    assert shown.exit_code == 0, shown.output
    assert "P0_CRITIQUE" in shown.output and "24 h" in shown.output

    missing = runner.invoke(cli, ["cves", "show", "CVE-1999-0001"])
    assert missing.exit_code == 1

    alerts = runner.invoke(cli, ["cves", "alerts"])
    assert alerts.exit_code == 0 and "Aucune alerte" in alerts.output

    status = runner.invoke(cli, ["status"])
    assert status.exit_code == 0 and "Jalon M3" in status.output
