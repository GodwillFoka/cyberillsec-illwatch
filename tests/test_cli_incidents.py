"""CLI `illwatch incidents` (phase 4) sur PostgreSQL réel."""

import asyncio
import re

import pytest
from click.testing import CliRunner
from sqlalchemy import delete

from illwatch.app.database import dispose_engine, get_engine
from illwatch.app.models import Incident
from illwatch.cli.main import cli

pytestmark = pytest.mark.postgres


async def _cleanup() -> None:
    async with get_engine().begin() as conn:
        await conn.execute(delete(Incident))
    await dispose_engine()


@pytest.fixture
def runner() -> CliRunner:
    asyncio.run(_cleanup())
    yield CliRunner()  # type: ignore[misc]
    asyncio.run(_cleanup())


def test_parcours_incidents(runner: CliRunner) -> None:
    assert "Aucun incident" in runner.invoke(cli, ["incidents", "list"]).output

    created = runner.invoke(
        cli, ["incidents", "create", "--title", "Phishing ciblé", "--severity", "HIGH"]
    )
    assert created.exit_code == 0, created.output
    match = re.search(r"[0-9a-f-]{36}", created.output)
    assert match is not None
    incident_id = match.group(0)

    jump = runner.invoke(cli, ["incidents", "move", incident_id, "CLOTURE"])
    assert jump.exit_code == 1 and "interdite" in jump.output
    assert runner.invoke(cli, ["incidents", "move", incident_id, "ANALYSE"]).exit_code == 0
    noted = runner.invoke(cli, ["incidents", "note", incident_id, "Boîte mail purgée", "--action"])
    assert noted.exit_code == 0, noted.output

    shown = runner.invoke(cli, ["incidents", "show", incident_id])
    assert shown.exit_code == 0, shown.output
    assert "ANALYSE" in shown.output and "ACTION_TAKEN" in shown.output

    listing = runner.invoke(cli, ["incidents", "list", "--open"])
    assert listing.exit_code == 0 and incident_id[:8] in listing.output
    assert runner.invoke(cli, ["incidents", "show", "pas-un-uuid"]).exit_code == 2
