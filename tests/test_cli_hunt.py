"""CLI `illwatch hunt` (phase 6) sur PostgreSQL réel, liste Tor simulée."""

from pathlib import Path

import pytest
from click.testing import CliRunner

from illwatch.cli import hunt as hunt_cli
from illwatch.cli.main import cli

pytestmark = pytest.mark.postgres


async def _tor(url: str) -> bytes:
    return b"185.220.101.1\n"


def test_parcours_hunt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hunt_cli, "fetch_feed_content", _tor)
    runner = CliRunner()
    rules = runner.invoke(cli, ["hunt", "rules"])
    assert rules.exit_code == 0 and "RULE-05" in rules.output

    observables = tmp_path / "proxy.txt"
    observables.write_text(
        "# export proxy\n185.220.101.1\nupdate.duckdns.org\n\n", encoding="utf-8"
    )
    ran = runner.invoke(cli, ["hunt", "run", "--observables", str(observables)])
    assert ran.exit_code == 0, ran.output  # aucune correspondance CRITICAL
    assert "RULE-01" in ran.output and "RULE-02" in ran.output

    refused = runner.invoke(cli, ["hunt", "run", "--rule", "RULE-99"])
    assert refused.exit_code == 1 and "RULE-99" in refused.output
    assert runner.invoke(cli, ["hunt", "show", "pas-un-uuid"]).exit_code == 2
