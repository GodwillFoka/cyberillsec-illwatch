"""CLI `illwatch dashboard` (phase 5) sur PostgreSQL réel."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from illwatch.cli.main import cli

pytestmark = pytest.mark.postgres


def test_vue_console_et_exports(tmp_path: Path) -> None:
    runner = CliRunner()
    shown = runner.invoke(cli, ["dashboard", "show"])
    assert shown.exit_code == 0, shown.output
    assert "IOC" in shown.output and "Incidents" in shown.output

    csv_file = tmp_path / "cves.csv"
    exported = runner.invoke(cli, ["dashboard", "export", "cves", "-o", str(csv_file)])
    assert exported.exit_code == 0, exported.output
    assert csv_file.read_text(encoding="utf-8").startswith("id,composite_risk_score")

    json_file = tmp_path / "incidents.json"
    runner.invoke(
        cli, ["dashboard", "export", "incidents", "--format", "json", "-o", str(json_file)]
    )
    assert isinstance(json.loads(json_file.read_text(encoding="utf-8")), list)
