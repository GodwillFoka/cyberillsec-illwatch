"""Import NVD 2.0 hors ligne (`illwatch cves import`) — lecture en flux, données NVD réelles.

Le fixture `nvd_feed_2021_extrait.json` est un extrait non modifié du flux annuel 2021 au
format API 2.0 (miroir fkie-cad) : Log4Shell, ProxyLogon, PrintNightmare et une CVE rejetée.
"""

import io
import json
import lzma
from datetime import UTC, datetime
from pathlib import Path

import pytest
from click.testing import CliRunner
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.config import Settings
from illwatch.app.models import CVE
from illwatch.modules.cve_tracker import sources
from illwatch.modules.cve_tracker.engine import import_nvd_file
from illwatch.modules.cve_tracker.sources import iter_nvd_items
from illwatch.modules.threat_feeds.parsers import FeedParseError
from illwatch.shared.enums import RiskPriority

FEED = Path(__file__).parent / "fixtures" / "cve" / "nvd_feed_2021_extrait.json"
PAGE = Path(__file__).parent / "fixtures" / "cve" / "nvd_page.json"


@pytest.fixture
def tiny_chunks(monkeypatch: pytest.MonkeyPatch) -> None:
    """Blocs de 7 caractères : chaque objet est coupé en de multiples endroits."""
    monkeypatch.setattr(sources, "_READ_CHUNK", 7)


@pytest.mark.usefixtures("tiny_chunks")
def test_flux_annuel_lu_en_flux() -> None:
    with FEED.open(encoding="utf-8") as stream:
        ids = [item["id"] for item in iter_nvd_items(stream)]
    assert ids == ["CVE-2021-26855", "CVE-2021-34527", "CVE-2021-44228", "CVE-2021-0010"]


@pytest.mark.usefixtures("tiny_chunks")
def test_page_api_lue_en_flux() -> None:
    expected = [v["cve"]["id"] for v in json.loads(PAGE.read_text())["vulnerabilities"]]
    with PAGE.open(encoding="utf-8") as stream:
        assert [item["id"] for item in iter_nvd_items(stream)] == expected


@pytest.mark.parametrize(
    "content",
    ['{"autre": []}', '{"cve_items": [{"id": "CVE-2021-1"}, {"id": "CVE-2', ""],
)
def test_fichier_invalide(content: str) -> None:
    with pytest.raises(FeedParseError):
        list(iter_nvd_items(io.StringIO(content)))


async def test_import_complete_le_catalogue_kev(db_session: AsyncSession) -> None:
    db_session.add(
        CVE(
            id="CVE-2021-44228",
            description="Apache Log4j2 (catalogue KEV)",
            published_date=datetime(2021, 12, 10, tzinfo=UTC),
            last_modified_date=datetime(2021, 12, 10, tzinfo=UTC),
            is_kev=True,
            has_ransomware_campaign=True,
        )
    )
    await db_session.flush()
    settings = Settings(_env_file=None)  # type: ignore[call-arg]

    with FEED.open(encoding="utf-8") as stream:
        report = await import_nvd_file(
            db_session, iter_nvd_items(stream), settings=settings, only_known=True
        )
    assert (report.nvd, report.created) == (1, 0)  # seule la CVE déjà suivie est importée
    log4shell = await db_session.get(CVE, "CVE-2021-44228", populate_existing=True)
    assert log4shell is not None
    assert float(log4shell.cvss_score or 0) == 10.0
    assert log4shell.has_public_exploit
    # 30 (CVSS) + 25 (KEV) + 10 (exploit) + 10 (ransomware), sans EPSS : P1, jamais P0.
    assert float(log4shell.composite_risk_score or 0) == 75.0
    assert log4shell.priority == RiskPriority.P1_ELEVE


async def test_import_complet_ignore_les_rejetees(db_session: AsyncSession) -> None:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    with FEED.open(encoding="utf-8") as stream:
        report = await import_nvd_file(db_session, iter_nvd_items(stream), settings=settings)
    assert (report.nvd, report.created) == (3, 3)
    assert await db_session.get(CVE, "CVE-2021-0010") is None


@pytest.mark.postgres
def test_cli_import_xz(tmp_path: Path) -> None:
    from illwatch.cli.main import cli

    archive = tmp_path / "CVE-2021.json.xz"
    archive.write_bytes(lzma.compress(FEED.read_bytes()))
    result = CliRunner().invoke(cli, ["cves", "import", str(archive)])
    assert result.exit_code == 0, result.output
    assert "3 CVE lues" in result.output

    broken = tmp_path / "casse.json"
    broken.write_text('{"cve_items": [{"id": ', encoding="utf-8")
    failed = CliRunner().invoke(cli, ["cves", "import", str(broken)])
    assert failed.exit_code == 1 and "tronqué" in failed.output
