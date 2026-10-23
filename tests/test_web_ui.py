"""Service de l'interface web compilée — ADR-016 (même origine que l'API)."""

import json
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest
from click.testing import CliRunner
from httpx import ASGITransport, AsyncClient

from illwatch.app.config import get_settings
from illwatch.app.main import create_app
from illwatch.app.web import UI_CSP
from illwatch.cli.main import cli

INDEX = "<!doctype html><title>ILLWATCH</title><div id=root></div>"


@pytest.fixture
def dist(tmp_path: Path) -> Path:
    (tmp_path / "assets").mkdir()
    (tmp_path / "index.html").write_text(INDEX, encoding="utf-8")
    (tmp_path / "assets" / "index-3f2a1c.js").write_text("console.log(1)", encoding="utf-8")
    (tmp_path / "favicon.svg").write_text("<svg/>", encoding="utf-8")
    return tmp_path


@pytest.fixture
def web_settings(monkeypatch: pytest.MonkeyPatch, dist: Path) -> Iterator[Path]:
    monkeypatch.setenv("WEB_DIR", str(dist))
    get_settings.cache_clear()
    yield dist
    get_settings.cache_clear()


@pytest.fixture
async def web(web_settings: Path) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


async def test_page_servie_avec_politique_stricte(web: AsyncClient) -> None:
    response = await web.get("/")
    assert response.status_code == 200
    assert response.text == INDEX
    assert response.headers["content-security-policy"] == UI_CSP
    assert response.headers["cache-control"] == "no-cache"
    assert response.headers["x-frame-options"] == "DENY"


async def test_routage_cote_navigateur(web: AsyncClient) -> None:
    for path in ("/incidents/42", "/vue-d-ensemble", "/chasse/sessions"):
        response = await web.get(path)
        assert response.status_code == 200 and response.text == INDEX


async def test_assets_immuables_et_fichiers_publics(web: AsyncClient) -> None:
    asset = await web.get("/assets/index-3f2a1c.js")
    assert asset.status_code == 200
    assert asset.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert (await web.get("/assets/absent.js")).status_code == 404
    assert (await web.get("/favicon.svg")).text == "<svg/>"


async def test_l_api_garde_ses_reponses(web: AsyncClient) -> None:
    unknown = await web.get("/api/v1/inexistant")
    assert unknown.status_code == 404
    assert unknown.headers["content-type"].startswith("application/json")
    assert (await web.get("/api/v1/dashboard/summary")).status_code == 401
    health = await web.get("/health")
    assert health.status_code == 200 and health.json()["status"]


async def test_pas_de_traversee_de_repertoire(web: AsyncClient, dist: Path) -> None:
    (dist.parent / "secret.txt").write_text("confidentiel", encoding="utf-8")
    response = await web.get("/..%2Fsecret.txt")
    assert "confidentiel" not in response.text


async def test_sans_interface_compilee_rien_n_est_servi(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("WEB_DIR", str(tmp_path / "absent"))
    get_settings.cache_clear()
    try:
        transport = ASGITransport(app=create_app())
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            assert (await client.get("/")).status_code == 404
            assert (await client.get("/incidents/42")).status_code == 404
    finally:
        get_settings.cache_clear()


def test_export_du_schema_openapi(tmp_path: Path) -> None:
    target = tmp_path / "openapi.json"
    result = CliRunner().invoke(cli, ["openapi", "-o", str(target)])
    assert result.exit_code == 0, result.output
    schema = json.loads(target.read_text(encoding="utf-8"))
    paths = schema["paths"]
    assert "/api/v1/stream" in paths and "/api/v1/feeds/health" in paths
    summary = schema["components"]["schemas"]["SummaryRead"]
    assert set(summary["required"]) >= {"iocs", "cves", "incidents", "alerts", "feeds"}
    assert not any(p == "/" or p.startswith("/{") for p in paths)  # interface hors schéma
