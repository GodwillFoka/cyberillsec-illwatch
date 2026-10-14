"""M11 (ADR-026) : métriques Prometheus, accès restreint, tableaux Grafana cohérents."""

import json
import re
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from illwatch.app.api.health import get_redis_probe
from illwatch.app.api.metrics import check_metrics_access
from illwatch.app.config import get_settings
from illwatch.app.security import create_access_token
from illwatch.modules.foundation.users import create_user
from illwatch.modules.observability.metrics import HttpMetrics, escape
from illwatch.modules.threat_feeds.indicators import Observation, ingest_indicators
from illwatch.shared.enums import UserRole

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*(\{.*\})? [-+0-9.eInf]+$")


def test_format_texte() -> None:
    metrics = HttpMetrics()
    metrics.observe("GET", "/api/v1/incidents/{incident_id}", 200, 0.03)
    metrics.observe("GET", "/api/v1/incidents/{incident_id}", 200, 3.0)
    metrics.observe("GET", "/api/v1/stream", 200, 120.0)  # flux SSE : hors histogramme
    text = "\n".join(metrics.render())
    assert (
        'illwatch_http_requests_total{method="GET",route="/api/v1/incidents/{incident_id}",'
        'status="200"} 2'
    ) in text
    assert 'route="/api/v1/incidents/{incident_id}",le="0.05"} 1' in text
    assert 'route="/api/v1/incidents/{incident_id}",le="+Inf"} 2' in text
    assert 'duration_seconds_count{method="GET",route="/api/v1/stream"}' not in text
    assert escape('a"b\\c\nd') == 'a\\"b\\\\c\\nd'
    for line in text.splitlines():
        assert line.startswith("#") or SAMPLE.match(line), line


async def test_point_metrics(client: AsyncClient, db_session: AsyncSession) -> None:
    async def _probe(_: str) -> bool:
        return True

    client._transport.app.dependency_overrides[get_redis_probe] = lambda: _probe  # type: ignore[attr-defined]
    await ingest_indicators(
        db_session, [Observation("198.51.100.77"), Observation("a.example.net")]
    )
    name = f"obs-{uuid4().hex[:8]}"
    user = await create_user(
        db_session,
        username=name,
        email=f"{name}@cyberill.test",
        password="mot-de-passe-robuste-2026",
        role=UserRole.VIEWER,
    )
    headers = {"Authorization": f"Bearer {create_access_token(user.id, user.role)}"}
    await client.get(f"/api/v1/incidents/{uuid4()}", headers=headers)
    await client.get("/api/v1/indicators")  # 401

    response = await client.get("/metrics")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain; version=0.0.4")
    body = response.text
    assert "illwatch_build_info{" in body
    assert "illwatch_database_up 1" in body and "illwatch_redis_up 1" in body
    assert 'illwatch_indicators_active{type="IPV4"} 1' in body
    assert 'illwatch_indicators_active{type="DOMAIN"} 1' in body
    # Modèle de route, jamais l'identifiant réel : cardinalité bornée.
    assert 'route="/api/v1/incidents/{incident_id}",status="404"' in body
    assert 'route="/api/v1/indicators",status="401"' in body
    assert "illwatch_collection_runs_24h" in body and "illwatch_incidents_open" in body
    for line in body.splitlines():
        assert line.startswith("#") or SAMPLE.match(line), line


async def test_acces_restreint(client: AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    def _request(host: str, auth: str | None = None) -> Request:
        headers = [(b"authorization", auth.encode())] if auth else []
        return Request({"type": "http", "client": (host, 4242), "headers": headers})

    settings = get_settings()
    check_metrics_access(_request("172.30.0.5"), settings)  # Prometheus dans le réseau Docker
    check_metrics_access(_request("127.0.0.1"), settings)
    with pytest.raises(HTTPException) as refused:
        check_metrics_access(_request("8.8.8.8"), settings)
    assert refused.value.status_code == 403

    monkeypatch.setenv("METRICS_TOKEN", "jeton-de-metriques-assez-long")
    get_settings.cache_clear()
    try:
        assert (await client.get("/metrics")).status_code == 401
        ok = await client.get(
            "/metrics", headers={"Authorization": "Bearer jeton-de-metriques-assez-long"}
        )
        assert ok.status_code == 200
    finally:
        monkeypatch.delenv("METRICS_TOKEN")
        get_settings.cache_clear()


def test_tableaux_et_alertes_coherents() -> None:
    """Chaque métrique citée par Grafana ou par une alerte est bien exposée par ILL Watch."""
    source = (ROOT / "illwatch/modules/observability/metrics.py").read_text(encoding="utf-8")
    exposed = set(re.findall(r'"(illwatch_[a-z0-9_]+)"', source))
    exposed |= {"illwatch_http_requests_total", "illwatch_build_info"}
    exposed |= {
        f"illwatch_http_request_duration_seconds{suffix}"
        for suffix in ("_bucket", "_sum", "_count")
    }
    exposed.add("illwatch_process_start_time_seconds")
    queries: list[str] = []
    for board in (ROOT / "deploy/observability/grafana/dashboards").glob("*.json"):
        data = json.loads(board.read_text(encoding="utf-8"))
        queries += [t["expr"] for p in data["panels"] for t in p["targets"]]
    queries.append((ROOT / "deploy/observability/alerts.yml").read_text(encoding="utf-8"))
    used = {m for q in queries for m in re.findall(r"illwatch_[a-z0-9_]+", q)}
    used -= {"illwatch_api"}  # nom du job Prometheus, pas une métrique
    assert used and used <= exposed, used - exposed
