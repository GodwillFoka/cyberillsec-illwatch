"""Tests d'intégration des endpoints web — critère de validation du jalon M1."""

from httpx import AsyncClient


async def test_health_retourne_200_avec_db_connectee(client: AsyncClient) -> None:
    response = await client.get("/health")
    assert response.status_code == 200

    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["database"] == "connected"
    assert payload["version"]


async def test_openapi_est_expose(client: AsyncClient) -> None:
    response = await client.get("/openapi.json")
    assert response.status_code == 200
    assert response.json()["info"]["title"].startswith("SENTRY")


async def test_route_inconnue_retourne_404(client: AsyncClient) -> None:
    response = await client.get("/api/v1/inexistant")
    assert response.status_code == 404
