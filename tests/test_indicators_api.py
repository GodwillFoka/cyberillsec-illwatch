"""Tests d'intégration de `/api/v1/indicators` (RF-07, RF-08)."""

from collections.abc import Awaitable, Callable
from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app.security import create_access_token
from sentry.modules.foundation.users import create_user
from sentry.shared.enums import UserRole

IOCS = "/api/v1/indicators"
FEEDS = "/api/v1/feeds"

Headers = dict[str, str]
HeadersFactory = Callable[[UserRole], Awaitable[Headers]]


@pytest.fixture
def auth_as(db_session: AsyncSession) -> HeadersFactory:
    async def _factory(role: UserRole) -> Headers:
        name = f"{role.value.lower()}-{uuid4().hex[:8]}"
        user = await create_user(
            db_session,
            username=name,
            email=f"{name}@cyberill.test",
            password="mot-de-passe-robuste-2026",
            role=role,
        )
        return {"Authorization": f"Bearer {create_access_token(user.id, user.role)}"}

    return _factory


async def test_analyste_soumet_un_lot(client: AsyncClient, auth_as: HeadersFactory) -> None:
    analyst = await auth_as(UserRole.ANALYST)
    response = await client.post(
        IOCS,
        json={
            "items": [
                {"value": "evil[.]example[.]com", "severity": "HIGH"},
                {"value": "EVIL.example.com"},
                {"value": "d41d8cd98f00b204e9800998ecf8427e", "description": "Dropper"},
                {"value": "n'importe quoi"},
            ]
        },
        headers=analyst,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["received"] == 4
    assert body["inserted"] == 2
    assert body["duplicates_in_batch"] == 1
    assert [r["value"] for r in body["rejected"]] == ["n'importe quoi"]

    again = await client.post(
        IOCS, json={"items": [{"value": "evil.example.com"}]}, headers=analyst
    )
    assert again.json()["updated"] == 1


async def test_lecteur_ne_peut_pas_soumettre(client: AsyncClient, auth_as: HeadersFactory) -> None:
    viewer = await auth_as(UserRole.VIEWER)
    response = await client.post(IOCS, json={"items": [{"value": "1.2.3.4"}]}, headers=viewer)
    assert response.status_code == 403


async def test_acces_anonyme_refuse(client: AsyncClient) -> None:
    assert (await client.get(IOCS)).status_code == 401
    assert (await client.post(IOCS, json={"items": [{"value": "1.2.3.4"}]})).status_code == 401


@pytest.mark.parametrize(
    "body",
    [
        {"items": []},
        {"items": [{"value": "1.2.3.4"}] * 1001},
        {"items": [{"value": "1.2.3.4", "severity": "URGENT"}]},
        {"items": [{"value": "1.2.3.4", "type": "IP"}]},
        {"items": [{"value": "1.2.3.4", "hit_count": 99}]},
    ],
)
async def test_lot_invalide(
    client: AsyncClient, auth_as: HeadersFactory, body: dict[str, object]
) -> None:
    analyst = await auth_as(UserRole.ANALYST)
    assert (await client.post(IOCS, json=body, headers=analyst)).status_code == 422


async def test_rattachement_a_un_flux(client: AsyncClient, auth_as: HeadersFactory) -> None:
    admin = await auth_as(UserRole.ADMIN)
    feed = (
        await client.post(
            FEEDS,
            json={
                "name": "Bulletin",
                "url": "https://cert.example.org/f.json",
                "feed_type": "JSON",
            },
            headers=admin,
        )
    ).json()

    unknown = await client.post(
        IOCS, json={"items": [{"value": "1.2.3.4"}], "feed_id": str(uuid4())}, headers=admin
    )
    assert unknown.status_code == 404

    await client.post(
        IOCS, json={"items": [{"value": "8.8.4.4"}], "feed_id": feed["id"]}, headers=admin
    )
    page = (await client.get(IOCS, params={"feed_id": feed["id"]}, headers=admin)).json()
    assert [i["value"] for i in page["items"]] == ["8.8.4.4"]


async def test_lecture_filtres_et_detail(client: AsyncClient, auth_as: HeadersFactory) -> None:
    analyst = await auth_as(UserRole.ANALYST)
    viewer = await auth_as(UserRole.VIEWER)
    await client.post(
        IOCS,
        json={
            "items": [
                {"value": "198.51.100.1", "severity": "LOW"},
                {"value": "198.51.100.2", "severity": "HIGH"},
                {"value": "bad.example.net", "severity": "CRITICAL"},
            ]
        },
        headers=analyst,
    )

    everything = (await client.get(IOCS, headers=viewer)).json()
    assert everything["total"] == 3
    assert all(i["is_active"] for i in everything["items"])

    ips = (await client.get(IOCS, params={"type": "IPV4"}, headers=viewer)).json()
    assert {i["value"] for i in ips["items"]} == {"198.51.100.1", "198.51.100.2"}

    serious = (await client.get(IOCS, params={"min_severity": "HIGH"}, headers=viewer)).json()
    assert {i["value"] for i in serious["items"]} == {"198.51.100.2", "bad.example.net"}

    found = (await client.get(IOCS, params={"value": "BAD[.]example.NET"}, headers=viewer)).json()
    assert found["total"] == 1
    ioc = found["items"][0]
    assert ioc["type"] == "DOMAIN"
    assert ioc["hit_count"] == 1
    assert ioc["expires_at"] is not None

    detail = await client.get(f"{IOCS}/{ioc['id']}", headers=viewer)
    assert detail.status_code == 200
    assert detail.json()["value"] == "bad.example.net"

    assert (await client.get(f"{IOCS}/{uuid4()}", headers=viewer)).status_code == 404
    garbage = await client.get(IOCS, params={"value": "pas un ioc"}, headers=viewer)
    assert garbage.json()["total"] == 0


async def test_pas_de_modification_ni_suppression(client: AsyncClient) -> None:
    """L'historique d'un IOC est une donnée d'enquête : aucune route d'écriture unitaire."""
    paths = (await client.get("/openapi.json")).json()["paths"]
    assert set(paths[IOCS]) == {"get", "post"}
    assert set(paths[f"{IOCS}/{{indicator_id}}"]) == {"get"}
