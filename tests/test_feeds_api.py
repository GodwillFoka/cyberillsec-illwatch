"""Tests d'intégration du CRUD des sources de flux — `/api/v1/feeds` (RF-04, T2.2)."""

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import Indicator, ThreatFeed
from illwatch.app.security import create_access_token
from illwatch.modules.foundation.users import create_user
from illwatch.shared.enums import FeedStatus, IndicatorType, UserRole

FEEDS = "/api/v1/feeds"
PASSWORD = "mot-de-passe-robuste-2026"

Headers = dict[str, str]
HeadersFactory = Callable[[UserRole], Awaitable[Headers]]


@pytest.fixture
def auth_as(db_session: AsyncSession) -> HeadersFactory:
    """Crée un utilisateur du rôle demandé et renvoie ses en-têtes Bearer."""

    async def _factory(role: UserRole) -> Headers:
        name = f"{role.value.lower()}-{uuid4().hex[:8]}"
        user = await create_user(
            db_session, username=name, email=f"{name}@cyberill.test", password=PASSWORD, role=role
        )
        return {"Authorization": f"Bearer {create_access_token(user.id, user.role)}"}

    return _factory


def _payload(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "name": "abuse.ch URLhaus",
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "feed_type": "CSV",
    }
    body.update(overrides)
    return body


async def _create(client: AsyncClient, headers: Headers, **overrides: object) -> dict[str, object]:
    response = await client.post(FEEDS, json=_payload(**overrides), headers=headers)
    assert response.status_code == 201, response.text
    return dict(response.json())


# --- Création -----------------------------------------------------------------


async def test_admin_cree_un_flux_avec_valeurs_par_defaut(
    client: AsyncClient, auth_as: HeadersFactory
) -> None:
    admin = await auth_as(UserRole.ADMIN)
    response = await client.post(FEEDS, json=_payload(), headers=admin)

    assert response.status_code == 201
    body = response.json()
    assert response.headers["location"] == f"{FEEDS}/{body['id']}"
    assert body["name"] == "abuse.ch URLhaus"
    assert body["feed_type"] == "CSV"
    assert body["status"] == "PENDING"
    assert body["is_active"] is True
    assert body["polling_interval"] == 3600
    assert body["last_successful_run"] is None
    assert body["last_error"] is None
    assert body["created_at"] and body["updated_at"]


async def test_champs_geres_par_le_serveur_refuses(
    client: AsyncClient, auth_as: HeadersFactory
) -> None:
    """Le client ne peut pas se déclarer `HEALTHY` : l'état appartient au collecteur."""
    admin = await auth_as(UserRole.ADMIN)
    response = await client.post(FEEDS, json=_payload(status="HEALTHY"), headers=admin)
    assert response.status_code == 422


async def test_nom_en_double_refuse_sans_tenir_compte_de_la_casse(
    client: AsyncClient, auth_as: HeadersFactory
) -> None:
    admin = await auth_as(UserRole.ADMIN)
    await _create(client, admin)
    response = await client.post(FEEDS, json=_payload(name="ABUSE.CH  urlhaus"), headers=admin)
    assert response.status_code == 409


@pytest.mark.parametrize(
    "overrides",
    [
        {"url": "http://urlhaus.abuse.ch/downloads/csv_recent/"},
        {"url": "https://169.254.169.254/latest/meta-data/"},
        {"url": "https://localhost:8000/health"},
        {"feed_type": "XML"},
        {"polling_interval": 59},
        {"polling_interval": 7 * 24 * 3600 + 1},
        {"name": "   "},
        {"name": "x" * 101},
    ],
)
async def test_donnees_invalides_refusees(
    client: AsyncClient, auth_as: HeadersFactory, overrides: dict[str, object]
) -> None:
    admin = await auth_as(UserRole.ADMIN)
    response = await client.post(FEEDS, json=_payload(**overrides), headers=admin)
    assert response.status_code == 422


# --- Contrôle d'accès ---------------------------------------------------------


async def test_ecriture_interdite_aux_analystes_et_lecteurs(
    client: AsyncClient, auth_as: HeadersFactory
) -> None:
    admin = await auth_as(UserRole.ADMIN)
    feed = await _create(client, admin)
    target = f"{FEEDS}/{feed['id']}"

    for role in (UserRole.ANALYST, UserRole.VIEWER):
        headers = await auth_as(role)
        assert (
            await client.post(FEEDS, json=_payload(name="x"), headers=headers)
        ).status_code == 403
        assert (
            await client.patch(target, json={"is_active": False}, headers=headers)
        ).status_code == 403
        assert (await client.delete(target, headers=headers)).status_code == 403


async def test_lecture_ouverte_a_tous_les_roles(
    client: AsyncClient, auth_as: HeadersFactory
) -> None:
    admin = await auth_as(UserRole.ADMIN)
    feed = await _create(client, admin)

    for role in UserRole:
        headers = await auth_as(role)
        assert (await client.get(FEEDS, headers=headers)).status_code == 200
        assert (await client.get(f"{FEEDS}/{feed['id']}", headers=headers)).status_code == 200


async def test_acces_anonyme_refuse(client: AsyncClient) -> None:
    for response in (
        await client.get(FEEDS),
        await client.get(f"{FEEDS}/{uuid4()}"),
        await client.post(FEEDS, json=_payload()),
        await client.patch(f"{FEEDS}/{uuid4()}", json={"is_active": False}),
        await client.delete(f"{FEEDS}/{uuid4()}"),
    ):
        assert response.status_code == 401


# --- Lecture ------------------------------------------------------------------


async def test_liste_paginee_triee_et_filtree(client: AsyncClient, auth_as: HeadersFactory) -> None:
    admin = await auth_as(UserRole.ADMIN)
    await _create(client, admin, name="Charlie", url="https://c.example.org/f.csv")
    await _create(client, admin, name="alpha", url="https://a.example.org/f.json", feed_type="JSON")
    await _create(client, admin, name="Bravo", url="https://b.example.org/f.csv", is_active=False)

    page = (await client.get(FEEDS, params={"limit": 2}, headers=admin)).json()
    assert page["total"] == 3
    assert page["limit"] == 2
    assert page["offset"] == 0
    assert [f["name"] for f in page["items"]] == ["alpha", "Bravo"]

    page2 = (await client.get(FEEDS, params={"limit": 2, "offset": 2}, headers=admin)).json()
    assert [f["name"] for f in page2["items"]] == ["Charlie"]

    actives = (await client.get(FEEDS, params={"is_active": "true"}, headers=admin)).json()
    assert {f["name"] for f in actives["items"]} == {"alpha", "Charlie"}

    json_only = (await client.get(FEEDS, params={"feed_type": "JSON"}, headers=admin)).json()
    assert [f["name"] for f in json_only["items"]] == ["alpha"]

    pending = (await client.get(FEEDS, params={"status": "PENDING"}, headers=admin)).json()
    assert pending["total"] == 3


@pytest.mark.parametrize("params", [{"limit": 0}, {"limit": 201}, {"offset": -1}])
async def test_pagination_bornee(
    client: AsyncClient, auth_as: HeadersFactory, params: dict[str, int]
) -> None:
    viewer = await auth_as(UserRole.VIEWER)
    assert (await client.get(FEEDS, params=params, headers=viewer)).status_code == 422


async def test_flux_inconnu_404_et_identifiant_invalide_422(
    client: AsyncClient, auth_as: HeadersFactory
) -> None:
    viewer = await auth_as(UserRole.VIEWER)
    assert (await client.get(f"{FEEDS}/{uuid4()}", headers=viewer)).status_code == 404
    assert (await client.get(f"{FEEDS}/pas-un-uuid", headers=viewer)).status_code == 422


# --- Modification -------------------------------------------------------------


async def test_modification_partielle(client: AsyncClient, auth_as: HeadersFactory) -> None:
    admin = await auth_as(UserRole.ADMIN)
    feed = await _create(client, admin)

    response = await client.patch(
        f"{FEEDS}/{feed['id']}", json={"polling_interval": 900, "is_active": False}, headers=admin
    )
    assert response.status_code == 200
    body = response.json()
    assert body["polling_interval"] == 900
    assert body["is_active"] is False
    assert body["name"] == feed["name"]
    assert body["url"] == feed["url"]


async def test_changer_la_source_reinitialise_l_etat(
    client: AsyncClient, auth_as: HeadersFactory, db_session: AsyncSession
) -> None:
    """Nouvelle URL = santé inconnue : retour à PENDING, dernière erreur effacée."""
    admin = await auth_as(UserRole.ADMIN)
    feed = await _create(client, admin)
    stored = await db_session.get(ThreatFeed, UUID(str(feed["id"])))
    assert stored is not None
    stored.status = FeedStatus.DEGRADED
    stored.last_error = "timeout"
    await db_session.flush()

    unchanged = await client.patch(
        f"{FEEDS}/{feed['id']}", json={"polling_interval": 600}, headers=admin
    )
    assert unchanged.json()["status"] == "DEGRADED"

    moved = await client.patch(
        f"{FEEDS}/{feed['id']}", json={"url": "https://mirror.example.org/f.csv"}, headers=admin
    )
    assert moved.json()["status"] == "PENDING"
    assert moved.json()["last_error"] is None


@pytest.mark.parametrize(
    "body",
    [{}, {"name": None}, {"is_active": None}, {"status": "HEALTHY"}, {"url": "http://x.org/f"}],
)
async def test_modification_invalide(
    client: AsyncClient, auth_as: HeadersFactory, body: dict[str, object]
) -> None:
    admin = await auth_as(UserRole.ADMIN)
    feed = await _create(client, admin)
    response = await client.patch(f"{FEEDS}/{feed['id']}", json=body, headers=admin)
    assert response.status_code == 422


async def test_renommage_vers_un_nom_pris_refuse(
    client: AsyncClient, auth_as: HeadersFactory
) -> None:
    admin = await auth_as(UserRole.ADMIN)
    await _create(client, admin, name="Premier", url="https://a.example.org/f.csv")
    second = await _create(client, admin, name="Second", url="https://b.example.org/f.csv")

    response = await client.patch(
        f"{FEEDS}/{second['id']}", json={"name": "premier"}, headers=admin
    )
    assert response.status_code == 409

    same = await client.patch(f"{FEEDS}/{second['id']}", json={"name": "Second"}, headers=admin)
    assert same.status_code == 200


async def test_modification_flux_inconnu(client: AsyncClient, auth_as: HeadersFactory) -> None:
    admin = await auth_as(UserRole.ADMIN)
    response = await client.patch(f"{FEEDS}/{uuid4()}", json={"is_active": False}, headers=admin)
    assert response.status_code == 404


# --- Suppression --------------------------------------------------------------


async def test_suppression_conserve_les_ioc(
    client: AsyncClient, auth_as: HeadersFactory, db_session: AsyncSession
) -> None:
    admin = await auth_as(UserRole.ADMIN)
    feed = await _create(client, admin)
    now = datetime.now(UTC)
    db_session.add(
        Indicator(
            feed_id=UUID(str(feed["id"])),
            type=IndicatorType.URL,
            value="https://malware.example.org/payload",
            first_seen=now,
            last_seen=now,
        )
    )
    await db_session.flush()

    response = await client.delete(f"{FEEDS}/{feed['id']}", headers=admin)
    assert response.status_code == 204
    assert response.content == b""

    assert (await client.get(f"{FEEDS}/{feed['id']}", headers=admin)).status_code == 404
    db_session.expire_all()
    ioc = (await db_session.execute(select(Indicator))).scalar_one()
    assert ioc.feed_id is None

    assert (await client.delete(f"{FEEDS}/{feed['id']}", headers=admin)).status_code == 404


# --- Contrat OpenAPI ----------------------------------------------------------


async def test_routes_documentees_dans_openapi(client: AsyncClient) -> None:
    paths = (await client.get("/openapi.json")).json()["paths"]
    assert set(paths[FEEDS]) == {"get", "post"}
    assert set(paths[f"{FEEDS}/{{feed_id}}"]) == {"get", "patch", "delete"}


async def test_detail_d_erreur_reserve_aux_administrateurs(
    client: AsyncClient, auth_as: HeadersFactory, db_session: AsyncSession
) -> None:
    """Un message d'erreur peut citer une IP interne refusée : ADMIN seulement."""
    admin = await auth_as(UserRole.ADMIN)
    feed = await _create(client, admin)
    stored = await db_session.get(ThreatFeed, UUID(str(feed["id"])))
    assert stored is not None
    stored.last_error = "rebind.example résout vers une adresse interne (10.0.0.8)"
    await db_session.flush()

    as_admin = (await client.get(f"{FEEDS}/{feed['id']}", headers=admin)).json()
    assert "10.0.0.8" in as_admin["last_error"]

    for role in (UserRole.ANALYST, UserRole.VIEWER):
        headers = await auth_as(role)
        detail = (await client.get(f"{FEEDS}/{feed['id']}", headers=headers)).json()
        listing = (await client.get(FEEDS, headers=headers)).json()["items"][0]
        for body in (detail, listing):
            assert body["last_error"] is not None
            assert "10.0.0.8" not in body["last_error"]


async def test_flux_otx_limite_a_l_api_otx(client: AsyncClient, auth_as: HeadersFactory) -> None:
    """La clé OTX part en en-tête vers l'URL du flux : seule l'API OTX est admise."""
    admin = await auth_as(UserRole.ADMIN)
    otx = {"name": "OTX", "feed_type": "OTX"}
    refused = await client.post(
        FEEDS, json={**otx, "url": "https://collecte.example.org/pulses"}, headers=admin
    )
    assert refused.status_code == 422
    assert "otx.alienvault.com" in refused.json()["detail"]

    created = await client.post(
        FEEDS,
        json={**otx, "url": "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50"},
        headers=admin,
    )
    assert created.status_code == 201, created.text
    feed_id = created.json()["id"]

    moved = await client.patch(
        f"{FEEDS}/{feed_id}", json={"url": "https://collecte.example.org/p"}, headers=admin
    )
    assert moved.status_code == 422
    kept = (await client.get(f"{FEEDS}/{feed_id}", headers=admin)).json()
    assert kept["url"].startswith("https://otx.alienvault.com/")

    csv = await client.post(
        FEEDS,
        json={"name": "CSV", "feed_type": "CSV", "url": "https://c.example.org/f"},
        headers=admin,
    )
    converted = await client.patch(
        f"{FEEDS}/{csv.json()['id']}", json={"feed_type": "OTX"}, headers=admin
    )
    assert converted.status_code == 422
