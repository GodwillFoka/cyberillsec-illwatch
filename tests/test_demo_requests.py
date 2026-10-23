"""Demandes de démonstration du site de présentation (ADR-027, lot S4)."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import AuditEvent, DemoRequest
from illwatch.app.security import create_access_token
from illwatch.modules.foundation.users import create_user
from illwatch.modules.sales import demo_requests as service
from illwatch.shared.enums import DemoInterest, UserRole

URL = "/api/v1/demo-requests"


def _form(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": "Ada Lovelace",
        "email": f"Ada.{uuid4().hex[:6]}@Example.org",
        "organisation": "CERT Exemple",
        "job_title": "Head of SOC",
        "country": "de",
        "interest": "PILOT",
        "message": "Pilot for our SOC, 6 analysts.",
        "language": "de",
        "consent": True,
    }
    body.update(overrides)
    return body


async def _count(session: AsyncSession) -> int:
    return int(await session.scalar(select(func.count()).select_from(DemoRequest)) or 0)


async def _headers(session: AsyncSession, role: UserRole) -> dict[str, str]:
    name = f"{role.value.lower()}-{uuid4().hex[:6]}"
    user = await create_user(
        session,
        username=name,
        email=f"{name}@cyberill.test",
        password="mot-de-passe-robuste-2026",
        role=role,
    )
    return {"Authorization": f"Bearer {create_access_token(user.id, user.role)}"}


async def test_demande_enregistree_sans_adresse_ip(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    before = await _count(db_session)
    response = await client.post(URL, json=_form())
    assert response.status_code == 202 and response.json() == {"status": "received"}
    assert await _count(db_session) == before + 1
    row = await db_session.scalar(select(DemoRequest).order_by(DemoRequest.created_at.desc()))
    assert row is not None
    assert row.email.startswith("ada.") and row.email.endswith("@example.org")
    assert (row.country, row.interest, row.language, row.status) == ("DE", "PILOT", "de", "NEW")
    assert row.consent_at is not None
    assert not hasattr(row, "ip")  # minimisation : aucune adresse en base


async def test_consentement_obligatoire(client: AsyncClient) -> None:
    assert (await client.post(URL, json=_form(consent=False))).status_code == 422


async def test_entrees_hostiles_refusees(client: AsyncClient) -> None:
    for bad in (
        {"email": "pas-une-adresse"},
        {"name": "<script>alert(1)</script>"},
        {"organisation": "x" * 161},
        {"message": "m" * 2001},
        {"country": "DEU"},
        {"language": "ja"},
        {"interest": "HACK"},
        {"admin": True},  # champ inconnu
    ):
        assert (await client.post(URL, json=_form(**bad))).status_code == 422, bad


async def test_champ_piege_ne_stocke_rien(client: AsyncClient, db_session: AsyncSession) -> None:
    before = await _count(db_session)
    response = await client.post(URL, json=_form(website="http://spam.example"))
    assert response.status_code == 202
    assert await _count(db_session) == before


async def test_debit_limite_par_adresse(client: AsyncClient) -> None:
    codes = [(await client.post(URL, json=_form())).status_code for _ in range(7)]
    assert codes[: service.PER_IP_LIMIT] == [202] * service.PER_IP_LIMIT
    assert codes[service.PER_IP_LIMIT :] == [429, 429]


async def test_suivi_reserve_aux_administrateurs(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await client.post(URL, json=_form(name="Grace Hopper"))
    analyst = await _headers(db_session, UserRole.ANALYST)
    assert (await client.get(URL, headers=analyst)).status_code == 403

    admin = await _headers(db_session, UserRole.ADMIN)
    page = (await client.get(URL, headers=admin, params={"status": "NEW"})).json()
    target = next(item for item in page["items"] if item["name"] == "Grace Hopper")
    done = await client.patch(f"{URL}/{target['id']}", headers=admin, json={"status": "CONTACTED"})
    assert done.status_code == 200 and done.json()["status"] == "CONTACTED"
    assert done.json()["handled_at"] is not None
    missing = await client.patch(f"{URL}/{uuid4()}", headers=admin, json={"status": "CLOSED"})
    assert missing.status_code == 404

    actions = (
        await db_session.scalars(
            select(AuditEvent.action).where(AuditEvent.action.like("demo_request.%"))
        )
    ).all()
    assert {"demo_request.list", "demo_request.update"} <= set(actions)


async def test_purge_apres_la_duree_de_conservation(db_session: AsyncSession) -> None:
    now = datetime(2027, 6, 1, tzinfo=UTC)
    old = await service.create_request(
        db_session,
        name="Old",
        email="old@example.org",
        organisation="Org",
        interest=DemoInterest.DEMO,
        language="en",
        now=now - timedelta(days=400),
    )
    recent = await service.create_request(
        db_session,
        name="Recent",
        email="recent@example.org",
        organisation="Org",
        interest=DemoInterest.SUPPORT,
        language="fr",
        now=now - timedelta(days=10),
    )
    assert await service.purge(db_session, now=now) >= 1
    assert await db_session.get(DemoRequest, recent.id) is not None
    db_session.expunge(old)
    assert await db_session.get(DemoRequest, old.id) is None
