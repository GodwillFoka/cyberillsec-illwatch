"""Gestion des incidents (phase 4) : service, chronologie immuable, API (RF-17 à RF-20)."""

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import CVE, CVEAlert, IncidentEvent, User
from illwatch.app.models.incident import ImmutableTimelineError
from illwatch.app.security import create_access_token
from illwatch.modules.foundation.users import create_user
from illwatch.modules.incidents import service
from illwatch.modules.incidents.state_machine import ClosureRequirementError, InvalidTransitionError
from illwatch.modules.threat_feeds.indicators import Observation, ingest_indicators
from illwatch.shared.enums import (
    IncidentEventType,
    IncidentStatus,
    RiskPriority,
    Severity,
    UserRole,
)

T0 = datetime(2026, 10, 3, 9, 0, tzinfo=UTC)
Headers = dict[str, str]


async def _user(session: AsyncSession, role: UserRole = UserRole.ANALYST) -> User:
    name = f"{role.value.lower()}-{uuid4().hex[:8]}"
    return await create_user(
        session,
        username=name,
        email=f"{name}@cyberill.test",
        password="mot-de-passe-robuste-2026",
        role=role,
    )


async def _cve(session: AsyncSession, cve_id: str = "CVE-2026-1234") -> CVE:
    cve = CVE(
        id=cve_id,
        description="RCE dans ExampleVPN",
        published_date=T0,
        last_modified_date=T0,
        cvss_score=9.8,
        composite_risk_score=91.5,
        priority=RiskPriority.P0_CRITIQUE,
        is_kev=True,
    )
    session.add(cve)
    await session.flush()
    return cve


# --- Service ------------------------------------------------------------------------------


async def test_cycle_de_vie_complet_et_chronologie(db_session: AsyncSession) -> None:
    analyst = await _user(db_session)
    incident = await service.create_incident(
        db_session,
        title="  Exfiltration   suspecte  ",
        description="Trafic sortant anormal",
        severity=Severity.HIGH,
        author_id=analyst.id,
    )
    assert incident.title == "Exfiltration suspecte" and incident.status == IncidentStatus.NOUVEAU

    path = [
        IncidentStatus.ANALYSE,
        IncidentStatus.CONFINEMENT,
        IncidentStatus.ANALYSE,  # retour en analyse permis
        IncidentStatus.CONFINEMENT,
        IncidentStatus.ERADICATION,
        IncidentStatus.RECUPERATION,
    ]
    for target in path:
        await service.transition(db_session, incident.id, target, author_id=analyst.id)
    with pytest.raises(ClosureRequirementError):
        await service.transition(
            db_session, incident.id, IncidentStatus.CLOTURE, author_id=analyst.id
        )
    closed = await service.transition(
        db_session,
        incident.id,
        IncidentStatus.CLOTURE,
        author_id=analyst.id,
        closure_summary="Compte compromis réinitialisé, règle pare-feu ajoutée.",
    )
    assert closed.closed_at is not None

    loaded = await service.get_incident(db_session, incident.id)
    kinds = [e.event_type for e in loaded.events]
    assert kinds[0] == IncidentEventType.CREATED
    assert kinds.count(IncidentEventType.STATUS_CHANGE) == 7
    last = loaded.events[-1]
    assert (last.from_status, last.to_status) == ("RECUPERATION", "CLOTURE")
    assert "Résumé de clôture" in last.message and last.author_id == analyst.id

    with pytest.raises(InvalidTransitionError):  # CLOTURE est terminal
        await service.transition(db_session, incident.id, IncidentStatus.ANALYSE, author_id=None)
    with pytest.raises(service.IncidentClosedError):
        await service.add_note(
            db_session, incident.id, "rollback", author_id=None, kind=IncidentEventType.ACTION_TAKEN
        )
    # Le retour d'expérience reste possible après clôture.
    await service.add_note(db_session, incident.id, "RETEX planifié", author_id=analyst.id)


async def test_saut_d_etape_refuse(db_session: AsyncSession) -> None:
    incident = await service.create_incident(
        db_session, title="x", description="x", severity=Severity.LOW, author_id=None
    )
    with pytest.raises(InvalidTransitionError, match="ANALYSE"):
        await service.transition(
            db_session, incident.id, IncidentStatus.ERADICATION, author_id=None
        )
    assert (await service.get_incident(db_session, incident.id)).status == "NOUVEAU"


async def test_chronologie_immuable_cote_orm(db_session: AsyncSession) -> None:
    incident = await service.create_incident(
        db_session, title="x", description="x", severity=Severity.LOW, author_id=None
    )
    event = await db_session.scalar(
        select(IncidentEvent).where(IncidentEvent.incident_id == incident.id)
    )
    assert event is not None
    event.message = "réécriture de l'histoire"
    with pytest.raises(ImmutableTimelineError):
        await db_session.flush()
    await db_session.rollback()


async def test_liens_ioc_et_cve_idempotents(db_session: AsyncSession) -> None:
    incident = await service.create_incident(
        db_session, title="C2", description="x", severity=Severity.HIGH, author_id=None
    )
    await ingest_indicators(db_session, [Observation("c2.evil.example.com")])
    await _cve(db_session)

    assert await service.attach_indicator(
        db_session, incident.id, author_id=None, value="C2[.]evil.example.com"
    )
    assert not await service.attach_indicator(
        db_session, incident.id, author_id=None, value="c2.evil.example.com"
    )
    assert await service.attach_cve(db_session, incident.id, "cve-2026-1234", author_id=None)
    assert not await service.attach_cve(db_session, incident.id, "CVE-2026-1234", author_id=None)
    with pytest.raises(service.LinkTargetNotFoundError):
        await service.attach_cve(db_session, incident.id, "CVE-1999-0001", author_id=None)
    with pytest.raises(service.LinkTargetNotFoundError):
        await service.attach_indicator(db_session, incident.id, author_id=None, value="absent.io")

    loaded = await service.get_incident(db_session, incident.id)
    assert [link.cve_id for link in loaded.cves] == ["CVE-2026-1234"]
    assert len(loaded.indicators) == 1
    kinds = [e.event_type for e in loaded.events]
    assert kinds.count("IOC_ATTACHED") == 1 and kinds.count("CVE_ATTACHED") == 1


async def test_liste_filtree_par_ioc_et_cve(db_session: AsyncSession) -> None:
    """Écrans IOC et CVE : retrouver les incidents auxquels un élément est associé."""
    linked = await service.create_incident(
        db_session, title="Lié", description="x", severity=Severity.HIGH, author_id=None
    )
    await service.create_incident(
        db_session, title="Autre", description="x", severity=Severity.CRITICAL, author_id=None
    )
    await ingest_indicators(db_session, [Observation("198.51.100.7")])
    await _cve(db_session)
    await service.attach_indicator(db_session, linked.id, author_id=None, value="198.51.100.7")
    await service.attach_cve(db_session, linked.id, "CVE-2026-1234", author_id=None)
    indicator_id = (await service.get_incident(db_session, linked.id)).indicators[0].indicator_id

    by_ioc = await service.list_incidents(db_session, limit=10, offset=0, indicator_id=indicator_id)
    by_cve = await service.list_incidents(db_session, limit=10, offset=0, cve_id="cve-2026-1234")
    assert [i.id for i in by_ioc.items] == [linked.id] and by_ioc.total == 1
    assert [i.id for i in by_cve.items] == [linked.id] and by_cve.total == 1
    none = await service.list_incidents(db_session, limit=10, offset=0, indicator_id=uuid4())
    assert none.total == 0


async def test_assignation(db_session: AsyncSession) -> None:
    analyst, viewer = await _user(db_session), await _user(db_session, UserRole.VIEWER)
    incident = await service.create_incident(
        db_session, title="x", description="x", severity=Severity.LOW, author_id=None
    )
    await service.assign(db_session, incident.id, analyst.id, author_id=None)
    assert incident.assigned_to == analyst.id
    with pytest.raises(service.InvalidAssigneeError):
        await service.assign(db_session, incident.id, viewer.id, author_id=None)
    with pytest.raises(service.LinkTargetNotFoundError):
        await service.assign(db_session, incident.id, uuid4(), author_id=None)
    await service.assign(db_session, incident.id, None, author_id=None)
    assert incident.assigned_to is None


async def test_incident_depuis_une_alerte(db_session: AsyncSession) -> None:
    await _cve(db_session)
    alert = CVEAlert(
        cve_id="CVE-2026-1234",
        score=91.5,
        priority=RiskPriority.P0_CRITIQUE,
        reason="kev",
        delivery_attempts=0,
    )
    db_session.add(alert)
    await db_session.flush()

    incident, created = await service.open_from_alert(db_session, alert.id, author_id=None)
    assert created and incident.severity == Severity.CRITICAL
    assert "24 h" in incident.description and incident.source_alert_id == alert.id
    assert alert.acknowledged_at is not None
    loaded = await service.get_incident(db_session, incident.id)
    assert [link.cve_id for link in loaded.cves] == ["CVE-2026-1234"]

    again, created_again = await service.open_from_alert(db_session, alert.id, author_id=None)
    assert again.id == incident.id and not created_again


async def test_liste_triee_par_gravite(db_session: AsyncSession) -> None:
    for severity in (Severity.LOW, Severity.CRITICAL, Severity.MEDIUM):
        await service.create_incident(
            db_session, title=str(severity), description="x", severity=severity, author_id=None
        )
    page = await service.list_incidents(db_session, limit=10, offset=0)
    assert [i.severity for i in page.items] == ["CRITICAL", "MEDIUM", "LOW"]
    assert (
        await service.list_incidents(db_session, limit=10, offset=0, severity=Severity.LOW)
    ).total == 1


# --- API --------------------------------------------------------------------------------


@pytest.fixture
def auth_as(db_session: AsyncSession) -> Callable[[UserRole], Awaitable[tuple[Headers, UUID]]]:
    async def _factory(role: UserRole) -> tuple[Headers, UUID]:
        user = await _user(db_session, role)
        return {"Authorization": f"Bearer {create_access_token(user.id, user.role)}"}, user.id

    return _factory


async def test_parcours_api(client: AsyncClient, db_session: AsyncSession, auth_as: Any) -> None:
    analyst, analyst_id = await auth_as(UserRole.ANALYST)
    viewer, _ = await auth_as(UserRole.VIEWER)
    payload = {
        "title": "Ransomware sur SRV-01",
        "description": "Chiffrement",
        "severity": "CRITICAL",
    }

    assert (await client.post("/api/v1/incidents", json=payload, headers=viewer)).status_code == 403
    created = await client.post("/api/v1/incidents", json=payload, headers=analyst)
    assert created.status_code == 201, created.text
    body = created.json()
    incident_id = body["id"]
    assert created.headers["Location"].endswith(incident_id)
    assert body["status"] == "NOUVEAU" and body["next_states"] == ["ANALYSE"]
    assert body["timeline"][0]["event_type"] == "CREATED"
    assert body["created_by"] == str(analyst_id)

    skip = await client.post(
        f"/api/v1/incidents/{incident_id}/transitions",
        json={"target": "CLOTURE"},
        headers=analyst,
    )
    assert skip.status_code == 409
    moved = await client.post(
        f"/api/v1/incidents/{incident_id}/transitions",
        json={"target": "ANALYSE", "note": "Prise en charge"},
        headers=analyst,
    )
    assert moved.status_code == 200 and moved.json()["status"] == "ANALYSE"

    note = await client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        json={"message": "Poste isolé du réseau", "kind": "ACTION_TAKEN"},
        headers=analyst,
    )
    assert note.status_code == 201 and note.json()["event_type"] == "ACTION_TAKEN"
    bad_kind = await client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        json={"message": "x", "kind": "STATUS_CHANGE"},
        headers=analyst,
    )
    assert bad_kind.status_code == 422

    assigned = await client.put(
        f"/api/v1/incidents/{incident_id}/assignee",
        json={"user_id": str(analyst_id)},
        headers=analyst,
    )
    assert assigned.status_code == 200 and assigned.json()["assigned_to"] == str(analyst_id)

    detail = (await client.get(f"/api/v1/incidents/{incident_id}", headers=viewer)).json()
    assert [e["event_type"] for e in detail["timeline"]] == [
        "CREATED",
        "STATUS_CHANGE",
        "ACTION_TAKEN",
        "ASSIGNED",
    ]
    listing = (await client.get("/api/v1/incidents?open_only=true", headers=viewer)).json()
    assert listing["total"] == 1
    assert (await client.get(f"/api/v1/incidents/{uuid4()}", headers=viewer)).status_code == 404


async def test_api_liens_et_alerte(
    client: AsyncClient, db_session: AsyncSession, auth_as: Any
) -> None:
    analyst, _ = await auth_as(UserRole.ANALYST)
    await _cve(db_session)
    alert = CVEAlert(
        cve_id="CVE-2026-1234",
        score=91.5,
        priority=RiskPriority.P0_CRITIQUE,
        reason="kev",
        delivery_attempts=0,
    )
    db_session.add(alert)
    await db_session.flush()

    opened = await client.post(f"/api/v1/alerts/{alert.id}/incident", headers=analyst)
    assert opened.status_code == 201 and opened.json()["cve_ids"] == ["CVE-2026-1234"]
    reopened = await client.post(f"/api/v1/alerts/{alert.id}/incident", headers=analyst)
    assert reopened.status_code == 200 and reopened.json()["id"] == opened.json()["id"]
    incident_id = opened.json()["id"]

    await ingest_indicators(db_session, [Observation("203.0.113.66")])
    linked = await client.post(
        f"/api/v1/incidents/{incident_id}/indicators",
        json={"value": "203.0.113.66"},
        headers=analyst,
    )
    assert linked.status_code == 200 and linked.json() == {"created": True}
    both = await client.post(
        f"/api/v1/incidents/{incident_id}/indicators",
        json={"value": "x", "indicator_id": str(uuid4())},
        headers=analyst,
    )
    assert both.status_code == 422
    missing = await client.post(
        f"/api/v1/incidents/{incident_id}/cves",
        json={"cve_id": "CVE-1999-0001"},
        headers=analyst,
    )
    assert missing.status_code == 404
