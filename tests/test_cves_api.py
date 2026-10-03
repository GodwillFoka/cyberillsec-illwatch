"""API du moteur CVE : `/api/v1/cves` et `/api/v1/alerts` (tâche 2.4), statut M3."""

from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app.config import Settings
from sentry.app.models import CVE, CVEAlert
from sentry.app.security import create_access_token
from sentry.modules.cve_tracker.engine import sync_cves
from sentry.modules.foundation.status import compute_status
from sentry.modules.foundation.users import create_user
from sentry.shared.enums import RiskPriority, UserRole

FIXTURES = Path(__file__).parent / "fixtures" / "cve"
T0 = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)
Headers = dict[str, str]


@pytest.fixture
def auth_as(db_session: AsyncSession) -> Callable[[UserRole], Awaitable[Headers]]:
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


async def _synced(session: AsyncSession) -> None:
    settings = Settings(secret_key="k" * 64)
    pages = {
        settings.kev_catalog_url: FIXTURES / "kev.json",
        settings.nvd_api_url: FIXTURES / "nvd_page.json",
        settings.epss_api_url: FIXTURES / "epss.json",
    }

    async def fetch(url: str, *, headers: Mapping[str, str] | None = None) -> bytes:
        return next(p.read_bytes() for prefix, p in pages.items() if url.startswith(prefix))

    async def no_sleep(_: float) -> None:
        return None

    await sync_cves(session, settings=settings, fetch=fetch, sleep=no_sleep, clock=lambda: T0)


async def test_liste_triee_par_risque_et_filtres(
    client: AsyncClient, db_session: AsyncSession, auth_as: Any
) -> None:
    await _synced(db_session)
    viewer = await auth_as(UserRole.VIEWER)

    body = (await client.get("/api/v1/cves", headers=viewer)).json()
    assert body["total"] == 4
    scores = [c["composite_risk_score"] for c in body["items"]]
    assert scores == sorted(scores, reverse=True)
    assert body["items"][0]["id"] == "CVE-2021-44228"
    assert body["items"][0]["sla_hours"] == 24

    p0 = (await client.get("/api/v1/cves?priority=P0_CRITIQUE", headers=viewer)).json()
    assert [c["id"] for c in p0["items"]] == ["CVE-2021-44228"]
    kev = (await client.get("/api/v1/cves?is_kev=true", headers=viewer)).json()
    assert {c["id"] for c in kev["items"]} == {"CVE-2021-44228", "CVE-2020-1472"}
    found = (await client.get("/api/v1/cves?q=netlogon", headers=viewer)).json()
    assert [c["id"] for c in found["items"]] == ["CVE-2020-1472"]
    high = (await client.get("/api/v1/cves?min_score=40", headers=viewer)).json()
    assert high["total"] == 2


async def test_detail_decomposition_et_historique(
    client: AsyncClient, db_session: AsyncSession, auth_as: Any
) -> None:
    await _synced(db_session)
    viewer = await auth_as(UserRole.VIEWER)

    body = (await client.get("/api/v1/cves/cve-2021-44228", headers=viewer)).json()
    assert body["id"] == "CVE-2021-44228"
    parts = body["breakdown"]
    assert (parts["cvss"], parts["kev"], parts["exploit"], parts["ransomware"]) == (
        30.0,
        25.0,
        10.0,
        10.0,
    )
    assert parts["total"] == body["composite_risk_score"]
    assert [h["new_priority"] for h in body["history"]][-1] == "P0_CRITIQUE"
    assert body["kev_required_action"]

    missing = await client.get("/api/v1/cves/CVE-1999-0001", headers=viewer)
    assert missing.status_code == 404
    invalid = await client.get("/api/v1/cves/pas-une-cve", headers=viewer)
    assert invalid.status_code == 422


async def test_alertes_liste_et_acquittement(
    client: AsyncClient, db_session: AsyncSession, auth_as: Any
) -> None:
    db_session.add(
        CVE(
            id="CVE-2026-9",
            description="x",
            published_date=T0,
            last_modified_date=T0,
            composite_risk_score=90,
            priority=RiskPriority.P0_CRITIQUE,
        )
    )
    alert = CVEAlert(
        cve_id="CVE-2026-9",
        score=90,
        priority=RiskPriority.P0_CRITIQUE,
        reason="kev",
        delivery_attempts=0,
    )
    db_session.add(alert)
    await db_session.flush()

    viewer, analyst = await auth_as(UserRole.VIEWER), await auth_as(UserRole.ANALYST)
    listing = (await client.get("/api/v1/alerts?acknowledged=false", headers=viewer)).json()
    assert [a["cve_id"] for a in listing["items"]] == ["CVE-2026-9"]

    assert (await client.post(f"/api/v1/alerts/{alert.id}/ack", headers=viewer)).status_code == 403
    acked = await client.post(f"/api/v1/alerts/{alert.id}/ack", headers=analyst)
    assert acked.status_code == 200 and acked.json()["acknowledged_at"]
    assert (await client.get("/api/v1/alerts?acknowledged=false", headers=viewer)).json()[
        "total"
    ] == 0
    unknown = await client.post(f"/api/v1/alerts/{uuid4()}/ack", headers=analyst)
    assert unknown.status_code == 404


async def test_acces_anonyme_refuse(client: AsyncClient) -> None:
    for path in ("/api/v1/cves", "/api/v1/alerts"):
        assert (await client.get(path)).status_code == 401


async def test_statut_m3(db_session: AsyncSession) -> None:
    before = await compute_status(db_session, now=T0)
    assert not before.m3_reached and [c.met for c in before.m3] == [False] * 4

    await _synced(db_session)
    state = await compute_status(db_session, now=T0)
    assert state.cves_total == 4 and state.cves_kev == 2 and state.cves_with_epss == 4
    assert state.cves_by_priority.get("P0_CRITIQUE") == 1
    nvd, kev, epss, alerting = (c.met for c in state.m3)
    assert nvd and epss and alerting
    assert not kev  # 2 entrées dans la fixture, le vrai catalogue en compte plus de 1 400
