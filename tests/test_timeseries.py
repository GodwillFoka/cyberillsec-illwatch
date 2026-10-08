"""Séries temporelles du tableau de bord — ADR-016 (Vue d'ensemble)."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import CVE, CVEAlert, Incident
from illwatch.app.security import create_access_token
from illwatch.modules.dashboard.timeseries import Metric, Window, time_series
from illwatch.modules.foundation.users import create_user
from illwatch.modules.threat_feeds.indicators import Observation, ingest_indicators
from illwatch.shared.enums import IncidentStatus, RiskPriority, Severity, UserRole

NOW = datetime(2026, 10, 8, 12, 30, tzinfo=UTC)


async def test_iocs_par_heure_avec_tranches_vides_a_zero(db_session: AsyncSession) -> None:
    await ingest_indicators(
        db_session,
        [Observation("a.example.com"), Observation("b.example.com")],
        now=NOW - timedelta(hours=2, minutes=10),
    )
    await ingest_indicators(
        db_session, [Observation("c.example.com")], now=NOW - timedelta(minutes=5)
    )
    await ingest_indicators(db_session, [Observation("d.example.com")], now=NOW - timedelta(days=2))

    series = await time_series(db_session, Metric.IOCS, Window.H24, now=NOW)

    assert series.bucket == "hour"
    assert len(series.points) == 24
    assert series.end == datetime(2026, 10, 8, 13, 0, tzinfo=UTC)  # tranche en cours incluse
    assert series.start == series.end - timedelta(hours=24)
    by_hour = {p.at: p.total for p in series.points}
    assert by_hour[datetime(2026, 10, 8, 10, 0, tzinfo=UTC)] == 2
    assert by_hour[datetime(2026, 10, 8, 12, 0, tzinfo=UTC)] == 1
    assert series.total == 3  # l'IOC d'il y a deux jours est hors fenêtre
    assert sum(1 for p in series.points if p.total == 0) == 22
    assert all(p.at.tzinfo is not None for p in series.points)


async def test_alertes_par_jour_reparties_par_priorite(db_session: AsyncSession) -> None:
    db_session.add(
        CVE(
            id="CVE-2026-1000",
            description="x",
            published_date=NOW,
            last_modified_date=NOW,
            composite_risk_score=90,
            priority=RiskPriority.P0_CRITIQUE,
        )
    )
    await db_session.flush()
    for days, priority in (
        (0, "P0_CRITIQUE"),
        (0, "P1_ELEVE"),
        (3, "P0_CRITIQUE"),
        (8, "P0_CRITIQUE"),
    ):
        db_session.add(
            CVEAlert(
                cve_id="CVE-2026-1000",
                score=90,
                priority=priority,
                reason="kev",
                delivery_attempts=0,
                created_at=NOW - timedelta(days=days),
            )
        )
    await db_session.flush()

    series = await time_series(db_session, Metric.ALERTS, Window.D7, now=NOW)

    assert series.bucket == "day" and len(series.points) == 7
    assert series.points[-1].at == datetime(2026, 10, 8, tzinfo=UTC)
    assert series.points[-1].by_level == {"P0_CRITIQUE": 1, "P1_ELEVE": 1}
    assert series.points[-4].by_level == {"P0_CRITIQUE": 1}
    assert series.total == 3


async def test_incidents_sur_trente_jours(db_session: AsyncSession) -> None:
    db_session.add_all(
        [
            Incident(
                title=f"I{d}",
                description="x",
                severity=Severity.HIGH,
                status=IncidentStatus.NOUVEAU,
                created_at=NOW - timedelta(days=d),
            )
            for d in (1, 29, 31)
        ]
    )
    await db_session.flush()

    series = await time_series(db_session, Metric.INCIDENTS, Window.D30, now=NOW)

    assert len(series.points) == 30
    assert series.total == 2


async def test_api_timeseries(client: AsyncClient, db_session: AsyncSession) -> None:
    name = f"viewer-{uuid4().hex[:8]}"
    user = await create_user(
        db_session,
        username=name,
        email=f"{name}@cyberill.test",
        password="mot-de-passe-2026!",
        role=UserRole.VIEWER,
    )
    headers = {"Authorization": f"Bearer {create_access_token(user.id, user.role)}"}
    await ingest_indicators(db_session, [Observation("e.example.com")], now=datetime.now(UTC))

    response = await client.get(
        "/api/v1/dashboard/timeseries", params={"metric": "iocs"}, headers=headers
    )
    assert response.status_code == 200
    body = response.json()
    assert (body["metric"], body["window"], body["bucket"]) == ("iocs", "24h", "hour")
    assert len(body["points"]) == 24 and body["total"] == 1
    assert [p["by_level"] for p in body["points"] if p["total"]] == [{"MEDIUM": 1}]


@pytest.mark.parametrize("params", [{}, {"metric": "cves"}, {"metric": "iocs", "window": "1y"}])
async def test_api_parametres_invalides(
    client: AsyncClient, db_session: AsyncSession, params: dict[str, str]
) -> None:
    name = f"viewer-{uuid4().hex[:8]}"
    user = await create_user(
        db_session,
        username=name,
        email=f"{name}@cyberill.test",
        password="mot-de-passe-2026!",
        role=UserRole.VIEWER,
    )
    headers = {"Authorization": f"Bearer {create_access_token(user.id, user.role)}"}
    response = await client.get("/api/v1/dashboard/timeseries", params=params, headers=headers)
    assert response.status_code == 422


async def test_api_timeseries_anonyme_refuse(client: AsyncClient) -> None:
    response = await client.get("/api/v1/dashboard/timeseries", params={"metric": "iocs"})
    assert response.status_code == 401
