"""Tests unitaires des modèles relationnels et contraintes d'intégrité."""

from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app.models import CVE, Incident, Indicator, ThreatFeed, User
from sentry.shared.enums import FeedStatus, FeedType, IncidentStatus, IndicatorType, Severity


async def test_creation_utilisateur(db_session: AsyncSession) -> None:
    user = User(username="alex", email="alex@cyberill.com", hashed_password="x")
    db_session.add(user)
    await db_session.flush()

    assert user.id is not None
    assert user.role == "ANALYST"
    assert user.is_active is True


async def test_unicite_du_couple_type_valeur(db_session: AsyncSession) -> None:
    """RF-08 : la contrainte d'unicité est la garantie structurelle de la déduplication."""
    now = datetime.now(UTC)
    for _ in range(2):
        db_session.add(
            Indicator(
                type=IndicatorType.IPV4,
                value="185.220.101.5",
                severity=Severity.HIGH,
                first_seen=now,
                last_seen=now,
            )
        )

    with pytest.raises(IntegrityError):
        await db_session.flush()


async def test_flux_par_defaut_en_attente(db_session: AsyncSession) -> None:
    feed = ThreatFeed(
        name="CISA KEV", url="https://example.invalid/kev.json", feed_type=FeedType.JSON
    )
    db_session.add(feed)
    await db_session.flush()

    assert feed.status == FeedStatus.PENDING
    assert feed.is_active is True
    assert feed.polling_interval == 3600


async def test_cve_persistee_avec_score(db_session: AsyncSession) -> None:
    now = datetime.now(UTC)
    db_session.add(
        CVE(
            id="CVE-2026-16812",
            description="Exécution de code à distance non authentifiée.",
            cvss_score=9.8,
            epss_score=0.8920,
            is_kev=True,
            composite_risk_score=76.65,
            published_date=now,
            last_modified_date=now,
        )
    )
    await db_session.flush()

    result = await db_session.execute(select(CVE).where(CVE.id == "CVE-2026-16812"))
    cve = result.scalar_one()
    assert float(cve.composite_risk_score) == pytest.approx(76.65)
    assert cve.is_kev is True


async def test_incident_demarre_en_nouveau(db_session: AsyncSession) -> None:
    incident = Incident(
        title="Exfiltration suspectée",
        description="Trafic sortant anormal.",
        severity=Severity.HIGH,
    )
    db_session.add(incident)
    await db_session.flush()

    assert incident.status == IncidentStatus.NOUVEAU
    assert incident.closed_at is None
