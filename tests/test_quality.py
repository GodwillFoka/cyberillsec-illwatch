"""Qualité des alertes en situation réelle (ADR-029) : issue des signaux par règle et par
source, précision, bruit et délai de traitement."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import (
    CVE,
    CorrelatedEvent,
    CVEAlert,
    HuntingMatch,
    HuntingSession,
    Indicator,
    ThreatFeed,
    User,
)
from illwatch.app.security import create_access_token
from illwatch.modules.correlation.assets import AssetInput, create_asset
from illwatch.modules.correlation.engine import run_correlation
from illwatch.modules.correlation.events import mark_false_positive, open_incident
from illwatch.modules.foundation.users import create_user
from illwatch.modules.incidents import service
from illwatch.modules.soc.exclusions import create_exclusion
from illwatch.modules.soc.quality import alert_quality
from illwatch.modules.threat_feeds.indicators import Observation, ingest_indicators
from illwatch.shared.enums import FeedType, HuntStatus, HuntTrigger, Severity, UserRole


async def _user(session: AsyncSession, role: UserRole) -> tuple[User, dict[str, str]]:
    name = f"{role.value.lower()}-{uuid4().hex[:8]}"
    user = await create_user(
        session,
        username=name,
        email=f"{name}@cyberill.test",
        password="mot-de-passe-robuste-2026",
        role=role,
    )
    return user, {"Authorization": f"Bearer {create_access_token(user.id, user.role)}"}


async def _indicator(session: AsyncSession, value: str) -> Indicator:
    found = await session.scalar(select(Indicator).where(Indicator.value == value))
    assert found is not None
    return found


async def _scenario(session: AsyncSession) -> datetime:
    """Un mois de vie d'un SOC, en miniature. Renvoie l'instant de la mesure."""
    now = datetime.now(UTC)
    analyst, _ = await _user(session, UserRole.ANALYST)
    abuse = ThreatFeed(
        name="Source A", url="https://a.example/feed.csv", feed_type=FeedType.CSV, reliability="B"
    )
    otx = ThreatFeed(
        name="Source B", url="https://b.example/feed.csv", feed_type=FeedType.CSV, reliability="D"
    )
    session.add_all([abuse, otx])
    await session.flush()
    await ingest_indicators(
        session, [Observation("198.51.100.10"), Observation("203.0.113.9")], feed_id=abuse.id
    )
    await ingest_indicators(session, [Observation("evil.example.net")], feed_id=otx.id)

    # Corrélation : une CVE KEV sur le pare-feu, et son adresse dans un IOC.
    session.add(
        CVE(
            id="CVE-2099-70001",
            description="Fortinet FortiOS heap overflow",
            is_kev=True,
            has_public_exploit=True,
            priority="P1_ELEVE",
            composite_risk_score=60.0,
            published_date=now - timedelta(days=5),
            last_modified_date=now,
        )
    )
    await create_asset(
        session,
        AssetInput(name="Pare-feu", product="FortiOS", addresses=("198.51.100.10",)),
    )
    await run_correlation(session, now=now, min_confidence=0)
    events = (await session.scalars(select(CorrelatedEvent))).all()
    kev = next(e for e in events if e.rule_id == "CORR-01")
    ioc = next(e for e in events if e.rule_id == "CORR-03")
    await open_incident(session, kev.id, author_id=analyst.id)  # confirmé
    await mark_false_positive(
        session, ioc.id, user_id=analyst.id, reason="Adresse partagée d'un CDN"
    )  # faux positif, l'IOC passe en liste d'exclusion

    # Alertes CVE, sur une autre CVE (hors inventaire) : une confirmée, une ignorée, une hors
    # fenêtre.
    session.add(
        CVE(
            id="CVE-2099-70002",
            description="Contoso Widget remote code execution",
            priority="P0_CRITIQUE",
            composite_risk_score=90.0,
            published_date=now - timedelta(days=50),
            last_modified_date=now,
        )
    )
    await session.flush()
    alerts = [
        CVEAlert(
            cve_id="CVE-2099-70002",
            score=90,
            priority="P0_CRITIQUE",
            reason="kev",
            delivery_attempts=0,
            created_at=now - timedelta(hours=4),
        ),
        CVEAlert(
            cve_id="CVE-2099-70002",
            score=80,
            priority="P0_CRITIQUE",
            reason="epss",
            delivery_attempts=0,
            created_at=now - timedelta(hours=3),
            acknowledged_at=now - timedelta(hours=1),
        ),
        CVEAlert(
            cve_id="CVE-2099-70002",
            score=78,
            priority="P1_ELEVE",
            reason="kev+floor_kev",
            delivery_attempts=0,
            created_at=now - timedelta(days=40),  # hors fenêtre de 30 jours
        ),
    ]
    session.add_all(alerts)
    await session.flush()
    await service.create_incident(
        session,
        title="Réponse à l'alerte KEV",
        description="d",
        severity=Severity.CRITICAL,
        author_id=analyst.id,
        source_alert_id=alerts[0].id,
    )

    # Chasse : deux sessions quotidiennes retrouvent les mêmes observables.
    evil = await _indicator(session, "evil.example.net")
    known = await _indicator(session, "203.0.113.9")
    for offset in (2, 1):
        hunt = HuntingSession(
            trigger=HuntTrigger.SCHEDULED,
            status=HuntStatus.TERMINEE,
            rules="RULE-02,RULE-06",
            started_at=now - timedelta(days=offset),
            finished_at=now - timedelta(days=offset),
        )
        session.add(hunt)
        await session.flush()
        session.add_all(
            [
                HuntingMatch(
                    session_id=hunt.id,
                    rule_id="RULE-06",
                    severity=Severity.HIGH,
                    observable="evil.example.net",
                    detail="IOC connu",
                    indicator_id=evil.id,
                ),
                HuntingMatch(
                    session_id=hunt.id,
                    rule_id="RULE-06",
                    severity=Severity.MEDIUM,
                    observable="203.0.113.9",
                    detail="IOC connu",
                    indicator_id=known.id,
                ),
                HuntingMatch(
                    session_id=hunt.id,
                    rule_id="RULE-02",
                    severity=Severity.HIGH,
                    observable="maison.duckdns.org",
                    detail="DNS dynamique",
                ),
            ]
        )
    incident = await service.create_incident(
        session,
        title="Domaine malveillant",
        description="d",
        severity=Severity.HIGH,
        author_id=None,
    )
    await service.attach_indicator(session, incident.id, author_id=None, indicator_id=evil.id)
    await create_exclusion(
        session, value="maison.duckdns.org", reason="Accès distant du directeur", author_id=None
    )
    await session.flush()
    return now + timedelta(minutes=1)


async def test_qualite_par_regle_et_par_source(db_session: AsyncSession) -> None:
    moment = await _scenario(db_session)
    report = await alert_quality(db_session, days=30, now=moment)
    rows = {r.key: r for r in report.rules}

    # Alertes CVE : l'alerte de plus de 30 jours est hors fenêtre.
    assert rows["kev"].signals == 1 and rows["kev"].confirmed == 1
    assert rows["kev"].precision == 1.0 and rows["kev"].handling_hours_median is not None
    assert rows["epss"].signals == 1 and rows["epss"].ignored == 1 and rows["epss"].noise == 1.0
    assert rows["epss"].handling_hours_median == 2.0

    # Corrélation : CORR-01 confirmée par un incident, CORR-03 qualifiée faux positif.
    assert rows["CORR-01"].confirmed == 1 and rows["CORR-01"].precision == 1.0
    assert rows["CORR-03"].false_positive == 1 and rows["CORR-03"].precision == 0.0

    # Chasse : comptée par observable distinct, malgré deux sessions.
    assert rows["RULE-06"].signals == 2
    assert rows["RULE-06"].confirmed == 1 and rows["RULE-06"].pending == 1
    assert rows["RULE-02"].signals == 1 and rows["RULE-02"].false_positive == 1

    # Sources : ce que leurs IOC ont donné sur le terrain.
    sources = {s.name: s for s in report.sources}
    assert sources["Source A"].triggered == 2  # 198.51.100.10 (corrélation), 203.0.113.9 (chasse)
    assert sources["Source A"].false_positive == 1 and sources["Source A"].precision == 0.0
    assert sources["Source A"].reliability == "B"
    assert sources["Source B"].confirmed == 1 and sources["Source B"].precision == 1.0

    total = report.total
    assert total.signals == sum(r.signals for r in report.rules)
    assert total.confirmed == 3 and total.false_positive == 2


async def test_qualite_fenetre_vide_et_fenetre_refusee(db_session: AsyncSession) -> None:
    report = await alert_quality(db_session, days=7)
    assert report.rules == [] and report.sources == []
    assert report.total.precision is None and report.total.noise is None
    with pytest.raises(ValueError, match="Fenêtre"):
        await alert_quality(db_session, days=14)


async def test_api_qualite(client: AsyncClient, db_session: AsyncSession) -> None:
    await _scenario(db_session)
    _, viewer = await _user(db_session, UserRole.VIEWER)
    response = await client.get("/api/v1/dashboard/quality", params={"days": 30}, headers=viewer)
    assert response.status_code == 200
    body = response.json()
    assert body["window_days"] == 30
    assert {r["key"] for r in body["rules"]} >= {"kev", "epss", "CORR-01", "CORR-03", "RULE-06"}
    assert {s["name"] for s in body["sources"]} == {"Source A", "Source B"}
    refused = await client.get("/api/v1/dashboard/quality", params={"days": 3}, headers=viewer)
    assert refused.status_code == 422
    anonymous = await client.get("/api/v1/dashboard/quality")
    assert anonymous.status_code == 401
