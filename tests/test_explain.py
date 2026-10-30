"""Priorisation expliquée (ADR-030) : chaque facteur dit s'il pousse la priorité, la modère ou
reste à vérifier, et l'échéance retient la plus proche des deux dates."""

from datetime import UTC, date, datetime
from uuid import uuid4

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import CVE, CorrelatedEvent
from illwatch.app.security import create_access_token
from illwatch.modules.correlation.assets import AssetInput, create_asset
from illwatch.modules.correlation.engine import run_correlation
from illwatch.modules.correlation.explain import AssetFacts, CveFacts, explain
from illwatch.modules.foundation.users import create_user
from illwatch.modules.threat_feeds.indicators import Observation, ingest_indicators
from illwatch.shared.enums import UserRole

SEEN = datetime(2026, 10, 30, 8, 0, tzinfo=UTC)

FIREWALL = AssetFacts(
    name="Pare-feu siège",
    criticality="CRITICAL",
    version="7.2.5",
    platform=None,
    addresses=("198.51.100.10",),
    domains=("vpn.example.com",),
)
KEV = CveFacts(
    cve_id="CVE-2099-1",
    cvss=9.8,
    epss=0.94,
    epss_percentile=0.999,
    is_kev=True,
    kev_date_added=date(2026, 10, 20),
    kev_due_date=date(2026, 10, 30),
    has_public_exploit=True,
    has_ransomware_campaign=True,
)


def _factors(result: object) -> dict[str, tuple[str, str]]:
    return {f.key: (f.effect, f.value) for f in result.factors}  # type: ignore[attr-defined]


def test_kev_sur_actif_critique_expose_et_version_confirmee() -> None:
    result = explain(
        rule_id="CORR-01",
        priority="P0_CRITIQUE",
        score=98.0,
        first_seen=SEEN,
        detail={
            "breakdown": {"base": 60.0, "criticality": 20.0, "signal": 18.0},
            "version_check": "vulnerable",
            "version_label": "version déclarée dans une plage vulnérable (NVD)",
        },
        asset=FIREWALL,
        cve=KEV,
    )
    factors = _factors(result)
    assert factors["criticality"][0] == "raises"
    assert (
        factors["exposure"][0] == "raises"
        and "1 adresse(s), 1 domaine(s)" in factors["exposure"][1]
    )
    assert factors["exploitation"][0] == "raises"
    assert (
        "20/10/2026" in factors["exploitation"][1] and "rançongiciels" in factors["exploitation"][1]
    )
    assert "94 %" in factors["exploitation"][1] and "99,9 %" in factors["exploitation"][1]
    assert factors["version"] == (
        "raises",
        "7.2.5 : version déclarée dans une plage vulnérable (NVD)",
    )
    assert [f.points for f in result.factors if f.points is not None] == [60.0, 20.0, 18.0]
    assert result.to_check == []
    assert result.summary.startswith("P0, score 98 / 100 : actif critique, exposé sur Internet")
    # Échéance CISA (30/10, 23 h 59) avant le délai P0 (31/10, 8 h) : la CISA l'emporte.
    assert result.deadline == datetime(2026, 10, 30, 23, 59, tzinfo=UTC)
    assert "CISA" in result.deadline_reason


def test_version_non_declaree_et_actif_interne_restent_a_verifier() -> None:
    internal = AssetFacts(
        name="Wiki", criticality="LOW", version=None, platform=None, addresses=(), domains=()
    )
    quiet = CveFacts(
        cve_id="CVE-2099-2",
        cvss=7.5,
        epss=0.02,
        epss_percentile=0.6,
        is_kev=False,
        kev_date_added=None,
        kev_due_date=None,
        has_public_exploit=True,
        has_ransomware_campaign=False,
    )
    result = explain(
        rule_id="CORR-02",
        priority="P2_MOYEN",
        score=50.0,
        first_seen=SEEN,
        detail={"version_check": "version_non_declaree", "version_label": "version non déclarée"},
        asset=internal,
        cve=quiet,
    )
    factors = _factors(result)
    assert factors["criticality"][0] == "lowers"
    assert factors["exposure"][0] == "check" and factors["version"][0] == "check"
    assert factors["exploitation"][0] == "neutral"
    assert len(result.to_check) == 2 and "2 point(s) à vérifier" in result.summary
    assert result.deadline == datetime(2026, 11, 29, 8, 0, tzinfo=UTC)  # P2 : 30 jours


def test_indicateur_d_une_seule_source() -> None:
    result = explain(
        rule_id="CORR-03",
        priority="P1_ELEVE",
        score=72.0,
        first_seen=SEEN,
        detail={"confidence": 75, "sources": 1, "breakdown": {"signal": 22.5}},
        asset=FIREWALL,
        cve=None,
    )
    factors = _factors(result)
    assert factors["confidence"] == ("raises", "75 / 100, 1 source(s)")
    assert any("Une seule source" in item for item in result.to_check)
    assert "version" not in factors and "exploitation" not in factors


async def test_api_correlation_expliquee(client: AsyncClient, db_session: AsyncSession) -> None:
    db_session.add(
        CVE(
            id="CVE-2099-80001",
            description="Fortinet FortiOS heap overflow",
            is_kev=True,
            has_public_exploit=True,
            priority="P1_ELEVE",
            composite_risk_score=60.0,
            published_date=SEEN,
            last_modified_date=SEEN,
            kev_due_date=date(2099, 1, 1),
        )
    )
    await ingest_indicators(db_session, [Observation("198.51.100.10")])
    await create_asset(
        db_session,
        AssetInput(
            name="Pare-feu",
            product="FortiOS",
            criticality="CRITICAL",
            addresses=("198.51.100.10",),
        ),
    )
    await run_correlation(db_session, min_confidence=0)
    await db_session.flush()
    name = f"viewer-{uuid4().hex[:8]}"
    viewer = await create_user(
        db_session,
        username=name,
        email=f"{name}@cyberill.test",
        password="mot-de-passe-robuste-2026",
        role=UserRole.VIEWER,
    )
    headers = {"Authorization": f"Bearer {create_access_token(viewer.id, viewer.role)}"}
    response = await client.get("/api/v1/correlations", headers=headers)
    assert response.status_code == 200
    items = {i["rule_id"]: i for i in response.json()["items"]}
    kev = items["CORR-01"]["explanation"]
    assert kev["summary"].startswith("P")
    assert {f["key"] for f in kev["factors"]} >= {"rule", "criticality", "exposure", "exploitation"}
    assert kev["deadline"] is not None
    ioc = items["CORR-03"]["explanation"]
    assert any(f["key"] == "confidence" for f in ioc["factors"])
    event = (
        await db_session.scalars(
            select(CorrelatedEvent).where(CorrelatedEvent.rule_id == "CORR-01")
        )
    ).one()
    single = await client.get(f"/api/v1/correlations/{event.id}", headers=headers)
    assert single.json()["explanation"]["factors"][0]["key"] == "rule"
