"""Corrélation actifs × CVE × IOC (M8, ADR-020) et sa mesure sur le jeu figé (incrément 4)."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from click.testing import CliRunner
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import CVE, CorrelatedEvent, Incident
from illwatch.app.security import create_access_token
from illwatch.modules.correlation.assets import AssetError, AssetInput, create_asset
from illwatch.modules.correlation.benchmark import evaluate
from illwatch.modules.correlation.engine import product_pattern, run_correlation
from illwatch.modules.foundation.users import create_user
from illwatch.modules.threat_feeds.indicators import Observation, ingest_indicators
from illwatch.shared.enums import Severity, UserRole

NOW = datetime(2026, 10, 13, 12, 0, tzinfo=UTC)


def _cve(cve_id: str, description: str, *, kev: bool, exploit: bool, priority: str) -> CVE:
    return CVE(
        id=cve_id,
        description=description,
        is_kev=kev,
        has_public_exploit=exploit,
        priority=priority,
        composite_risk_score=70.0,
        published_date=NOW - timedelta(days=10),
        last_modified_date=NOW - timedelta(days=1),
    )


async def _headers(session: AsyncSession, role: UserRole) -> dict[str, str]:
    name = f"{role.value.lower()}-{uuid4().hex[:8]}"
    user = await create_user(
        session,
        username=name,
        email=f"{name}@cyberill.test",
        password="mot-de-passe-robuste-2026",
        role=role,
    )
    return {"Authorization": f"Bearer {create_access_token(user.id, user.role)}"}


def test_nom_de_produit_en_mot_entier() -> None:
    pattern = product_pattern("Exchange Server")
    assert pattern.search("Microsoft Exchange  Server RCE")
    assert not pattern.search("Exchangeable image file format")
    assert not product_pattern("FortiOS").search("FortiOSmonitor dashboard")
    assert product_pattern("FortiOS").search("Fortinet FortiOS SSL-VPN")


async def test_saisie_normalisee_et_controlee(db_session: AsyncSession) -> None:
    asset = await create_asset(
        db_session,
        AssetInput(
            name="  Pare-feu   siège ",
            product="FortiOS",
            addresses=("198.51.100.10", "198.51.100.10"),
            domains=("VPN.Corp.Example.",),
        ),
    )
    assert asset.name == "Pare-feu siège"
    assert asset.addresses == ["198.51.100.10"] and asset.domains == ["vpn.corp.example"]
    with pytest.raises(AssetError):
        await create_asset(db_session, AssetInput(name="X", product="ab"))
    with pytest.raises(AssetError):
        await create_asset(
            db_session, AssetInput(name="Y", product="Jenkins", addresses=("pas-ip",))
        )
    with pytest.raises(AssetError):
        await create_asset(db_session, AssetInput(name="Pare-feu siège", product="FortiOS"))


async def test_regles_et_deduplication(db_session: AsyncSession) -> None:
    db_session.add_all(
        [
            _cve(
                "CVE-2099-70001",
                "Fortinet FortiOS heap overflow",
                kev=True,
                exploit=True,
                priority="P0_CRITIQUE",
            ),
            _cve(
                "CVE-2099-70002", "FortiOS info leak", kev=False, exploit=True, priority="P1_ELEVE"
            ),
            _cve(
                "CVE-2099-70003", "FortiOS minor bug", kev=False, exploit=False, priority="P1_ELEVE"
            ),
        ]
    )
    await ingest_indicators(db_session, [Observation("198.51.100.10")])
    await create_asset(
        db_session,
        AssetInput(
            name="Pare-feu",
            product="FortiOS",
            criticality=Severity.CRITICAL,
            addresses=("198.51.100.10",),
        ),
    )
    first = await run_correlation(db_session, now=NOW, min_confidence=0)
    assert first.created == 3 and dict(first.by_rule) == {"CORR-01": 1, "CORR-02": 1, "CORR-03": 1}
    events = (await db_session.scalars(select(CorrelatedEvent))).all()
    kev = next(e for e in events if e.rule_id == "CORR-01")
    assert kev.priority == "P0_CRITIQUE"  # 60 + 20 (critique) + 14 (CVE 70) = 94
    assert kev.detail["breakdown"] == {"base": 60.0, "criticality": 20.0, "signal": 14.0}
    # Seconde passe : aucun doublon, mise à jour seulement.
    second = await run_correlation(db_session, now=NOW + timedelta(hours=1), min_confidence=0)
    assert second.created == 0 and second.updated == 3
    # Seuil de confiance : l'IOC soumis à la main (cote C, une observation) reste sous 90.
    await db_session.delete(next(e for e in events if e.rule_id == "CORR-03"))
    await db_session.flush()
    strict = await run_correlation(db_session, now=NOW, min_confidence=90)
    assert strict.by_rule.get("CORR-03", 0) == 0


async def test_api_inventaire_et_evenements(client: AsyncClient, db_session: AsyncSession) -> None:
    viewer = await _headers(db_session, UserRole.VIEWER)
    analyst = await _headers(db_session, UserRole.ANALYST)
    admin = await _headers(db_session, UserRole.ADMIN)
    db_session.add(
        _cve(
            "CVE-2099-70010",
            "Atlassian Confluence OGNL injection",
            kev=True,
            exploit=True,
            priority="P1_ELEVE",
        )
    )
    await db_session.flush()
    body = {"name": "Wiki", "product": "Confluence", "criticality": "HIGH"}
    assert (await client.post("/api/v1/assets", json=body, headers=viewer)).status_code == 403
    created = await client.post("/api/v1/assets", json=body, headers=analyst)
    assert created.status_code == 201, created.text
    asset_id = created.json()["id"]
    assert (await client.post("/api/v1/assets", json=body, headers=analyst)).status_code == 409
    bad = {**body, "name": "Autre", "domains": ["pas un domaine !"]}
    assert (await client.post("/api/v1/assets", json=bad, headers=analyst)).status_code == 422

    run = await client.post("/api/v1/correlations/run", headers=analyst)
    assert run.status_code == 200 and run.json()["created"] == 1
    page = (await client.get("/api/v1/correlations", headers=viewer)).json()
    assert page["total"] == 1
    event = page["items"][0]
    assert event["rule_id"] == "CORR-01" and event["asset_name"] == "Wiki"
    assert event["cve_id"] == "CVE-2099-70010"

    summary = (await client.get("/api/v1/dashboard/summary", headers=viewer)).json()
    assert summary["correlations"]["open"] == 1

    opened = await client.post(f"/api/v1/correlations/{event['id']}/incident", headers=analyst)
    assert opened.status_code == 201, opened.text
    again = await client.post(f"/api/v1/correlations/{event['id']}/incident", headers=analyst)
    assert again.status_code == 200
    assert again.json()["incident_id"] == opened.json()["incident_id"]
    incident = await db_session.get(Incident, opened.json()["incident_id"])
    assert incident is not None and incident.severity == "CRITICAL"  # 60 + 12 + 14 = 86 → P0
    # Ouvrir l'incident acquitte l'évènement : il quitte la liste des ouverts.
    assert (await client.get("/api/v1/correlations", headers=viewer)).json()["total"] == 0

    assert (await client.delete(f"/api/v1/assets/{asset_id}", headers=analyst)).status_code == 403
    assert (await client.delete(f"/api/v1/assets/{asset_id}", headers=admin)).status_code == 204
    remaining = (await client.get("/api/v1/correlations?open=false", headers=viewer)).json()
    assert remaining["total"] == 0  # évènements supprimés avec l'actif


async def test_mesure_sur_le_jeu_fige() -> None:
    """Critère de sortie de M8 : 100 % des cas attendus détectés, faux positifs mesurés."""
    result = await evaluate()
    assert result.missed == [], result.missed
    assert result.false_positives == [], result.false_positives
    assert result.recall == 1.0 and result.false_positive_rate == 0.0
    assert result.expected == 7 and result.cases == 15


def test_cli_evaluate(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from illwatch.cli.main import cli

    report = tmp_path / "mesure.md"
    result = CliRunner().invoke(cli, ["correlate", "evaluate", "--report", str(report)])
    assert result.exit_code == 0, result.output
    assert "100" in result.output and report.read_text(encoding="utf-8").startswith("# Mesure")
