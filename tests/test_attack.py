"""M10 (ADR-023) : référentiel ATT&CK, techniques des détections, acteurs cités."""

import json
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import CVE
from illwatch.app.security import create_access_token
from illwatch.modules.attack.catalog import RULE_TECHNIQUES, technique_url
from illwatch.modules.attack.demo import demo_attack_data
from illwatch.modules.attack.service import actors_in, import_attack, technique_refs
from illwatch.modules.attack.stix import AttackBundleError, parse_bundle
from illwatch.modules.correlation.assets import AssetInput, create_asset
from illwatch.modules.foundation.users import create_user
from illwatch.modules.threat_feeds.indicators import Observation, ingest_indicators
from illwatch.modules.threat_hunting.rules import CATALOG
from illwatch.shared.enums import UserRole

NOW = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)


def _ref(external_id: str, kind: str = "mitre-attack") -> list[dict[str, str]]:
    return [{"source_name": kind, "external_id": external_id}]


BUNDLE = {
    "type": "bundle",
    "id": "bundle--1",
    "objects": [
        {"type": "x-mitre-collection", "id": "x-mitre-collection--1", "x_mitre_version": "18.0"},
        {
            "type": "attack-pattern",
            "id": "attack-pattern--a",
            "name": "Exploit Public-Facing Application",
            "external_references": _ref("T1190"),
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
            ],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--b",
            "name": "Phishing: Spearphishing Attachment",
            "external_references": _ref("T1566.001"),
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--old",
            "name": "Ancienne",
            "external_references": _ref("T9999"),
            "revoked": True,
        },
        {
            "type": "malware",
            "id": "malware--q",
            "name": "QakBot",
            "x_mitre_aliases": ["QakBot", "QBot", "Pinkslipbot"],
            "description": "QakBot is a banking trojan. (Citation: Source 2021)",
            "external_references": _ref("S0650"),
        },
        {
            "type": "tool",
            "id": "tool--tor",
            "name": "Tor",
            "external_references": _ref("S0183"),
        },
        {
            "type": "intrusion-set",
            "id": "intrusion-set--w",
            "name": "Wizard Spider",
            "aliases": ["Wizard Spider", "Grim Spider", "Royal"],
            "external_references": _ref("G0102"),
        },
        {
            "type": "relationship",
            "id": "relationship--1",
            "relationship_type": "uses",
            "source_ref": "malware--q",
            "target_ref": "attack-pattern--b",
        },
        {
            "type": "relationship",
            "id": "relationship--2",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--w",
            "target_ref": "attack-pattern--a",
        },
    ],
}


def test_lecture_du_bundle() -> None:
    data = parse_bundle(json.dumps(BUNDLE).encode())
    assert data.version == "18.0"
    assert set(data.techniques) == {"T1190", "T1566.001"}  # révoquée écartée
    assert data.techniques["T1566.001"].is_subtechnique
    assert data.techniques["T1190"].tactics == ["initial-access"]
    assert data.actors["S0650"].kind == "malware" and "QBot" in data.actors["S0650"].aliases
    assert data.actors["S0650"].description == "QakBot is a banking trojan."
    assert data.actors["S0183"].kind == "tool"
    assert data.uses == {("S0650", "T1566.001"), ("G0102", "T1190")}
    with pytest.raises(AttackBundleError):
        parse_bundle(b'{"type": "bundle", "objects": []}')
    with pytest.raises(AttackBundleError):
        parse_bundle(b"pas du json")


def test_chaque_regle_declare_ses_techniques() -> None:
    assert {r.id for r in CATALOG} <= set(RULE_TECHNIQUES)
    assert RULE_TECHNIQUES["RULE-03"] == ("T1568.002",)
    assert technique_url("T1568.002") == "https://attack.mitre.org/techniques/T1568/002/"


async def test_acteurs_cites_avec_prudence(db_session: AsyncSession) -> None:
    await import_attack(db_session, parse_bundle(json.dumps(BUNDLE).encode()), now=NOW)
    found = await actors_in(
        db_session,
        ["Qakbot distribution [démo]", "Relais de sortie Tor", "Royal Mail phishing"],
    )
    # QakBot reconnu (casse indifférente) ; « Tor » est un outil, « Royal » un mot courant.
    assert [(a.id, a.matched) for a in found] == [("S0650", "Qakbot")]
    assert [t.id for t in found[0].techniques] == ["T1566.001"]
    assert not await actors_in(db_session, ["QakBotnet", "pas de nom ici"])
    refs = await technique_refs(db_session, ["T1190", "T1568.002"])
    assert [(r.id, r.name) for r in refs] == [
        ("T1190", "Exploit Public-Facing Application"),
        ("T1568.002", "Dynamic Resolution: Domain Generation Algorithms"),  # nom intégré
    ]


async def test_contexte_attack_dans_l_api(client: AsyncClient, db_session: AsyncSession) -> None:
    await import_attack(db_session, demo_attack_data(), now=NOW)
    name = f"analyst-{uuid4().hex[:8]}"
    user = await create_user(
        db_session,
        username=name,
        email=f"{name}@cyberill.test",
        password="mot-de-passe-robuste-2026",
        role=UserRole.ANALYST,
    )
    headers = {"Authorization": f"Bearer {create_access_token(user.id, user.role)}"}
    db_session.add(
        CVE(
            id="CVE-2099-50001",
            description="Fortinet FortiOS heap overflow",
            is_kev=True,
            has_public_exploit=True,
            priority="P1_ELEVE",
            composite_risk_score=70.0,
            published_date=NOW - timedelta(days=3),
            last_modified_date=NOW,
        )
    )
    await ingest_indicators(db_session, [Observation("198.51.100.20", description="QBot C2")])
    await create_asset(
        db_session, AssetInput(name="Pare-feu", product="FortiOS", addresses=("198.51.100.20",))
    )
    await db_session.flush()

    status = (await client.get("/api/v1/attack/status", headers=headers)).json()
    assert status["techniques"] == 10 and "MITRE" in status["attribution"]
    technique = (await client.get("/api/v1/attack/techniques/T1486", headers=headers)).json()
    assert [a["id"] for a in technique["actors"]] == ["G0102"]
    assert (await client.get("/api/v1/attack/techniques/T0000", headers=headers)).status_code == 404

    await client.post("/api/v1/correlations/run", headers=headers)
    events = (await client.get("/api/v1/correlations", headers=headers)).json()["items"]
    kev = next(e for e in events if e["rule_id"] == "CORR-01")
    assert [t["id"] for t in kev["attack"]["techniques"]] == ["T1190"]
    hunt = await client.post(
        "/api/v1/hunting/sessions",
        json={"observables": ["198.51.100.20"], "rules": ["RULE-06"]},
        headers=headers,
    )
    assert hunt.status_code == 201, hunt.text
    match = hunt.json()["matches"][0]
    assert [a["name"] for a in match["attack"]["actors"]] == ["QakBot"]
    assert match["attack"]["techniques"] == []  # RULE-06 : « déjà vu », pas « comment »

    rules = (await client.get("/api/v1/hunting/rules", headers=headers)).json()
    assert {r["id"]: r["techniques"] for r in rules}["RULE-04"] == ["T1486"]

    created = await client.post(
        "/api/v1/incidents",
        json={"title": "Balise QakBot", "description": "EDR", "severity": "HIGH"},
        headers=headers,
    )
    iid = created.json()["id"]
    await client.post(
        f"/api/v1/incidents/{iid}/cves", json={"cve_id": "CVE-2099-50001"}, headers=headers
    )
    detail = (await client.get(f"/api/v1/incidents/{iid}", headers=headers)).json()
    assert [t["id"] for t in detail["attack"]["techniques"]] == ["T1190"]
    assert [a["id"] for a in detail["attack"]["actors"]] == ["S0650"]


# --- Campagnes (M10, incrément 2) --------------------------------------------------------------


async def test_campagnes_attribution_par_l_infrastructure(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from illwatch.modules.attack.campaigns import (
        CampaignError,
        CampaignExistsError,
        attach,
        campaigns_of,
        create_campaign,
    )

    await import_attack(db_session, demo_attack_data(), now=NOW)
    await ingest_indicators(
        db_session,
        [
            Observation("198.51.100.30", description="Pulse OTX : distribution printemps"),
            Observation("dl.example.net", description="Pulse OTX : distribution printemps"),
            Observation("198.51.100.31", description="autre chose"),
        ],
    )
    with pytest.raises(CampaignError):
        await create_campaign(db_session, name="Op X", actor_id="G9999")
    campaign = await create_campaign(db_session, name="Opération printemps", actor_id="g0102")
    assert campaign.actor_id == "G0102"
    with pytest.raises(CampaignExistsError):
        await create_campaign(db_session, name="Opération  printemps")
    attached, unknown = await attach(
        db_session, campaign.id, description_contains="distribution printemps"
    )
    assert (attached, unknown) == (2, 0)
    again, unknown = await attach(
        db_session, campaign.id, values=["198.51.100.30", "203.0.113.200", "pas un ioc"]
    )
    assert (again, unknown) == (0, 2)  # déjà rattaché ; inconnu ; invalide
    with pytest.raises(CampaignError):
        await attach(db_session, campaign.id, description_contains="ab")

    name = f"analyst-{uuid4().hex[:8]}"
    user = await create_user(
        db_session,
        username=name,
        email=f"{name}@cyberill.test",
        password="mot-de-passe-robuste-2026",
        role=UserRole.ANALYST,
    )
    headers = {"Authorization": f"Bearer {create_access_token(user.id, user.role)}"}
    hunt = await client.post(
        "/api/v1/hunting/sessions",
        json={"observables": ["198.51.100.30"], "rules": ["RULE-06"]},
        headers=headers,
    )
    context = hunt.json()["matches"][0]["attack"]
    assert [c["name"] for c in context["campaigns"]] == ["Opération printemps"]
    assert [(a["id"], a["matched"]) for a in context["actors"]] == [
        ("G0102", "campagne « Opération printemps »")
    ]
    listed = (await client.get("/api/v1/campaigns", headers=headers)).json()
    assert listed[0]["indicators"] == 2 and listed[0]["actor"]["name"] == "Wizard Spider"
    detail = (await client.get(f"/api/v1/campaigns/{campaign.id}", headers=headers)).json()
    assert {i["value"] for i in detail["infrastructure"]} == {"198.51.100.30", "dl.example.net"}
    refs = await campaigns_of(db_session, [UUID(detail["infrastructure"][0]["id"])])
    assert refs and refs[0].name == "Opération printemps"
    created = await client.post(
        "/api/v1/campaigns", json={"name": "Opération printemps"}, headers=headers
    )
    assert created.status_code == 409
    assert (
        await client.delete(f"/api/v1/campaigns/{campaign.id}", headers=headers)
    ).status_code == 403
