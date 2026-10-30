"""M9 SOC Operations (ADR-022) : niveaux, faux positifs, chasse depuis l'incident,
recommandations, pilotage, et le critère de sortie : un incident traverse L1 → L2 → L3 sans
quitter ILLWATCH, MTTR mesuré."""

from datetime import UTC, date, datetime, timedelta
from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.api.v1 import incidents as incidents_api
from illwatch.app.models import CVE, CorrelatedEvent, Incident, IncidentEvent, User
from illwatch.app.security import create_access_token
from illwatch.modules.correlation.assets import AssetInput, create_asset
from illwatch.modules.correlation.engine import run_correlation
from illwatch.modules.correlation.events import mark_false_positive
from illwatch.modules.foundation.users import create_user
from illwatch.modules.incidents import service
from illwatch.modules.soc.exclusions import (
    ExclusionError,
    ExclusionExistsError,
    create_exclusion,
    find_exclusion,
)
from illwatch.modules.soc.metrics import soc_metrics
from illwatch.modules.soc.response import CveFacts, IocFacts, recommend
from illwatch.modules.threat_feeds.indicators import (
    Observation,
    ingest_indicators,
    list_indicators,
)
from illwatch.shared.enums import (
    IncidentEventType,
    IncidentStatus,
    IndicatorType,
    Severity,
    SocTier,
    UserRole,
)

NOW = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)


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


# --- Niveaux SOC -----------------------------------------------------------------------------


async def test_escalade_ne_fait_que_monter(db_session: AsyncSession) -> None:
    incident = await service.create_incident(
        db_session, title="Balise C2", description="d", severity=Severity.HIGH, author_id=None
    )
    assert incident.tier == SocTier.L1
    with pytest.raises(ValueError, match="Motif"):
        await service.escalate(db_session, incident.id, reason="  ", author_id=None)
    await service.escalate(db_session, incident.id, reason="Hôte métier touché", author_id=None)
    await service.escalate(db_session, incident.id, reason="Besoin d'une règle", author_id=None)
    assert (await service.get_incident(db_session, incident.id)).tier == SocTier.L3
    with pytest.raises(service.InvalidEscalationError):
        await service.escalate(db_session, incident.id, reason="Encore plus haut", author_id=None)
    loaded = await service.get_incident(db_session, incident.id)
    steps = [e.message for e in loaded.events if e.event_type == IncidentEventType.ESCALATED]
    assert steps[0].startswith("Escalade L1 → L2") and steps[1].startswith("Escalade L2 → L3")
    page = await service.list_incidents(db_session, limit=10, offset=0, tier=SocTier.L3)
    assert [i.id for i in page.items] == [incident.id]


# --- Liste d'exclusion -----------------------------------------------------------------------


async def test_ioc_exclu_n_est_plus_actif(db_session: AsyncSession) -> None:
    await ingest_indicators(
        db_session,
        [Observation("198.51.100.77", description="Scanner"), Observation("cdn.example.net")],
        now=NOW,
    )
    incident = await service.create_incident(
        db_session, title="Faux positif CDN", description="d", severity=Severity.LOW, author_id=None
    )
    with pytest.raises(ExclusionError):
        await create_exclusion(db_session, value="cdn.example.net", reason="", author_id=None)
    exclusion = await create_exclusion(
        db_session,
        value="CDN.Example.NET.",
        reason="CDN de l'organisation",
        author_id=None,
        incident_id=incident.id,
        now=NOW,
    )
    assert exclusion.value == "cdn.example.net" and exclusion.indicator_type == "DOMAIN"
    with pytest.raises(ExclusionExistsError):
        await create_exclusion(
            db_session, value="cdn.example.net", reason="Doublon", author_id=None
        )
    active = await list_indicators(db_session, limit=10, offset=0, now=NOW, active=True)
    assert {i.value for i in active.items} == {"198.51.100.77"}
    loaded = await service.get_incident(db_session, incident.id)
    assert any(e.event_type == IncidentEventType.IOC_EXCLUDED for e in loaded.events)

    # Exclusion à durée limitée : échue, l'IOC redevient actif ; elle peut être reposée.
    await create_exclusion(
        db_session,
        value="198.51.100.77",
        reason="Scanner autorisé",
        author_id=None,
        days=1,
        now=NOW,
    )
    later = NOW + timedelta(days=2)
    assert await find_exclusion(db_session, IndicatorType.IPV4, "198.51.100.77", later) is None
    active = await list_indicators(db_session, limit=10, offset=0, now=later, active=True)
    assert "198.51.100.77" in {i.value for i in active.items}
    await create_exclusion(
        db_session, value="198.51.100.77", reason="Toujours autorisé", author_id=None, now=later
    )


async def test_faux_positif_correle_jamais_rouvert(db_session: AsyncSession) -> None:
    analyst, _ = await _user(db_session, UserRole.ANALYST)
    db_session.add(
        CVE(
            id="CVE-2099-60001",
            description="Fortinet FortiOS heap overflow",
            is_kev=True,
            has_public_exploit=True,
            priority="P1_ELEVE",
            composite_risk_score=60.0,
            published_date=NOW - timedelta(days=5),
            last_modified_date=NOW,
        )
    )
    await ingest_indicators(db_session, [Observation("198.51.100.10")], now=NOW)
    await create_asset(
        db_session,
        AssetInput(name="Pare-feu", product="FortiOS", addresses=("198.51.100.10",)),
    )
    await run_correlation(db_session, now=NOW, min_confidence=0)
    events = (await db_session.scalars(select(CorrelatedEvent))).all()
    kev = next(e for e in events if e.rule_id == "CORR-01")
    ioc = next(e for e in events if e.rule_id == "CORR-03")
    with pytest.raises(ValueError):
        await mark_false_positive(db_session, kev.id, user_id=analyst.id, reason="non")
    await mark_false_positive(
        db_session, kev.id, user_id=analyst.id, reason="Version corrigée par l'éditeur"
    )
    await mark_false_positive(
        db_session, ioc.id, user_id=analyst.id, reason="Adresse partagée d'un CDN"
    )
    assert await find_exclusion(db_session, IndicatorType.IPV4, "198.51.100.10") is not None

    # La CVE s'aggrave (P0) : un acquittement simple rouvrirait, un faux positif non.
    cve = await db_session.get(CVE, "CVE-2099-60001")
    assert cve is not None
    cve.priority, cve.composite_risk_score = "P0_CRITIQUE", 99.0
    report = await run_correlation(db_session, now=NOW + timedelta(hours=1), min_confidence=0)
    assert report.reopened == 0
    await db_session.refresh(kev)
    assert kev.acknowledged_at is not None and kev.detail["false_positive"]["reason"]
    # L'IOC exclu n'est plus actif : CORR-03 ne le voit plus, l'évènement reste clos.
    assert report.by_rule.get("CORR-03", 0) == 0


# --- Recommandations -------------------------------------------------------------------------


def test_recommandations_selon_le_contenu_et_la_phase() -> None:
    recs = recommend(
        status=IncidentStatus.CONFINEMENT,
        severity=Severity.CRITICAL,
        tier=SocTier.L1,
        iocs=[
            IocFacts("IPV4", "203.0.113.50", "LockBit 3.0 affiliate"),
            IocFacts("DOMAIN", "update-92.malicious.example", None),
            IocFacts("HASH_SHA256", "a" * 64, None),
        ],
        cves=[CveFacts("CVE-2099-1", True, date(2026, 11, 1), True, False)],
    )
    titles = [r.title for r in recs]
    assert "Bloquer les adresses en périphérie" in titles
    assert "Bloquer les domaines au DNS" in titles
    assert "Bloquer les fichiers sur les postes" in titles
    assert "Isoler les hôtes touchés (rançongiciel)" in titles
    assert "Corriger CVE-2099-1" in titles
    assert "Escalader en L2" in titles
    assert recs[0].current and recs[0].phase == IncidentStatus.CONFINEMENT
    fix = next(r for r in recs if r.title == "Corriger CVE-2099-1")
    assert "01/11/2026" in fix.detail and not fix.current
    closed = recommend(status="CLOTURE", severity="LOW", tier="L3", iocs=[], cves=[])
    assert closed and all(r.phase == IncidentStatus.RECUPERATION for r in closed)


# --- Pilotage --------------------------------------------------------------------------------


async def test_pilotage_mtta_mttr_delais_et_charge(db_session: AsyncSession) -> None:
    admin, _ = await _user(db_session, UserRole.ADMIN)
    analyst, _ = await _user(db_session, UserRole.ANALYST)

    def incident(severity: Severity, opened: datetime, **kw: object) -> Incident:
        item = Incident(
            title=f"Incident {severity}",
            description="d",
            severity=severity,
            status=kw.pop("status", IncidentStatus.NOUVEAU),
            created_at=opened,
            updated_at=opened,
            **kw,
        )
        db_session.add(item)
        return item

    # Critique : pris en charge en 30 min, clos en 20 h (dans les délais 1 h / 24 h).
    fast = incident(
        Severity.CRITICAL,
        NOW - timedelta(days=2),
        status=IncidentStatus.CLOTURE,
        closed_at=NOW - timedelta(days=2) + timedelta(hours=20),
        assigned_to=analyst.id,
        tier=SocTier.L3,
    )
    # Élevé : pris en charge en 6 h (hors délai 4 h), toujours ouvert depuis 5 jours (> 72 h).
    slow = incident(Severity.HIGH, NOW - timedelta(days=5), assigned_to=analyst.id, tier="L2")
    # Moyen : jamais pris en charge, ouvert depuis 30 h (> 24 h).
    incident(Severity.MEDIUM, NOW - timedelta(hours=30))
    await db_session.flush()
    for item, delay, kind, message in (
        (fast, timedelta(minutes=30), IncidentEventType.ASSIGNED, "Incident assigné."),
        (fast, timedelta(hours=2), IncidentEventType.ESCALATED, "Escalade L1 → L2 (x). Motif : y"),
        (fast, timedelta(hours=3), IncidentEventType.ESCALATED, "Escalade L2 → L3 (x). Motif : y"),
        (slow, timedelta(hours=6), IncidentEventType.STATUS_CHANGE, "Nouveau → En analyse."),
    ):
        db_session.add(
            IncidentEvent(
                incident_id=item.id,
                event_type=kind,
                message=message,
                created_at=item.created_at + delay,
            )
        )
    await db_session.flush()

    metrics = await soc_metrics(db_session, viewer=admin, days=7, now=NOW)
    assert (metrics.opened, metrics.closed, metrics.open_now) == (3, 1, 2)
    assert metrics.mtta_minutes == pytest.approx((30 + 360) / 2)
    assert metrics.mttr_hours == pytest.approx(20.0)
    critical = next(s for s in metrics.by_severity if s.severity == "CRITICAL")
    high = next(s for s in metrics.by_severity if s.severity == "HIGH")
    assert critical.ack_within_sla == 1.0 and critical.resolved_within_sla == 1.0
    assert high.ack_within_sla == 0.0
    assert metrics.escalations == {"L1 → L2": 1, "L2 → L3": 1}
    assert metrics.open_by_tier == {"L1": 1, "L2": 1, "L3": 0}
    kinds = {(b.severity, b.kind) for b in metrics.breaches}
    assert kinds == {("HIGH", "résolution"), ("MEDIUM", "prise en charge")}
    assert len(metrics.daily) == 7
    names = {w.label for w in metrics.workload}
    assert analyst.username in names and "non assigné" in names
    # Un analyste ne voit pas les noms de ses collègues.
    colleague = User(
        id=uuid4(), username="x", email="x@cyberill.test", role=UserRole.ANALYST, hashed_password=""
    )
    other = await soc_metrics(db_session, viewer=colleague, days=7, now=NOW)
    assert analyst.username not in {w.label for w in other.workload}
    with pytest.raises(ValueError):
        await soc_metrics(db_session, viewer=admin, days=14, now=NOW)


# --- Critère de sortie : L1 → L2 → L3 sans quitter ILLWATCH, MTTR mesuré ----------------------


async def test_parcours_l1_l2_l3_de_bout_en_bout(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def no_tor(url: str) -> bytes:
        return b"185.220.101.1\n"

    monkeypatch.setattr(incidents_api, "fetch_feed_content", no_tor)
    _, viewer = await _user(db_session, UserRole.VIEWER)
    l1_user, l1 = await _user(db_session, UserRole.ANALYST)
    _, l2 = await _user(db_session, UserRole.ANALYST)
    _, l3 = await _user(db_session, UserRole.ADMIN)
    await ingest_indicators(
        db_session,
        [
            Observation("203.0.113.50", description="LockBit 3.0 affiliate"),
            Observation("cdn-partenaire.example"),
        ],
    )
    await db_session.flush()

    # L1 : qualification.
    created = await client.post(
        "/api/v1/incidents",
        json={
            "title": "Connexions vers une IP LockBit",
            "description": "EDR",
            "severity": "CRITICAL",
        },
        headers=l1,
    )
    assert created.status_code == 201, created.text
    incident = created.json()
    iid = incident["id"]
    assert incident["tier"] == "L1"
    assert any(r["title"] == "Escalader en L2" for r in incident["recommendations"])
    for value in ("203.0.113.50", "cdn-partenaire.example"):
        linked = await client.post(
            f"/api/v1/incidents/{iid}/indicators", json={"value": value}, headers=l1
        )
        assert linked.status_code == 200, linked.text
    await client.put(
        f"/api/v1/incidents/{iid}/assignee", json={"user_id": str(l1_user.id)}, headers=l1
    )
    refused = await client.post(
        f"/api/v1/incidents/{iid}/escalate", json={"reason": "Grave"}, headers=viewer
    )
    assert refused.status_code == 403
    up = await client.post(
        f"/api/v1/incidents/{iid}/escalate", json={"reason": "Infrastructure LockBit"}, headers=l1
    )
    assert up.status_code == 200 and up.json()["tier"] == "L2"

    # L2 : investigation, chasse depuis l'incident, faux positif écarté.
    hunt = await client.post(
        f"/api/v1/incidents/{iid}/hunt", json={"observables": ["185.220.101.1"]}, headers=l2
    )
    assert hunt.status_code == 201, hunt.text
    assert hunt.json()["trigger"] == "INCIDENT" and hunt.json()["matches_count"] >= 2
    excluded = await client.post(
        "/api/v1/exclusions",
        json={
            "value": "cdn-partenaire.example",
            "reason": "CDN d'un partenaire",
            "incident_id": iid,
        },
        headers=l2,
    )
    assert excluded.status_code == 201, excluded.text
    detail = (await client.get(f"/api/v1/incidents/{iid}", headers=viewer)).json()
    assert len(detail["hunts"]) == 1
    kinds = [e["event_type"] for e in detail["timeline"]]
    assert "HUNT_RUN" in kinds and "IOC_EXCLUDED" in kinds
    await client.post(
        f"/api/v1/incidents/{iid}/transitions", json={"target": "ANALYSE"}, headers=l2
    )
    up = await client.post(
        f"/api/v1/incidents/{iid}/escalate",
        json={"reason": "Règle de détection à écrire"},
        headers=l2,
    )
    assert up.json()["tier"] == "L3"
    again = await client.post(
        f"/api/v1/incidents/{iid}/escalate", json={"reason": "Plus haut"}, headers=l2
    )
    assert again.status_code == 409

    # L3 : réponse et clôture.
    for target in ("CONFINEMENT", "ERADICATION", "RECUPERATION"):
        moved = await client.post(
            f"/api/v1/incidents/{iid}/transitions", json={"target": target}, headers=l3
        )
        assert moved.status_code == 200, moved.text
    closed = await client.post(
        f"/api/v1/incidents/{iid}/transitions",
        json={"target": "CLOTURE", "closure_summary": "IP bloquée, poste réimagé, règle ajoutée."},
        headers=l3,
    )
    assert closed.status_code == 200, closed.text

    # Pilotage : MTTR mesuré, escalades comptées.
    soc = await client.get("/api/v1/dashboard/soc?days=7", headers=viewer)
    assert soc.status_code == 200, soc.text
    body = soc.json()
    assert body["closed"] >= 1 and body["mttr_hours"] is not None
    assert body["escalations"].get("L1 → L2", 0) >= 1 and body["escalations"].get("L2 → L3", 0) >= 1
    assert (await client.get("/api/v1/dashboard/soc?days=14", headers=viewer)).status_code == 422
    exclusions = (await client.get("/api/v1/exclusions", headers=viewer)).json()
    assert [e["value"] for e in exclusions] == ["cdn-partenaire.example"]
    indicator = (
        await client.get(
            "/api/v1/indicators", params={"value": "cdn-partenaire.example"}, headers=viewer
        )
    ).json()["items"][0]
    shown = (await client.get(f"/api/v1/indicators/{indicator['id']}", headers=viewer)).json()
    assert shown["exclusion"]["reason"] == "CDN d'un partenaire"
    rules = (await client.get("/api/v1/hunting/rules", headers=viewer)).json()
    assert {r["id"]: r["version"] for r in rules}["RULE-03"] == 2
