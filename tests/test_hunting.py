"""Threat hunting (phase 6) : règles, moteur, sessions, API (RF-25 à RF-28)."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.config import Settings
from illwatch.app.models import CVE
from illwatch.app.security import create_access_token
from illwatch.modules.foundation.users import create_user
from illwatch.modules.threat_feeds.indicators import Observation, ingest_indicators
from illwatch.modules.threat_hunting import engine
from illwatch.modules.threat_hunting.rules import (
    CATALOG,
    looks_generated,
    registered_label,
    shannon_entropy,
)
from illwatch.shared.enums import HuntStatus, HuntTrigger, RiskPriority, UserRole

NOW = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)
SETTINGS = Settings(secret_key="k" * 64)
TOR_LIST = b"# liste\n185.220.101.1\n2001:db8::dead\npas une ip\n"


async def tor(url: str) -> bytes:
    assert url == SETTINGS.tor_exit_list_url
    return TOR_LIST


async def tor_down(url: str) -> bytes:
    raise OSError("connexion refusée")


# --- Règles unitaires ------------------------------------------------------------------


def test_catalogue_conforme_au_cahier_des_charges() -> None:
    ids = [r.id for r in CATALOG]
    assert ids[:5] == ["RULE-01", "RULE-02", "RULE-03", "RULE-04", "RULE-05"]
    assert len(set(ids)) == len(ids)


@pytest.mark.parametrize(
    ("label", "generated"),
    [
        ("xjq8wz0vkp3mlq7b", True),  # DGA type Necurs
        ("qwrtzpkxvbnmlkjh", True),  # consonnes seules
        ("microsoftonline", False),  # mots du dictionnaire
        ("internationalbank", False),
        ("my-company-portal", False),  # tirets : noms composés
        ("xn--bcher-kva", False),  # IDN
        ("short1", False),
    ],
)
def test_heuristique_dga(label: str, generated: bool) -> None:
    assert looks_generated(label)[0] is generated


def test_outils() -> None:
    assert registered_label("a.b.example.co.uk") == "example"
    assert registered_label("login.evil.com") == "evil"
    assert shannon_entropy("") == 0.0 and shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") == pytest.approx(2.0)


# --- Moteur ---------------------------------------------------------------------------------


async def _seed_base(session: AsyncSession) -> None:
    await ingest_indicators(
        session,
        [
            Observation("203.0.113.50", description="LockBit 3.0 affiliate infrastructure"),
            Observation("198.51.100.77", description="Generic scanner"),
            Observation("cdn-update.duckdns.org"),
            Observation("xjq8wz0vkp3mlq7b.com"),
            Observation("185.220.101.1", description="Scanner"),
        ],
        now=NOW - timedelta(hours=1),
    )
    session.add(
        CVE(
            id="CVE-2026-2001",
            description="Fortinet FortiOS SSL-VPN heap overflow allows RCE.",
            published_date=NOW,
            last_modified_date=NOW,
            composite_risk_score=95,
            priority=RiskPriority.P0_CRITIQUE,
            has_public_exploit=True,
        )
    )
    await session.flush()


async def test_chasse_sur_observables(db_session: AsyncSession) -> None:
    await _seed_base(db_session)
    hunt = await engine.run_hunt(
        db_session,
        settings=SETTINGS,
        fetch=tor,
        observables=[
            "203.0.113.50",  # IOC ransomware connu → RULE-04 + RULE-06
            "185.220.101.1",  # relais Tor → RULE-01 (+ RULE-06, IOC connu)
            "beacon.cdn-update.duckdns.org",  # RULE-02
            "hxxp://kq3zx9vw7plm2nbt[.]net/a",  # RULE-03 (URL désamorcée)
            "www.example.org",  # rien
            "pas un observable",  # rejeté
            "203.0.113.50",  # doublon
        ],
        assets=["FortiOS", "Exchange"],
        clock=lambda: NOW,
    )
    loaded = await engine.get_hunt(db_session, hunt.id)
    found = {(m.rule_id, m.observable) for m in loaded.matches}
    assert ("RULE-04", "203.0.113.50") in found and ("RULE-06", "203.0.113.50") in found
    assert ("RULE-01", "185.220.101.1") in found
    assert ("RULE-02", "beacon.cdn-update.duckdns.org") in found
    assert ("RULE-03", "http://kq3zx9vw7plm2nbt.net/a") in found
    assert ("RULE-05", "FortiOS") in found and ("RULE-05", "Exchange") not in found
    assert not any(o == "www.example.org" for _, o in found)
    assert (loaded.observables_count, loaded.rejected_count) == (5, 1)
    assert loaded.status == HuntStatus.TERMINEE and loaded.matches_count == len(found)
    ransomware = next(m for m in loaded.matches if m.rule_id == "RULE-04")
    assert ransomware.severity == "CRITICAL" and ransomware.indicator_id is not None
    assert next(m for m in loaded.matches if m.rule_id == "RULE-05").cve_id == "CVE-2026-2001"


async def test_chasse_sur_la_base_planifiee(db_session: AsyncSession) -> None:
    await _seed_base(db_session)
    hunt = await engine.run_hunt(
        db_session, settings=SETTINGS, fetch=tor, trigger=HuntTrigger.SCHEDULED, clock=lambda: NOW
    )
    loaded = await engine.get_hunt(db_session, hunt.id)
    rules = {m.rule_id for m in loaded.matches}
    assert {"RULE-01", "RULE-02", "RULE-03", "RULE-04"} <= rules
    assert "RULE-06" not in rules  # sans observables, pas de correspondance « IOC connu »
    assert loaded.trigger == "SCHEDULED" and loaded.observables_count == 5


async def test_liste_tor_indisponible_session_partielle(db_session: AsyncSession) -> None:
    await _seed_base(db_session)
    hunt = await engine.run_hunt(
        db_session,
        settings=SETTINGS,
        fetch=tor_down,
        observables=["cdn.duckdns.org"],
        clock=lambda: NOW,
    )
    assert hunt.status == HuntStatus.PARTIELLE
    assert hunt.errors is not None and "RULE-01" in hunt.errors
    assert hunt.matches_count == 1  # RULE-02 exécutée malgré tout


async def test_limites_et_regle_inconnue(db_session: AsyncSession) -> None:
    with pytest.raises(engine.UnknownRuleError):
        await engine.run_hunt(db_session, settings=SETTINGS, fetch=tor, rule_ids=["RULE-99"])
    with pytest.raises(ValueError, match="10000"):
        await engine.run_hunt(
            db_session, settings=SETTINGS, fetch=tor, observables=["1.1.1.1"] * 10_001
        )
    only = await engine.run_hunt(
        db_session,
        settings=SETTINGS,
        fetch=tor_down,
        observables=["a.duckdns.org"],
        rule_ids=["RULE-02", "RULE-02"],
    )
    assert only.rules == "RULE-02" and only.status == HuntStatus.TERMINEE


async def test_cadence_de_chasse(db_session: AsyncSession) -> None:
    assert await engine.hunt_due(db_session, interval_seconds=3600, now=NOW)
    await engine.mark_hunt_attempt(db_session, NOW)
    assert not await engine.hunt_due(db_session, interval_seconds=3600, now=NOW)
    assert await engine.hunt_due(db_session, interval_seconds=3600, now=NOW + timedelta(hours=1))


# --- API ------------------------------------------------------------------------------------


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


async def test_api_hunting(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from illwatch.app.api.v1 import hunting

    monkeypatch.setattr(hunting, "fetch_feed_content", tor)
    await _seed_base(db_session)
    analyst = await _headers(db_session, UserRole.ANALYST)
    viewer = await _headers(db_session, UserRole.VIEWER)

    catalogue = (await client.get("/api/v1/hunting/rules", headers=viewer)).json()
    assert [r["id"] for r in catalogue][:5] == [
        "RULE-01",
        "RULE-02",
        "RULE-03",
        "RULE-04",
        "RULE-05",
    ]

    body: dict[str, Any] = {"observables": ["203.0.113.50", "x.duckdns.org"], "assets": ["FortiOS"]}
    assert (
        await client.post("/api/v1/hunting/sessions", json=body, headers=viewer)
    ).status_code == 403
    created = await client.post("/api/v1/hunting/sessions", json=body, headers=analyst)
    assert created.status_code == 201, created.text
    result = created.json()
    assert result["status"] == "TERMINEE" and result["matches_count"] >= 4
    assert {m["rule_id"] for m in result["matches"]} >= {"RULE-02", "RULE-04", "RULE-05", "RULE-06"}

    listed = (await client.get("/api/v1/hunting/sessions", headers=viewer)).json()
    assert listed[0]["id"] == result["id"]
    detail = await client.get(f"/api/v1/hunting/sessions/{result['id']}", headers=viewer)
    assert detail.status_code == 200 and detail.json()["matches"]
    assert (
        await client.get(f"/api/v1/hunting/sessions/{uuid4()}", headers=viewer)
    ).status_code == 404
    bad = await client.post(
        "/api/v1/hunting/sessions", json={"rules": ["RULE-99"]}, headers=analyst
    )
    assert bad.status_code == 422
