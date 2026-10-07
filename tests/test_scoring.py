"""Tests du moteur de Score de Risque Composite — RF-14."""

import pytest

from illwatch.modules.cve_tracker.scoring import (
    classify_priority,
    compute_risk_breakdown,
    compute_risk_score,
    remediation_sla_hours,
)
from illwatch.shared.enums import RiskPriority


def test_score_nul_sans_donnee() -> None:
    assert compute_risk_score() == 0.0


def test_score_maximal_borne_a_100() -> None:
    score = compute_risk_score(
        cvss=10.0,
        epss=1.0,
        is_kev=True,
        has_public_exploit=True,
        has_ransomware_campaign=True,
    )
    assert score == 100.0


def test_contributions_conformes_au_cahier_des_charges() -> None:
    """CVSS 9.8 + EPSS 0.89 + KEV : 29.4 + 22.25 + 25 = 76.65."""
    breakdown = compute_risk_breakdown(cvss=9.8, epss=0.89, is_kev=True)
    assert breakdown.cvss_contribution == pytest.approx(29.4)
    assert breakdown.epss_contribution == pytest.approx(22.25)
    assert breakdown.kev_contribution == 25.0
    assert breakdown.exploit_contribution == 0.0
    assert breakdown.total == pytest.approx(76.65)
    assert breakdown.priority is RiskPriority.P1_ELEVE


def test_cvss_seul_ne_declenche_jamais_une_alerte_critique() -> None:
    """Une CVSS 10.0 sans exploitation observée plafonne à 30 : c'est voulu."""
    assert compute_risk_score(cvss=10.0) == 30.0
    assert classify_priority(30.0) is RiskPriority.P3_FAIBLE


def test_kev_plus_epss_eleve_atteint_le_seuil_critique() -> None:
    score = compute_risk_score(cvss=9.8, epss=0.95, is_kev=True, has_public_exploit=True)
    assert score >= 80.0
    assert classify_priority(score) is RiskPriority.P0_CRITIQUE


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (100.0, RiskPriority.P0_CRITIQUE),
        (80.0, RiskPriority.P0_CRITIQUE),
        (79.99, RiskPriority.P1_ELEVE),
        (60.0, RiskPriority.P1_ELEVE),
        (59.99, RiskPriority.P2_MOYEN),
        (40.0, RiskPriority.P2_MOYEN),
        (39.99, RiskPriority.P3_FAIBLE),
        (0.0, RiskPriority.P3_FAIBLE),
    ],
)
def test_grille_de_decision_soc(score: float, expected: RiskPriority) -> None:
    assert classify_priority(score) is expected


@pytest.mark.parametrize(
    ("cvss", "epss"),
    [(10.1, None), (-0.1, None), (None, 1.1), (None, -0.01)],
)
def test_entrees_hors_domaine_rejetees(cvss: float | None, epss: float | None) -> None:
    with pytest.raises(ValueError):
        compute_risk_score(cvss=cvss, epss=epss)


def test_determinisme() -> None:
    kwargs = {"cvss": 7.5, "epss": 0.42, "is_kev": False, "has_public_exploit": True}
    assert compute_risk_score(**kwargs) == compute_risk_score(**kwargs)


def test_sla_de_remediation() -> None:
    assert remediation_sla_hours(RiskPriority.P0_CRITIQUE) == 24
    assert remediation_sla_hours(RiskPriority.P1_ELEVE) == 168


# --- ADR-014 : plancher KEV ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "priority", "floor"),
    [
        ({"is_kev": True}, RiskPriority.P1_ELEVE, True),  # 25 points : P3 par la formule
        ({"cvss": 7.5, "is_kev": True}, RiskPriority.P1_ELEVE, True),  # 47,5 : P2 par la formule
        ({"cvss": 9.8, "epss": 0.89, "is_kev": True}, RiskPriority.P1_ELEVE, False),  # déjà P1
        (
            {"cvss": 9.8, "epss": 0.95, "is_kev": True, "has_public_exploit": True},
            RiskPriority.P0_CRITIQUE,
            False,
        ),
        ({"cvss": 7.5}, RiskPriority.P3_FAIBLE, False),  # hors KEV : formule seule
    ],
)
def test_plancher_kev(kwargs: dict[str, object], priority: RiskPriority, floor: bool) -> None:
    """Une CVE exploitée (KEV) n'est jamais en P2/P3 ; le score, lui, reste celui de la formule."""
    breakdown = compute_risk_breakdown(**kwargs)  # type: ignore[arg-type]
    assert breakdown.priority is priority
    assert breakdown.kev_floor is floor
    assert breakdown.total == compute_risk_score(**kwargs)  # type: ignore[arg-type]
