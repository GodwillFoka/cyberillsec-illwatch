"""Moteur de Score de Risque Composite — RF-14 (§3.3.3 du Cahier des Charges).

Formule de référence (CdC v1.0.0, baseline approuvée) :

    R = min(100, CVSS x 3.0 + EPSS x 100 x 0.25 + K x 25 + E x 10 + A x 10)

    CVSS ∈ [0.0, 10.0]  sévérité technique brute (contribution max 30)
    EPSS ∈ [0.0, 1.0]   probabilité d'exploitation à 30 jours (max 25)
    K    ∈ {0, 1}       présence au catalogue CISA KEV (max 25)
    E    ∈ {0, 1}       exploit public documenté / PoC (max 10)
    A    ∈ {0, 1}       campagne ransomware ou attaque confirmée (max 10)

Somme des contributions maximales = 100, la borne `min` est donc une sécurité
défensive contre des entrées hors domaine plutôt qu'un écrêtage nominal.

ÉCART DOCUMENTÉ — le Product Vision Document v1.0 décrit une pondération
différente (CVSS 30 % + EPSS 25 % + KEV 25 % + Exploit 10 % + Ransomware 5 %
+ CWE 5 %) et des seuils différents (70/40/20 au lieu de 80/60/40). Le Cahier
des Charges, seul document « Approuvé pour Développement », fait foi pour la
v1.0. Voir docs/adr/ADR-001-scoring-composite.md.

PLANCHER KEV (ADR-014, décidé le 07/10/2026) — une CVE du catalogue CISA KEV est classée
**au moins P1**, quel que soit son score. Le score lui-même n'est pas modifié (formule
inchangée, comparabilité de l'historique préservée) : seule la priorité est relevée, et
`RiskBreakdown.kev_floor` le signale. Motif : une vulnérabilité activement exploitée ne peut
pas relever de la maintenance standard (directive CISA BOD 22-01). Sur la base réelle du
07/10, 612 CVE KEV sur 1 734 étaient classées P2 ou P3.
"""

from dataclasses import dataclass

from illwatch.shared.enums import RiskPriority

# Coefficients de pondération — §3.3.3
W_CVSS = 3.0
W_EPSS = 25.0
W_KEV = 25.0
W_EXPLOIT = 10.0
W_ATTACK = 10.0

MAX_SCORE = 100.0

# Grille de décision SOC — §3.3.3
THRESHOLD_CRITICAL = 80.0
THRESHOLD_HIGH = 60.0
THRESHOLD_MEDIUM = 40.0


@dataclass(frozen=True, slots=True)
class RiskBreakdown:
    """Décomposition auditable du score : chaque contribution est traçable."""

    cvss_contribution: float
    epss_contribution: float
    kev_contribution: float
    exploit_contribution: float
    attack_contribution: float
    total: float
    priority: RiskPriority
    # Priorité relevée à P1 par le plancher KEV (ADR-014) ; le score `total` est inchangé.
    kev_floor: bool = False


def compute_risk_score(
    *,
    cvss: float | None = None,
    epss: float | None = None,
    is_kev: bool = False,
    has_public_exploit: bool = False,
    has_ransomware_campaign: bool = False,
) -> float:
    """Calcule le score de risque composite déterministe ∈ [0, 100].

    Args:
        cvss: score CVSS v3.1 base ∈ [0.0, 10.0]. `None` vaut 0.0.
        epss: probabilité EPSS ∈ [0.0, 1.0]. `None` vaut 0.0.
        is_kev: la CVE figure au catalogue CISA KEV.
        has_public_exploit: un exploit public / PoC est documenté.
        has_ransomware_campaign: une campagne ransomware exploite la faille.

    Returns:
        Le score arrondi à 2 décimales.

    Raises:
        ValueError: si `cvss` ou `epss` sort de son domaine de définition.
    """
    return compute_risk_breakdown(
        cvss=cvss,
        epss=epss,
        is_kev=is_kev,
        has_public_exploit=has_public_exploit,
        has_ransomware_campaign=has_ransomware_campaign,
    ).total


def compute_risk_breakdown(
    *,
    cvss: float | None = None,
    epss: float | None = None,
    is_kev: bool = False,
    has_public_exploit: bool = False,
    has_ransomware_campaign: bool = False,
) -> RiskBreakdown:
    """Identique à `compute_risk_score` mais retourne le détail par composante."""
    cvss_value = 0.0 if cvss is None else float(cvss)
    epss_value = 0.0 if epss is None else float(epss)

    if not 0.0 <= cvss_value <= 10.0:
        raise ValueError(f"CVSS hors domaine [0.0, 10.0] : {cvss_value}")
    if not 0.0 <= epss_value <= 1.0:
        raise ValueError(f"EPSS hors domaine [0.0, 1.0] : {epss_value}")

    cvss_part = cvss_value * W_CVSS
    epss_part = epss_value * W_EPSS
    kev_part = W_KEV if is_kev else 0.0
    exploit_part = W_EXPLOIT if has_public_exploit else 0.0
    attack_part = W_ATTACK if has_ransomware_campaign else 0.0

    total = round(min(MAX_SCORE, cvss_part + epss_part + kev_part + exploit_part + attack_part), 2)
    priority = classify_priority(total)
    kev_floor = is_kev and priority in (RiskPriority.P2_MOYEN, RiskPriority.P3_FAIBLE)

    return RiskBreakdown(
        cvss_contribution=round(cvss_part, 2),
        epss_contribution=round(epss_part, 2),
        kev_contribution=kev_part,
        exploit_contribution=exploit_part,
        attack_contribution=attack_part,
        total=total,
        priority=RiskPriority.P1_ELEVE if kev_floor else priority,
        kev_floor=kev_floor,
    )


def classify_priority(score: float) -> RiskPriority:
    """Traduit un score en priorité SOC selon la grille de décision §3.3.3."""
    if score >= THRESHOLD_CRITICAL:
        return RiskPriority.P0_CRITIQUE
    if score >= THRESHOLD_HIGH:
        return RiskPriority.P1_ELEVE
    if score >= THRESHOLD_MEDIUM:
        return RiskPriority.P2_MOYEN
    return RiskPriority.P3_FAIBLE


def remediation_sla_hours(priority: RiskPriority) -> int:
    """Délai de remédiation contractuel associé à une priorité (en heures)."""
    return {
        RiskPriority.P0_CRITIQUE: 24,
        RiskPriority.P1_ELEVE: 24 * 7,
        RiskPriority.P2_MOYEN: 24 * 30,
        RiskPriority.P3_FAIBLE: 24 * 90,
    }[priority]
