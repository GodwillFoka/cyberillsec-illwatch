"""Priorisation expliquée : ADR-030.

Le score d'un évènement corrélé se décompose déjà en trois parts (règle, criticité de l'actif,
signal). Pour décider quoi traiter d'abord, l'analyste a besoin de plus : la version est-elle
vraiment dans la plage vulnérable ? L'actif est-il exposé sur Internet ? La faille est-elle
exploitée aujourd'hui, et par qui ? Avant quand faut-il agir ?

Ce module répond à ces questions à partir des faits déjà connus, sans changer le score : il
dit, facteur par facteur, ce qui **pousse** la priorité vers le haut, ce qui la **modère**, et
ce qui reste **à vérifier**. Fonction pure : testée sans base ni serveur.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from typing import Any, Literal

from illwatch.modules.cve_tracker.scoring import remediation_sla_hours
from illwatch.shared.enums import CorrelationRule, RiskPriority, Severity
from illwatch.shared.server_text import tr

Effect = Literal["raises", "lowers", "neutral", "check"]

_CRITICALITY = {
    Severity.CRITICAL: ("critique", "critical"),
    Severity.HIGH: ("élevée", "high"),
    Severity.MEDIUM: ("moyenne", "medium"),
    Severity.LOW: ("faible", "low"),
}
_PRIORITY_SHORT = {
    RiskPriority.P0_CRITIQUE: "P0",
    RiskPriority.P1_ELEVE: "P1",
    RiskPriority.P2_MOYEN: "P2",
    RiskPriority.P3_FAIBLE: "P3",
}
# Verdicts de version (ADR-021) : seul « vulnerable » confirme ; les autres restent à vérifier.
_VERSION_CHECK = {"conditionnel", "inconnu", "version_non_declaree"}


@dataclass(frozen=True, slots=True)
class AssetFacts:
    name: str
    criticality: str
    version: str | None
    platform: str | None
    addresses: Sequence[str] = ()
    domains: Sequence[str] = ()


@dataclass(frozen=True, slots=True)
class CveFacts:
    cve_id: str
    cvss: float | None
    epss: float | None
    epss_percentile: float | None
    is_kev: bool
    kev_date_added: date | None
    kev_due_date: date | None
    has_public_exploit: bool
    has_ransomware_campaign: bool


@dataclass(frozen=True, slots=True)
class Factor:
    key: str  # rule, criticality, exploitation, version, exposure, confidence, freshness
    label: str
    value: str
    effect: Effect
    points: float | None = None  # part du score, quand le facteur en a une

    def public(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "value": self.value,
            "effect": self.effect,
            "points": self.points,
        }


@dataclass(slots=True)
class Explanation:
    summary: str
    deadline: datetime | None
    deadline_reason: str
    factors: list[Factor] = field(default_factory=list)
    to_check: list[str] = field(default_factory=list)

    def public(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "deadline": self.deadline,
            "deadline_reason": self.deadline_reason,
            "factors": [f.public() for f in self.factors],
            "to_check": self.to_check,
        }


def _pct(value: float) -> str:
    """« 99,9 % » en français, « 99.9 % » sinon ; « 94 % » plutôt que « 94,0 % »."""
    text = f"{value * 100:.1f}".rstrip("0").rstrip(".")
    return f"{tr(text.replace('.', ','), text)} %"


def _day(value: date) -> str:
    return value.strftime("%d/%m/%Y")


def _num(value: Any) -> float | None:
    return float(value) if isinstance(value, int | float) else None


def explain(
    *,
    rule_id: str,
    priority: str,
    score: float,
    first_seen: datetime,
    detail: dict[str, Any],
    asset: AssetFacts,
    cve: CveFacts | None,
) -> Explanation:
    """Explique pourquoi un évènement corrélé a sa priorité, et quand agir."""
    rule = CorrelationRule(rule_id)
    level = RiskPriority(priority)
    breakdown = detail.get("breakdown") or {}
    factors: list[Factor] = []
    to_check: list[str] = []
    reasons: list[str] = []

    # 1. La règle : ce qui a été relié.
    rule_text = {
        CorrelationRule.KEV_ASSET: tr(
            "une faille exploitée activement (catalogue KEV) touche ce produit",
            "an actively exploited flaw (KEV catalogue) affects this product",
        ),
        CorrelationRule.EXPLOIT_ASSET: tr(
            "une faille avec exploit public touche ce produit",
            "a flaw with a public exploit affects this product",
        ),
        CorrelationRule.ASSET_IN_IOC: tr(
            "une adresse ou un domaine de l'actif figure dans un indicateur de compromission",
            "an address or domain of the asset appears in an indicator of compromise",
        ),
    }[rule]
    factors.append(
        Factor(
            "rule",
            tr("Règle", "Rule"),
            tr(f"{rule.value} : {rule_text}", f"{rule.value}: {rule_text}"),
            "raises",
            _num(breakdown.get("base")),
        )
    )

    # 2. La criticité déclarée de l'actif.
    crit_fr, crit_en = _CRITICALITY.get(
        Severity(asset.criticality), (asset.criticality, asset.criticality)
    )
    crit_effect: Effect = (
        "raises" if asset.criticality in (Severity.CRITICAL, Severity.HIGH) else "lowers"
    )
    factors.append(
        Factor(
            "criticality",
            tr("Criticité de l'actif", "Asset criticality"),
            tr(f"{crit_fr} (déclarée dans l'inventaire)", f"{crit_en} (declared in the inventory)"),
            crit_effect,
            _num(breakdown.get("criticality")),
        )
    )
    if crit_effect == "raises":
        reasons.append(tr(f"actif {crit_fr}", f"{crit_en}-criticality asset"))

    # 3. L'exposition : ce que l'inventaire dit de la surface visible depuis Internet.
    exposed = len(asset.addresses) + len(asset.domains)
    if exposed:
        parts = []
        if asset.addresses:
            parts.append(
                tr(f"{len(asset.addresses)} adresse(s)", f"{len(asset.addresses)} address(es)")
            )
        if asset.domains:
            parts.append(tr(f"{len(asset.domains)} domaine(s)", f"{len(asset.domains)} domain(s)"))
        factors.append(
            Factor(
                "exposure",
                tr("Exposition", "Exposure"),
                tr(
                    f"exposé sur Internet : {', '.join(parts)} déclarés",
                    f"exposed to the Internet: {', '.join(parts)} declared",
                ),
                "raises",
            )
        )
        reasons.append(tr("exposé sur Internet", "Internet-facing"))
    else:
        factors.append(
            Factor(
                "exposure",
                tr("Exposition", "Exposure"),
                tr(
                    "aucune adresse ni aucun domaine exposé déclaré",
                    "no exposed address or domain declared",
                ),
                "check",
            )
        )
        to_check.append(
            tr(
                "Confirmer que l'actif n'est pas joignable depuis Internet (sinon, déclarer ses "
                "adresses ou domaines exposés).",
                "Confirm the asset is not reachable from the Internet (otherwise declare its "
                "exposed addresses or domains).",
            )
        )

    if cve is not None:
        # 4. L'exploitation : constatée (KEV, rançongiciel), publiée (exploit) ou prévue (EPSS).
        seen: list[str] = []
        if cve.is_kev:
            since = (
                tr(f" depuis le {_day(cve.kev_date_added)}", f" since {_day(cve.kev_date_added)}")
                if cve.kev_date_added
                else ""
            )
            seen.append(
                tr(f"exploitée activement (KEV){since}", f"actively exploited (KEV){since}")
            )
        if cve.has_ransomware_campaign:
            seen.append(tr("utilisée par des rançongiciels", "used by ransomware"))
        if cve.has_public_exploit:
            seen.append(tr("exploit public", "public exploit"))
        if cve.epss is not None:
            rank = (
                tr(
                    f", plus probable que {_pct(cve.epss_percentile)} des CVE",
                    f", more likely than {_pct(cve.epss_percentile)} of CVEs",
                )
                if cve.epss_percentile is not None
                else ""
            )
            seen.append(
                tr(
                    f"probabilité d'exploitation à 30 jours {_pct(cve.epss)}{rank}",
                    f"30-day exploitation probability {_pct(cve.epss)}{rank}",
                )
            )
        strong = cve.is_kev or cve.has_ransomware_campaign or (cve.epss or 0) >= 0.1
        factors.append(
            Factor(
                "exploitation",
                tr("Exploitation", "Exploitation"),
                "; ".join(seen) or tr("aucun signal d'exploitation", "no exploitation signal"),
                "raises" if strong else "neutral",
                _num(breakdown.get("signal")),
            )
        )
        if cve.is_kev:
            reasons.append(tr("faille exploitée activement", "actively exploited flaw"))
        elif cve.has_public_exploit:
            reasons.append(tr("exploit public", "public exploit"))

        # 5. La version : confirmée dans la plage vulnérable, ou à vérifier.
        verdict = str(detail.get("version_check") or "")
        version_label = str(detail.get("version_label") or "")
        if verdict == "vulnerable":
            factors.append(
                Factor(
                    "version",
                    tr("Version", "Version"),
                    tr(f"{asset.version} : {version_label}", f"{asset.version}: {version_label}")
                    if asset.version
                    else version_label,
                    "raises",
                )
            )
            reasons.append(tr("version vulnérable confirmée", "vulnerable version confirmed"))
        elif verdict in _VERSION_CHECK:
            factors.append(
                Factor("version", tr("Version", "Version"), version_label or verdict, "check")
            )
            to_check.append(
                tr(
                    "Vérifier la version installée par rapport à l'avis de l'éditeur avant de "
                    "mobiliser l'équipe.",
                    "Check the installed version against the vendor advisory before "
                    "mobilising the team.",
                )
            )
    else:
        # CORR-03 : la confiance et la fraîcheur de l'indicateur.
        confidence = _num(detail.get("confidence"))
        sources = int(_num(detail.get("sources")) or 0)
        if confidence is not None:
            effect: Effect = (
                "raises" if confidence >= 70 else "check" if confidence < 40 else "neutral"
            )
            factors.append(
                Factor(
                    "confidence",
                    tr("Confiance de l'indicateur", "Indicator confidence"),
                    tr(
                        f"{confidence:.0f} / 100, {sources} source(s)",
                        f"{confidence:.0f} / 100, {sources} source(s)",
                    ),
                    effect,
                    _num(breakdown.get("signal")),
                )
            )
            if effect == "raises":
                reasons.append(tr("indicateur de confiance élevée", "high-confidence indicator"))
            if sources <= 1:
                to_check.append(
                    tr(
                        "Une seule source rapporte cet indicateur : chercher une confirmation "
                        "(journaux, autre source) avant de bloquer.",
                        "Only one source reports this indicator: look for confirmation "
                        "(logs, another source) before blocking.",
                    )
                )

    # Échéance : la plus proche entre le délai de la priorité et l'échéance CISA.
    start = first_seen if first_seen.tzinfo else first_seen.replace(tzinfo=UTC)
    sla_hours = remediation_sla_hours(level)
    deadline = start + timedelta(hours=sla_hours)
    deadline_reason = tr(
        f"délai de remédiation de la priorité {_PRIORITY_SHORT[level]} ({sla_hours} h)",
        f"{_PRIORITY_SHORT[level]} remediation target ({sla_hours} h)",
    )
    if cve is not None and cve.kev_due_date is not None:
        cisa = datetime.combine(cve.kev_due_date, time(23, 59), tzinfo=UTC)
        if cisa < deadline:
            deadline = cisa
            deadline_reason = tr(
                f"échéance fixée par la CISA ({_day(cve.kev_due_date)})",
                f"CISA due date ({_day(cve.kev_due_date)})",
            )

    why = ", ".join(reasons) if reasons else tr("aucun facteur aggravant", "no aggravating factor")
    summary = tr(
        f"{_PRIORITY_SHORT[level]}, score {score:.0f} / 100 : {why}.",
        f"{_PRIORITY_SHORT[level]}, score {score:.0f} / 100: {why}.",
    )
    if to_check:
        summary += tr(
            f" {len(to_check)} point(s) à vérifier avant d'agir.",
            f" {len(to_check)} point(s) to check before acting.",
        )
    return Explanation(
        summary=summary,
        deadline=deadline,
        deadline_reason=deadline_reason,
        factors=factors,
        to_check=to_check,
    )
