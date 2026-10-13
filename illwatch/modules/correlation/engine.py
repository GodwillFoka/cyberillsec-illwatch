"""Moteur de corrélation — M8, ADR-020 (incrément 3).

Trois règles relient l'inventaire d'actifs au renseignement collecté :

- **CORR-01** : une CVE du catalogue KEV (exploitée activement) touche un produit de
  l'inventaire ;
- **CORR-02** : une CVE P0/P1 avec exploit public (hors KEV) touche un produit de
  l'inventaire ;
- **CORR-03** : une adresse IP ou un domaine de l'organisation figure dans un IOC actif dont
  la confiance atteint le seuil (`CORRELATION_MIN_CONFIDENCE`, 40 = « moyenne ») : un actif
  compromis, usurpé ou listé.

Score 0–100, chaque point justifié (`detail.breakdown`) : base de la règle + criticité de
l'actif + signal (score de la CVE ou confiance de l'IOC). La priorité suit la même grille
que les CVE (P0 ≥ 80, P1 ≥ 60, P2 ≥ 40). Un évènement est unique par règle et par couple
(actif, CVE/IOC) : une nouvelle passe le met à jour ; s'il monte d'un cran de priorité après
avoir été acquitté, il est rouvert.

Correspondance produit ↔ CVE : nom du produit en mot entier dans la description de la CVE
(insensible à la casse). Limite assumée : la version n'est pas comparée (pas de CPE) ; un
actif mal nommé produit du bruit, d'où la mesure de l'incrément 4.
"""

import contextlib
import ipaddress
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import ColumnElement, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import CVE, Asset, CollectorState, CorrelatedEvent, Indicator
from illwatch.modules.correlation.confidence import compute_confidence, source_reliabilities
from illwatch.modules.correlation.versions import VERDICT_LABEL, assess, platforms
from illwatch.modules.cve_tracker.scoring import classify_priority
from illwatch.modules.enrichment.lookup import enrich_ip
from illwatch.shared.enums import (
    CorrelationRule,
    IndicatorType,
    RiskPriority,
    Severity,
)

CORRELATION_STATE = "correlation"

BASE_POINTS: dict[CorrelationRule, float] = {
    CorrelationRule.KEV_ASSET: 60.0,
    CorrelationRule.EXPLOIT_ASSET: 45.0,
    CorrelationRule.ASSET_IN_IOC: 50.0,
}
CRITICALITY_POINTS: dict[str, float] = {
    Severity.LOW: 0.0,
    Severity.MEDIUM: 5.0,
    Severity.HIGH: 12.0,
    Severity.CRITICAL: 20.0,
}
CVE_SIGNAL_WEIGHT = 0.2  # score composite de la CVE (0–100) → 0–20 points
IOC_SIGNAL_WEIGHT = 0.3  # confiance de l'IOC (0–100) → 0–30 points

RULE_LABEL: dict[CorrelationRule, str] = {
    CorrelationRule.KEV_ASSET: "CVE exploitée activement (KEV) sur un actif",
    CorrelationRule.EXPLOIT_ASSET: "CVE avec exploit public sur un actif",
    CorrelationRule.ASSET_IN_IOC: "Actif présent dans un indicateur de compromission",
}

_RANK = {
    RiskPriority.P0_CRITIQUE: 0,
    RiskPriority.P1_ELEVE: 1,
    RiskPriority.P2_MOYEN: 2,
    RiskPriority.P3_FAIBLE: 3,
}


@dataclass
class CorrelationReport:
    assets: int = 0
    created: int = 0
    updated: int = 0
    reopened: int = 0
    resolved: int = 0
    by_rule: Counter[str] = field(default_factory=Counter)

    def as_dict(self) -> dict[str, Any]:
        return {
            "assets": self.assets,
            "created": self.created,
            "updated": self.updated,
            "reopened": self.reopened,
            "resolved": self.resolved,
            "by_rule": dict(self.by_rule),
        }


@dataclass(frozen=True)
class Finding:
    rule: CorrelationRule
    asset: Asset
    title: str
    signal: float  # 0–100 : score de la CVE ou confiance de l'IOC
    detail: dict[str, Any]
    cve_id: str | None = None
    indicator_id: Any = None

    @property
    def key(self) -> str:
        # Sans la règle : un même couple (actif, CVE) passe de CORR-02 à CORR-01 sans doublon.
        target = f"cve:{self.cve_id}" if self.cve_id else f"ioc:{self.indicator_id}"
        return f"{self.asset.id}:{target}"

    def breakdown(self) -> dict[str, float]:
        weight = CVE_SIGNAL_WEIGHT if self.cve_id else IOC_SIGNAL_WEIGHT
        return {
            "base": BASE_POINTS[self.rule],
            "criticality": CRITICALITY_POINTS.get(self.asset.criticality, 0.0),
            "signal": round(self.signal * weight, 1),
        }

    def score(self) -> float:
        return round(min(100.0, sum(self.breakdown().values())), 1)


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _like_literal(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def product_pattern(product: str) -> re.Pattern[str]:
    """Nom de produit en mot entier, insensible à la casse (« Exchange » ≠ « Exchangeable »)."""
    words = r"\s+".join(re.escape(part) for part in product.split())
    return re.compile(rf"(?<![\w-]){words}(?![\w-])", re.IGNORECASE)


async def _cve_findings(session: AsyncSession, asset: Asset) -> list[Finding]:
    product = asset.product.strip()
    if len(product) < 3:
        return []
    pattern = product_pattern(product)
    rows = (
        await session.scalars(
            select(CVE).where(
                CVE.description.ilike(f"%{_like_literal(product)}%", escape="\\"),
                or_(
                    CVE.is_kev.is_(True),
                    CVE.has_public_exploit.is_(True)
                    & CVE.priority.in_([RiskPriority.P0_CRITIQUE, RiskPriority.P1_ELEVE]),
                ),
            )
        )
    ).all()
    found: list[Finding] = []
    for cve in rows:
        if not pattern.search(cve.description):
            continue
        verdict = assess(product, asset.version, cve.affected)
        if verdict in ("autre_produit", "hors_plage"):
            # La NVD dit que ce produit n'est pas touché, ou pas dans cette version (ADR-021).
            continue
        rule = CorrelationRule.KEV_ASSET if cve.is_kev else CorrelationRule.EXPLOIT_ASSET
        signals = [
            label
            for flag, label in (
                (cve.is_kev, "catalogue KEV"),
                (cve.has_public_exploit, "exploit public"),
                (cve.has_ransomware_campaign, "campagnes de rançongiciel"),
            )
            if flag
        ]
        found.append(
            Finding(
                rule=rule,
                asset=asset,
                title=f"{cve.id} touche {asset.name} ({product})",
                signal=float(cve.composite_risk_score),
                cve_id=cve.id,
                detail={
                    "product": product,
                    "cve_priority": str(cve.priority),
                    "cve_score": float(cve.composite_risk_score),
                    "signals": signals,
                    "kev_due_date": cve.kev_due_date.isoformat() if cve.kev_due_date else None,
                    "version": asset.version,
                    "version_check": verdict,
                    "version_label": VERDICT_LABEL.get(verdict, verdict),
                    "version_platforms": (
                        platforms(product, cve.affected) if verdict == "conditionnel" else None
                    ),
                },
            )
        )
    return found


def _normalized_addresses(asset: Asset) -> set[str]:
    out: set[str] = set()
    for raw in asset.addresses or []:
        try:
            out.add(str(ipaddress.ip_address(str(raw).strip())))
        except ValueError:
            continue
    return out


async def _ioc_findings(
    session: AsyncSession, asset: Asset, *, now: datetime, min_confidence: int
) -> list[Finding]:
    addresses = _normalized_addresses(asset)
    domains = {str(d).strip().lower().rstrip(".") for d in asset.domains or [] if str(d).strip()}
    if not addresses and not domains:
        return []
    conditions: list[ColumnElement[bool]] = []
    if addresses:
        conditions.append(
            Indicator.type.in_([IndicatorType.IPV4, IndicatorType.IPV6])
            & Indicator.value.in_(sorted(addresses))
        )
    for domain in sorted(domains):
        conditions.append(
            (Indicator.type == IndicatorType.DOMAIN)
            & (
                (Indicator.value == domain)
                | Indicator.value.like(f"%.{_like_literal(domain)}", escape="\\")
            )
        )
    candidates = (
        await session.scalars(
            select(Indicator).where(
                or_(*conditions),
                or_(Indicator.expires_at.is_(None), Indicator.expires_at > now),
            )
        )
    ).all()
    cotes = await source_reliabilities(session, [i.id for i in candidates])
    found: list[Finding] = []
    for ioc in candidates:
        last_seen = _utc(ioc.last_seen) or now
        confidence = compute_confidence(
            reliabilities=cotes.get(ioc.id, []),
            ioc_type=ioc.type,
            last_seen=last_seen,
            hit_count=ioc.hit_count,
            now=now,
        )
        if confidence.total < min_confidence:
            continue
        detail: dict[str, Any] = {
            "value": ioc.value,
            "ioc_type": str(ioc.type),
            "ioc_severity": str(ioc.severity),
            "confidence": confidence.total,
            "confidence_level": confidence.level,
            "sources": len(cotes.get(ioc.id, [])),
            "description": ioc.description,
        }
        if ioc.type in (IndicatorType.IPV4, IndicatorType.IPV6):
            where = await enrich_ip(session, ioc.value)
            detail.update(country=where.country, asn=where.asn, as_org=where.as_org)
        found.append(
            Finding(
                rule=CorrelationRule.ASSET_IN_IOC,
                asset=asset,
                title=f"{ioc.value} ({asset.name}) figure dans un indicateur de compromission",
                signal=float(confidence.total),
                indicator_id=ioc.id,
                detail=detail,
            )
        )
    return found


ACK_PRIORITY = "acknowledged_priority"  # priorité au moment de l'acquittement (dans `detail`)
RESOLVED_AT = "resolved_at"  # l'évènement ne correspondait plus : clos par le moteur


def _upsert(
    session: AsyncSession,
    existing: dict[str, CorrelatedEvent],
    finding: Finding,
    now: datetime,
    report: CorrelationReport,
) -> None:
    score = finding.score()
    priority = classify_priority(score)
    detail: dict[str, Any] = {
        **finding.detail,
        "rule_label": RULE_LABEL[finding.rule],
        "asset": finding.asset.name,
        "asset_criticality": str(finding.asset.criticality),
        "breakdown": finding.breakdown(),
    }
    report.by_rule[finding.rule.value] += 1
    event = existing.get(finding.key)
    if event is None:
        event = CorrelatedEvent(
            rule_id=finding.rule.value,
            dedup_key=finding.key,
            priority=priority.value,
            score=score,
            title=finding.title[:300],
            detail=detail,
            asset_id=finding.asset.id,
            cve_id=finding.cve_id,
            indicator_id=finding.indicator_id,
            first_seen=now,
            last_seen=now,
        )
        session.add(event)
        existing[finding.key] = event
        report.created += 1
        return
    previous = event.detail or {}
    if event.acknowledged_at is not None:
        ack_priority = str(previous.get(ACK_PRIORITY, event.priority))
        worse = _RANK[priority] < _RANK[RiskPriority(ack_priority)]
        if previous.get(RESOLVED_AT) or worse:
            # Correspond de nouveau après avoir été clos, ou plus grave qu'au moment de
            # l'acquittement : l'évènement redemande l'attention.
            event.acknowledged_at = None
            event.acknowledged_by = None
            report.reopened += 1
        else:
            detail[ACK_PRIORITY] = ack_priority
    # La règle peut changer pour un même couple (CVE entrée au catalogue KEV : CORR-02 → 01).
    event.rule_id = finding.rule.value
    event.priority = priority.value
    event.score = score
    event.title = finding.title[:300]
    event.detail = detail
    event.last_seen = now
    report.updated += 1


async def _lock_pass(session: AsyncSession) -> None:
    """Sérialise les passes (worker, bouton, CLI) : la seconde attend la fin de la première,
    puis retrouve ses évènements au lieu d'en créer des doublons. Verrou de ligne PostgreSQL
    (SQLite, sans concurrence ici, l'ignore)."""
    if await session.get(CollectorState, CORRELATION_STATE) is None:
        # Création concurrente possible : le point de sauvegarde annule seulement ce doublon.
        with contextlib.suppress(IntegrityError):
            async with session.begin_nested():
                session.add(CollectorState(name=CORRELATION_STATE, items=0))
    await session.execute(
        select(CollectorState.name)
        .where(CollectorState.name == CORRELATION_STATE)
        .with_for_update()
    )


async def run_correlation(
    session: AsyncSession, *, now: datetime | None = None, min_confidence: int = 40
) -> CorrelationReport:
    """Passe complète sur les actifs en service. L'appelant valide la transaction.

    Un évènement encore ouvert qui ne correspond plus (IOC expiré, actif retiré, CVE sortie
    des critères) est clos par le moteur ; il se rouvre s'il correspond de nouveau.
    """
    moment = now or datetime.now(UTC)
    report = CorrelationReport()
    await _lock_pass(session)
    existing = {e.dedup_key: e for e in (await session.scalars(select(CorrelatedEvent))).all()}
    seen: set[str] = set()
    assets = (
        await session.scalars(select(Asset).where(Asset.is_active.is_(True)).order_by(Asset.name))
    ).all()
    report.assets = len(assets)
    for asset in assets:
        findings = await _cve_findings(session, asset)
        findings += await _ioc_findings(session, asset, now=moment, min_confidence=min_confidence)
        for finding in findings:
            if finding.key in seen:
                continue
            seen.add(finding.key)
            _upsert(session, existing, finding, moment, report)
    for key, event in existing.items():
        if key in seen or event.acknowledged_at is not None:
            continue
        event.acknowledged_at = moment
        event.detail = {**(event.detail or {}), RESOLVED_AT: moment.isoformat()}
        report.resolved += 1
    await session.flush()
    return report


async def correlation_due(session: AsyncSession, *, interval_seconds: int, now: datetime) -> bool:
    state = await session.get(CollectorState, CORRELATION_STATE)
    last = _utc(None if state is None else state.last_success_at)
    return last is None or last + timedelta(seconds=interval_seconds) <= now


async def mark_correlation(session: AsyncSession, now: datetime, items: int) -> None:
    state = await session.get(CollectorState, CORRELATION_STATE)
    if state is None:
        state = CollectorState(name=CORRELATION_STATE, items=0)
        session.add(state)
    state.last_success_at = now
    state.items = items
    await session.flush()
