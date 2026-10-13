"""Investigation (L2) et réponse (L3) depuis un incident — M9 (ADR-022).

- `hunt_from_incident` : chasse lancée sur les IOC associés à l'incident (et, au besoin,
  d'autres observables relevés pendant l'investigation), avec l'inventaire d'actifs pour
  RULE-05 ; la session est rattachée à l'incident et résumée dans sa chronologie.
- `recommend` : recommandations de réponse déduites de ce que contient l'incident (types
  d'IOC, CVE KEV ou à exploit, campagne de rançongiciel) et de sa phase NIST. ILL Watch
  recommande ; il n'exécute rien : l'analyste déclare ensuite l'action menée.
"""

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import date
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.config import Settings
from illwatch.app.models import (
    CVE,
    Asset,
    HuntingSession,
    Incident,
    IncidentCVE,
    IncidentEvent,
    IncidentIndicator,
    Indicator,
)
from illwatch.modules.incidents.service import IncidentClosedError, get_incident
from illwatch.modules.threat_hunting import engine
from illwatch.modules.threat_hunting.rules import RANSOMWARE_PATTERN
from illwatch.shared.enums import (
    HuntTrigger,
    IncidentEventType,
    IncidentStatus,
    IndicatorType,
    Severity,
    SocTier,
)

MAX_EXTRA = 1000


# --- Chasse depuis l'incident ---------------------------------------------------------------


async def incident_observables(session: AsyncSession, incident_id: UUID) -> list[str]:
    rows = await session.scalars(
        select(Indicator.value)
        .join(IncidentIndicator, IncidentIndicator.indicator_id == Indicator.id)
        .where(IncidentIndicator.incident_id == incident_id)
        .order_by(IncidentIndicator.added_at)
    )
    return list(rows.all())


async def hunt_from_incident(
    session: AsyncSession,
    incident_id: UUID,
    *,
    author_id: UUID | None,
    settings: Settings,
    fetch: Callable[[str], Awaitable[bytes]],
    extra: Sequence[str] = (),
) -> HuntingSession:
    """Chasse sur les IOC de l'incident (+ observables relevés), rattachée à l'incident."""
    incident = await get_incident(session, incident_id)
    if incident.status == IncidentStatus.CLOTURE:
        raise IncidentClosedError("Incident clos : la chasse se lance sur un incident ouvert.")
    if len(extra) > MAX_EXTRA:
        raise ValueError(f"{MAX_EXTRA} observables supplémentaires au plus.")
    values = list(dict.fromkeys([*await incident_observables(session, incident.id), *extra]))
    products = list(
        (
            await session.scalars(
                select(Asset.product).where(Asset.is_active.is_(True)).order_by(Asset.product)
            )
        ).all()
    )
    if not values and not products:
        raise ValueError(
            "Rien à chasser : associez des IOC à l'incident, saisissez des observables ou "
            "déclarez l'inventaire d'actifs."
        )
    hunt = await engine.run_hunt(
        session,
        settings=settings,
        fetch=fetch,
        observables=values,
        assets=list(dict.fromkeys(products))[: engine.MAX_ASSETS],
        rule_ids=None if values else ["RULE-05"],
        trigger=HuntTrigger.INCIDENT,
        author_id=author_id,
        incident_id=incident.id,
    )
    loaded = await engine.get_hunt(session, hunt.id)
    lines = [
        f"Chasse sur {hunt.observables_count} observable(s) et {len(products)} produit(s) de "
        f"l'inventaire : {hunt.matches_count} correspondance(s), statut {hunt.status}."
    ]
    lines += [
        f"• {m.rule_id} · {m.observable[:120]} : {m.detail[:160]}" for m in loaded.matches[:8]
    ]
    if hunt.matches_count > 8:
        lines.append(f"… et {hunt.matches_count - 8} autres (écran Chasse).")
    session.add(
        IncidentEvent(
            incident_id=incident.id,
            author_id=author_id,
            event_type=IncidentEventType.HUNT_RUN,
            message="\n".join(lines),
            created_at=hunt.finished_at or hunt.started_at,
        )
    )
    await session.flush()
    return hunt


async def incident_hunts(session: AsyncSession, incident_id: UUID) -> list[HuntingSession]:
    return list(
        (
            await session.scalars(
                select(HuntingSession)
                .where(HuntingSession.incident_id == incident_id)
                .order_by(HuntingSession.started_at.desc())
                .limit(20)
            )
        ).all()
    )


# --- Recommandations de réponse -------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Recommendation:
    phase: str  # étape NIST où l'action s'inscrit
    title: str
    detail: str
    current: bool  # à faire dans la phase en cours de l'incident


@dataclass(frozen=True, slots=True)
class IocFacts:
    type: str
    value: str
    description: str | None


@dataclass(frozen=True, slots=True)
class CveFacts:
    id: str
    is_kev: bool
    kev_due_date: date | None
    has_public_exploit: bool
    has_ransomware_campaign: bool


def _sample(values: Sequence[str], limit: int = 3) -> str:
    shown = ", ".join(values[:limit])
    return shown + (f" (+ {len(values) - limit})" if len(values) > limit else "")


def recommend(
    *,
    status: str,
    severity: str,
    tier: str,
    iocs: Sequence[IocFacts],
    cves: Sequence[CveFacts],
) -> list[Recommendation]:
    """Recommandations ordonnées (phase en cours d'abord), déterministes et explicables."""
    phase = IncidentStatus(status)
    out: list[tuple[IncidentStatus, str, str]] = []
    by_type: dict[str, list[str]] = {}
    for ioc in iocs:
        by_type.setdefault(ioc.type, []).append(ioc.value)

    if severity == Severity.CRITICAL and tier == SocTier.L1 and phase != IncidentStatus.CLOTURE:
        out.append(
            (
                IncidentStatus.ANALYSE,
                "Escalader en L2",
                "Sévérité critique : l'investigation relève du niveau 2 (escalade motivée).",
            )
        )
    if iocs and phase in (IncidentStatus.NOUVEAU, IncidentStatus.ANALYSE):
        out.append(
            (
                IncidentStatus.ANALYSE,
                "Chasser les IOC de l'incident",
                "Lancer la chasse depuis l'incident : correspondances avec la base, DNS "
                "dynamique, DGA, infrastructures de rançongiciel, CVE de l'inventaire.",
            )
        )
    addresses = by_type.get(IndicatorType.IPV4, []) + by_type.get(IndicatorType.IPV6, [])
    addresses += by_type.get(IndicatorType.NETWORK, [])
    if addresses:
        out.append(
            (
                IncidentStatus.CONFINEMENT,
                "Bloquer les adresses en périphérie",
                f"Pare-feu et proxy : {_sample(addresses)} ; rechercher les connexions "
                "sortantes vers ces adresses sur 30 jours (journaux pare-feu, NetFlow).",
            )
        )
    if by_type.get(IndicatorType.DOMAIN):
        out.append(
            (
                IncidentStatus.CONFINEMENT,
                "Bloquer les domaines au DNS",
                f"Résolveur (RPZ ou sinkhole) et proxy : {_sample(by_type[IndicatorType.DOMAIN])} ;"
                " lister les postes qui les ont résolus.",
            )
        )
    if by_type.get(IndicatorType.URL):
        out.append(
            (
                IncidentStatus.CONFINEMENT,
                "Bloquer les URL et retrouver les destinataires",
                f"Proxy et passerelle de messagerie : {_sample(by_type[IndicatorType.URL], 2)} ;"
                " identifier qui a reçu ou ouvert le lien, réinitialiser les identifiants saisis.",
            )
        )
    hashes = [
        v
        for t in (IndicatorType.HASH_SHA256, IndicatorType.HASH_SHA1, IndicatorType.HASH_MD5)
        for v in by_type.get(t, [])
    ]
    if hashes:
        out.append(
            (
                IncidentStatus.CONFINEMENT,
                "Bloquer les fichiers sur les postes",
                f"Liste de blocage EDR : {_sample(hashes, 2)} ; balayer le parc et isoler les "
                "postes où le fichier est présent.",
            )
        )
    if by_type.get(IndicatorType.EMAIL):
        out.append(
            (
                IncidentStatus.CONFINEMENT,
                "Bloquer les expéditeurs",
                f"Passerelle de messagerie : {_sample(by_type[IndicatorType.EMAIL])} ; purger les "
                "messages déjà distribués.",
            )
        )
    ransomware = any(RANSOMWARE_PATTERN.search(i.description or "") for i in iocs) or any(
        c.has_ransomware_campaign for c in cves
    )
    if ransomware:
        out.append(
            (
                IncidentStatus.CONFINEMENT,
                "Isoler les hôtes touchés (rançongiciel)",
                "Isoler du réseau sans éteindre (mémoire utile à l'analyse) ; vérifier que les "
                "sauvegardes hors ligne sont intactes et non joignables depuis le réseau.",
            )
        )
    for cve in cves:
        if cve.is_kev:
            due = (
                f" avant l'échéance CISA du {cve.kev_due_date:%d/%m/%Y}" if cve.kev_due_date else ""
            )
            out.append(
                (
                    IncidentStatus.ERADICATION,
                    f"Corriger {cve.id}",
                    f"Exploitée activement (catalogue KEV) : appliquer le correctif{due} ; "
                    "à défaut, la mesure d'atténuation de l'éditeur, puis vérifier l'absence "
                    "de compromission antérieure.",
                )
            )
        elif cve.has_public_exploit:
            out.append(
                (
                    IncidentStatus.ERADICATION,
                    f"Corriger {cve.id}",
                    "Exploit public disponible : correctif prioritaire et surveillance des "
                    "tentatives d'exploitation.",
                )
            )
    out.append(
        (
            IncidentStatus.ERADICATION,
            "Supprimer les accès de l'attaquant",
            "Persistance (tâches, services, comptes créés) retirée ; identifiants exposés "
            "réinitialisés, sessions et jetons révoqués.",
        )
    )
    out.append(
        (
            IncidentStatus.RECUPERATION,
            "Rétablir et surveiller",
            "Restaurer depuis une source saine, puis surveillance renforcée 72 h sur les "
            "hôtes et comptes concernés.",
        )
    )
    out.append(
        (
            IncidentStatus.RECUPERATION,
            "Préparer le retour d'expérience",
            "Résumé de clôture (cause, mesures, enseignements) ; IOC jugés faux positifs mis en "
            "liste d'exclusion ; règle de détection à créer ou ajuster (L3).",
        )
    )
    order = list(IncidentStatus)
    current = {
        IncidentStatus.NOUVEAU: IncidentStatus.ANALYSE,
        IncidentStatus.CLOTURE: IncidentStatus.RECUPERATION,
    }.get(phase, phase)
    result = [
        Recommendation(phase=p.value, title=t, detail=d, current=p == current) for p, t, d in out
    ]
    if phase == IncidentStatus.CLOTURE:
        return [r for r in result if r.phase == IncidentStatus.RECUPERATION]
    # Phase en cours d'abord, puis l'ordre NIST ; les étapes déjà passées en dernier.
    return sorted(
        result,
        key=lambda r: (
            not r.current,
            order.index(IncidentStatus(r.phase)) < order.index(current),
            order.index(IncidentStatus(r.phase)),
        ),
    )


async def incident_recommendations(
    session: AsyncSession, incident: Incident
) -> list[Recommendation]:
    iocs = (
        await session.execute(
            select(Indicator.type, Indicator.value, Indicator.description)
            .join(IncidentIndicator, IncidentIndicator.indicator_id == Indicator.id)
            .where(IncidentIndicator.incident_id == incident.id)
        )
    ).all()
    cves = (
        await session.execute(
            select(
                CVE.id,
                CVE.is_kev,
                CVE.kev_due_date,
                CVE.has_public_exploit,
                CVE.has_ransomware_campaign,
            )
            .join(IncidentCVE, IncidentCVE.cve_id == CVE.id)
            .where(IncidentCVE.incident_id == incident.id)
        )
    ).all()
    return recommend(
        status=incident.status,
        severity=incident.severity,
        tier=incident.tier,
        iocs=[IocFacts(str(t), v, d) for t, v, d in iocs],
        cves=[CveFacts(*row) for row in cves],
    )
