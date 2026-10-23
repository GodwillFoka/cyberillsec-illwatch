"""Jeu de données de démonstration — préproduction locale, captures d'écran, présentations.

Toutes les valeurs sont **fictives** : adresses des plages réservées à la documentation
(RFC 5737 : 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 ; RFC 3849 : 2001:db8::/32),
domaines `example`/`.test`, CVE numérotées CVE-2099-9xxxx (année que MITRE n'attribuera pas
avant longtemps)
dont la description commence par « [démo] » (« [demo] » sur une instance non francophone :
les textes suivent `DEFAULT_LANGUAGE`, ADR-027 décision 12). Rien ne peut être confondu
avec du renseignement réel, et le chargement est refusé sur une base qui contient déjà des
IOC : il ne mélange jamais la démonstration à une collecte réelle.
"""

from __future__ import annotations

import random
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.config import Settings
from illwatch.app.models import (
    CVE,
    Asset,
    AttackActor,
    AttackTechnique,
    Campaign,
    CollectionRun,
    CVEAlert,
    CVEPriorityChange,
    EnrichmentDatasetInfo,
    Incident,
    Indicator,
    ThreatFeed,
    User,
)
from illwatch.modules.attack.campaigns import attach as attach_to_campaign
from illwatch.modules.attack.campaigns import create_campaign
from illwatch.modules.attack.demo import demo_attack_data
from illwatch.modules.attack.service import import_attack
from illwatch.modules.correlation.engine import run_correlation
from illwatch.modules.cve_tracker.scoring import compute_risk_breakdown
from illwatch.modules.enrichment.dbip import import_dataset
from illwatch.modules.foundation.seed import seed_reference_feeds
from illwatch.modules.incidents import service as incidents
from illwatch.modules.incidents.service import STATUS_LABELS_EN
from illwatch.modules.sales.demo_requests import create_request
from illwatch.modules.soc.exclusions import create_exclusion
from illwatch.modules.soc.response import hunt_from_incident
from illwatch.modules.threat_feeds.indicators import Observation, ingest_indicators
from illwatch.modules.threat_hunting.engine import run_hunt
from illwatch.shared.enums import (
    DemoInterest,
    EnrichmentDataset,
    FeedStatus,
    IncidentEventType,
    IncidentStatus,
    Severity,
    UserRole,
)
from illwatch.shared.server_text import tr

DEMO_TAG = "[démo]"
DEMO_TAG_EN = "[demo]"


def demo_tag() -> str:
    """Marque des données fictives, dans la langue de l'instance."""
    return tr(DEMO_TAG, DEMO_TAG_EN)


TOR_EXIT = "198.51.100.66"  # relais Tor fictif, servi par la liste Tor de démonstration


class DemoRefusedError(RuntimeError):
    """La base contient déjà des données réelles."""


# Erreur de collecte réaliste (longue, avec une adresse d'un seul tenant) : les captures
# vérifient qu'elle reste dans son panneau, comme celle qu'un vrai flux TAXII renvoie.
def _demo_feed_error() -> str:
    return (
        "ConnectTimeout: HTTPSConnectionPool(host='feeds.example.org', port=443): Max retries "
        "exceeded with url: /taxii2reports/collections/c1f43330-103b-11ee-9ee3-4b022e286589/"
        "objects/ (connect timeout=15.0) " + tr("(4 tentatives) ", "(4 attempts) ") + demo_tag()
    )


# Enrichissement fictif des plages de documentation, avec les numéros d'AS réservés à la
# documentation (RFC 5398) : jamais chargé si une vraie base DB-IP est déjà importée.
_DEMO_COUNTRY = [
    "192.0.2.0,192.0.2.255,FR",
    "198.51.100.0,198.51.100.255,NL",
    "203.0.113.0,203.0.113.255,DE",
    "2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,FR",
]


def _demo_asn() -> list[str]:
    host, carrier, cloud, tag = (
        tr("Hébergeur A", "Hosting A"),
        tr("Opérateur B", "Carrier B"),
        tr("Nuage C", "Cloud C"),
        demo_tag(),
    )
    return [
        f'192.0.2.0,192.0.2.255,64496,"{host} {tag}"',
        f'198.51.100.0,198.51.100.255,64497,"{carrier} {tag}"',
        f'203.0.113.0,203.0.113.255,64498,"{cloud} {tag}"',
        f'2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,64499,"{host} {tag}"',
    ]


# Inventaire fictif : produits présents dans les CVE de démonstration, une adresse du pare-feu
# présente dans les IOC (règle CORR-03).
_DEMO_ASSETS = [
    (("Pare-feu siège", "HQ firewall"), "FortiOS", "Fortinet", Severity.CRITICAL, ["203.0.113.19"]),
    (("Messagerie", "Email"), "Exchange Server", "Microsoft", Severity.HIGH, []),
    (("Wiki interne", "Internal wiki"), "Confluence", "Atlassian", Severity.MEDIUM, []),
    (("Intégration continue", "Continuous integration"), "Jenkins", "Jenkins", Severity.LOW, []),
    (
        (
            "Passerelle de messagerie sécurisée du siège — cluster de production principal "
            "(Francfort)",
            "Headquarters secure email gateway — main production cluster (Frankfurt)",
        ),
        "Proofpoint Email Protection",
        "Proofpoint",
        Severity.MEDIUM,
        [],
    ),
]


@dataclass(slots=True)
class DemoReport:
    feeds: int = 0
    indicators: int = 0
    cves: int = 0
    alerts: int = 0
    incidents: int = 0
    hunts: int = 0
    runs: int = 0
    correlations: int = 0
    notes: list[str] = field(default_factory=list)


# --- IOC ---------------------------------------------------------------------------------

# Valeurs longues et d'un seul tenant, comme en collecte réelle : les captures vérifient
# qu'aucun écran ne déborde (URL d'hameçonnage à rallonge, sous-domaine généré, etc.).
LONG_URL = (
    "https://secure-login.microsoftonline-verification.phish.example/common/oauth2/v2.0/"
    "authorize?client_id=4765445b-32c6-49b0-83e6-1d93765276ca&response_type=code&redirect_uri="
    "https%3A%2F%2Fsecure-login.microsoftonline-verification.phish.example%2Fcallback&scope="
    "openid%20profile%20offline_access&state=a8f5f167f44f4964e6c998dee827110c&nonce="
    "6f1ed002ab5595859014ebf0951522d9"
)
LONG_DOMAIN = (
    "verification-compte-securise-office365.authentification-renouvellement-session.phish.example"
)

_FAMILIES = [
    (("Cobalt Strike C2", "Cobalt Strike C2"), Severity.CRITICAL),
    (("LockBit 3.0 affiliate infrastructure",) * 2, Severity.CRITICAL),
    (("Qakbot distribution", "Qakbot distribution"), Severity.HIGH),
    (("AsyncRAT C2", "AsyncRAT C2"), Severity.HIGH),
    (("Phishing Microsoft 365", "Microsoft 365 phishing"), Severity.MEDIUM),
    (("Scanner SSH", "SSH scanner"), Severity.LOW),
    (("Emotet loader", "Emotet loader"), Severity.HIGH),
    (("Bruteforce RDP", "RDP brute force"), Severity.MEDIUM),
]


def _observations(rng: random.Random, count: int) -> list[Observation]:
    items: list[Observation] = []
    tag = demo_tag()
    for i in range(count):
        names, severity = _FAMILIES[i % len(_FAMILIES)]
        family = tr(*names)
        kind = i % 6
        if kind == 0:
            value = f"203.0.113.{1 + i % 250}"
        elif kind == 1:
            value = f"192.0.2.{1 + (i * 7) % 250}"
        elif kind == 2:
            value = f"{rng.choice(['cdn', 'update', 'login', 'sync', 'api'])}-{i}.malicious.example"
        elif kind == 3:
            value = f"https://portal-{i}.phish.example/auth/signin"
        elif kind == 4:
            value = "".join(rng.choice("0123456789abcdef") for _ in range(64))
        else:
            value = f"2001:db8::{i:x}"
        items.append(Observation(value, severity=severity, description=f"{family} {tag}"))
    # Cas reconnus par les règles de chasse.
    items += [
        Observation("203.0.113.50", severity=Severity.CRITICAL, description=f"LockBit 3.0 {tag}"),
        Observation("beacon.cdn-update.duckdns.org", severity=Severity.HIGH),
        Observation("xjq8wz0vkp3mlq7b.example", severity=Severity.MEDIUM),
        Observation(TOR_EXIT, severity=Severity.MEDIUM, description=f"Scanner {tag}"),
        Observation(
            LONG_URL,
            severity=Severity.HIGH,
            description=tr(
                "Page d'hameçonnage imitant la mire de connexion Microsoft 365, envoyée par "
                f"courriel aux services financiers {tag}",
                "Phishing page imitating the Microsoft 365 sign-in screen, emailed to the "
                f"finance department {tag}",
            ),
        ),
        Observation(
            LONG_DOMAIN,
            severity=Severity.HIGH,
            description=f"{tr('Hameçonnage', 'Phishing')} {tag}",
        ),
    ]
    return items


# --- CVE ---------------------------------------------------------------------------------

_PRODUCTS: list[tuple[str, tuple[str, str]]] = [
    (
        "Fortinet FortiOS SSL-VPN",
        (
            "débordement de tas permettant l'exécution de code à distance",
            "heap overflow allowing remote code execution",
        ),
    ),
    (
        "Microsoft Exchange Server",
        (
            "contournement d'authentification puis exécution de code",
            "authentication bypass followed by code execution",
        ),
    ),
    (
        "Atlassian Confluence",
        ("injection de modèle OGNL non authentifiée", "unauthenticated OGNL template injection"),
    ),
    (
        "Ivanti Connect Secure",
        ("injection de commande dans l'interface web", "command injection in the web interface"),
    ),
    (
        "Citrix NetScaler ADC",
        (
            "lecture de mémoire hors limites (fuite de session)",
            "out-of-bounds memory read (session leak)",
        ),
    ),
    (
        "Apache Struts",
        (
            "téléversement de fichier conduisant à l'exécution de code",
            "file upload leading to code execution",
        ),
    ),
    (
        "VMware vCenter",
        (
            "débordement de tampon dans le protocole DCERPC",
            "buffer overflow in the DCERPC protocol",
        ),
    ),
    (
        "Palo Alto PAN-OS",
        ("injection de commande dans GlobalProtect", "command injection in GlobalProtect"),
    ),
    (
        "Cisco IOS XE",
        (
            "élévation de privilèges via l'interface web",
            "privilege escalation through the web interface",
        ),
    ),
    (
        "OpenSSH",
        (
            "condition de concurrence dans le gestionnaire de signaux",
            "race condition in the signal handler",
        ),
    ),
    ("WordPress (extension)", ("injection SQL authentifiée", "authenticated SQL injection")),
    (
        "Jenkins",
        (
            "lecture de fichiers arbitraires via le CLI (avis : https://www.jenkins.io/security/"
            "advisory/2099-01-24/#SECURITY-3314-lecture-de-fichiers-arbitraires-via-le-cli)",
            "arbitrary file read through the CLI (advisory: https://www.jenkins.io/security/"
            "advisory/2099-01-24/#SECURITY-3314-arbitrary-file-read-vulnerability-through-the-cli)",
        ),
    ),
]


def _cves(rng: random.Random, now: datetime) -> list[tuple[CVE, list[CVEPriorityChange]]]:
    out: list[tuple[CVE, list[CVEPriorityChange]]] = []
    for i in range(48):
        product, flaws = _PRODUCTS[i % len(_PRODUCTS)]
        flaw = tr(*flaws)
        cvss = round(rng.choice([9.8, 9.8, 9.1, 8.8, 8.1, 7.5, 7.2, 6.5, 5.3, 4.3]), 1)
        epss = round(rng.betavariate(0.6, 3.0), 4)
        is_kev = i % 5 == 0
        exploit = is_kev or i % 3 == 0
        ransomware = is_kev and i % 2 == 0
        parts = compute_risk_breakdown(
            cvss=cvss,
            epss=epss,
            is_kev=is_kev,
            has_public_exploit=exploit,
            has_ransomware_campaign=ransomware,
        )
        published = now - timedelta(days=rng.randint(3, 120), hours=rng.randint(0, 23))
        modified = now - timedelta(hours=rng.randint(1, 24 * 6))
        cve = CVE(
            id=f"CVE-2099-9{i:04d}",
            description=tr(f"{DEMO_TAG} {product} : {flaw}.", f"{DEMO_TAG_EN} {product}: {flaw}."),
            cvss_score=cvss,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" if cvss >= 9 else None,
            epss_score=epss,
            epss_percentile=round(min(0.9999, 0.5 + epss / 2), 4),
            is_kev=is_kev,
            kev_date_added=(now - timedelta(days=rng.randint(1, 30))).date() if is_kev else None,
            kev_due_date=(now + timedelta(days=rng.randint(2, 21))).date() if is_kev else None,
            kev_required_action=(
                tr(
                    "Appliquer les correctifs de l'éditeur ou retirer le produit du service.",
                    "Apply mitigations per vendor instructions or discontinue use of the product.",
                )
                if is_kev
                else None
            ),
            has_public_exploit=exploit,
            has_ransomware_campaign=ransomware,
            composite_risk_score=parts.total,
            priority=parts.priority,
            published_date=published,
            last_modified_date=modified,
        )
        history = [
            CVEPriorityChange(
                cve_id=cve.id,
                old_priority=None,
                new_priority=parts.priority,
                old_score=None,
                new_score=parts.total,
                reason="nvd",
                changed_at=published + timedelta(hours=2),
            )
        ]
        out.append((cve, history))
    return out


async def _empty(session: AsyncSession) -> bool:
    """Aucune donnée de renseignement ni d'enquête : ni IOC, ni CVE, ni incident."""
    for model in (Indicator, CVE, Incident):
        if await session.scalar(select(func.count()).select_from(model)):
            return False
    return True


async def load_demo_data(
    session: AsyncSession,
    *,
    settings: Settings,
    now: datetime | None = None,
    seed: int = 2026,
) -> DemoReport:
    """Charge le jeu de démonstration. Refusé si la base contient déjà des IOC."""
    if not await _empty(session):
        raise DemoRefusedError(
            "La base contient déjà des IOC, des CVE ou des incidents : la démonstration ne se "
            "charge que sur une base vide "
            "(préproduction locale, captures). Rien n'a été écrit."
        )
    moment = now or datetime.now(UTC)
    tag = demo_tag()
    feed_error = _demo_feed_error()
    rng = random.Random(seed)  # noqa: S311 - données fictives, pas de sécurité en jeu
    report = DemoReport()

    # Sources de référence (réelles) et leur journal de collecte (fictif) sur 3 jours.
    await seed_reference_feeds(session)
    feeds = list((await session.scalars(select(ThreatFeed).order_by(ThreatFeed.name))).all())
    report.feeds = len(feeds)
    degraded = feeds[-1] if feeds else None
    for feed in feeds:
        if not feed.is_active:
            continue
        for h in range(0, 72, 6):
            started = moment - timedelta(hours=h, minutes=rng.randint(0, 50))
            failed = feed is degraded and h < 18
            session.add(
                CollectionRun(
                    feed_id=feed.id,
                    started_at=started,
                    duration_ms=rng.randint(300, 9000),
                    succeeded=not failed,
                    status=FeedStatus.DEGRADED if failed else FeedStatus.HEALTHY,
                    inserted=0 if failed else rng.randint(0, 400),
                    updated=0 if failed else rng.randint(0, 900),
                    rejected=0 if failed else rng.randint(0, 12),
                    error=feed_error if failed else None,
                )
            )
            report.runs += 1
        feed.status = FeedStatus.DEGRADED if feed is degraded else FeedStatus.HEALTHY
        feed.last_successful_run = moment - timedelta(hours=18 if feed is degraded else 1)
        feed.last_error = feed_error if feed is degraded else None

    # IOC répartis sur 30 jours, attribués à plusieurs sources.
    observations = _observations(rng, 640)
    sources: list[ThreatFeed | None] = []
    sources.extend(f for f in feeds if f.is_active)
    sources = sources[:4] or [None]
    for day in range(30, -1, -1):
        batch = observations[day::31]
        if not batch:
            continue
        source = sources[day % len(sources)]
        result = await ingest_indicators(
            session,
            batch,
            feed_id=source.id if source else None,
            now=moment - timedelta(days=day, hours=rng.randint(0, 20)),
        )
        report.indicators += result.inserted
    # Un même IOC rapporté par une seconde source (provenance multiple).
    if len(sources) > 1 and sources[1] is not None:
        await ingest_indicators(session, observations[:40], feed_id=sources[1].id, now=moment)

    # CVE, historique, alertes.
    pairs = _cves(rng, moment)
    for cve, history in pairs:
        session.add(cve)
        session.add_all(history)
    await session.flush()
    report.cves = len(pairs)
    urgent = [c for c, _ in pairs if c.priority in ("P0_CRITIQUE", "P1_ELEVE")]
    for i, cve in enumerate(urgent[:14]):
        created = moment - timedelta(hours=3 + i * 11)
        alert = CVEAlert(
            cve_id=cve.id,
            score=cve.composite_risk_score,
            previous_score=max(0.0, float(cve.composite_risk_score) - 12.5),
            priority=cve.priority,
            reason=("kev", "epss", "nvd")[i % 3],
            created_at=created,
            # Toutes « déjà envoyées » : un webhook réel configuré dans .env ne doit jamais
            # recevoir d'alerte de démonstration.
            delivered_at=created + timedelta(seconds=4),
            delivery_attempts=1,
            acknowledged_at=created + timedelta(hours=1) if i >= 8 else None,
        )
        session.add(alert)
        report.alerts += 1
    await session.flush()

    # Incidents à différents stades du cycle NIST.
    analyst = await session.scalar(
        select(User).where(User.role == UserRole.ANALYST, User.is_active.is_(True)).limit(1)
    )
    author = analyst.id if analyst else None
    iocs = list((await session.scalars(select(Indicator).limit(12))).all())
    plans: Sequence[tuple[str, Severity, list[IncidentStatus], int]] = [
        (
            tr(
                "Ransomware : chiffrement en cours sur SRV-FILES-02",
                "Ransomware: encryption in progress on SRV-FILES-02",
            ),
            Severity.CRITICAL,
            [IncidentStatus.ANALYSE, IncidentStatus.CONFINEMENT],
            0,
        ),
        (
            tr(
                "Balise Cobalt Strike depuis un poste comptable",
                "Cobalt Strike beacon from an accounting workstation",
            ),
            Severity.HIGH,
            [IncidentStatus.ANALYSE],
            1,
        ),
        (
            tr(
                "Campagne d'hameçonnage Microsoft 365 visant la direction financière, les "
                "achats et deux filiales (12 destinataires, pièces jointes HTML piégées)",
                "Microsoft 365 phishing campaign targeting finance, procurement and two "
                "subsidiaries (12 recipients, booby-trapped HTML attachments)",
            ),
            Severity.MEDIUM,
            [],
            2,
        ),
        (
            tr(
                "Exploitation FortiOS SSL-VPN tentée depuis l'extérieur",
                "FortiOS SSL-VPN exploitation attempted from outside",
            ),
            Severity.HIGH,
            [IncidentStatus.ANALYSE, IncidentStatus.CONFINEMENT, IncidentStatus.ERADICATION],
            3,
        ),
        (
            tr("Scan SSH massif sur la DMZ", "Mass SSH scan on the DMZ"),
            Severity.LOW,
            [
                IncidentStatus.ANALYSE,
                IncidentStatus.CONFINEMENT,
                IncidentStatus.ERADICATION,
                IncidentStatus.RECUPERATION,
                IncidentStatus.CLOTURE,
            ],
            6,
        ),
    ]

    # Liste Tor de démonstration : aucune requête sortante pendant les chasses.
    async def tor_list(_: str) -> bytes:
        return f"# demo\n{TOR_EXIT}\n".encode()

    for title, severity, path, days_ago in plans:
        incident = await incidents.create_incident(
            session,
            title=f"{title} {tag}",
            description=tr(
                "Incident de démonstration : données fictives, pour présenter le cycle de "
                "réponse NIST SP 800-61 dans l'interface.",
                "Demonstration incident: fictitious data, to present the NIST SP 800-61 "
                "response cycle in the interface.",
            ),
            severity=severity,
            author_id=author,
        )
        for ioc in iocs[report.incidents * 2 : report.incidents * 2 + 2]:
            await incidents.attach_indicator(
                session, incident.id, author_id=author, indicator_id=ioc.id
            )
        if urgent:
            await incidents.attach_cve(
                session, incident.id, urgent[report.incidents % len(urgent)].id, author_id=author
            )
        await incidents.add_note(
            session,
            incident.id,
            tr(
                "Premiers constats consignés ; périmètre en cours de qualification.",
                "Initial findings recorded; scope being qualified.",
            ),
            author_id=author,
        )
        for target in path:
            await incidents.transition(
                session,
                incident.id,
                target,
                author_id=author,
                note=tr(
                    f"Passage en {target.value.lower()}.",
                    f"Moved to {STATUS_LABELS_EN[target].lower()}.",
                ),
                closure_summary=(
                    tr(
                        "Faux positif partiel : scanners bloqués au pare-feu, aucune "
                        "compromission.",
                        "Partial false positive: scanners blocked at the firewall, no compromise.",
                    )
                    if target == IncidentStatus.CLOTURE
                    else None
                ),
            )
        # Niveaux SOC (M9) : escalade motivée des incidents graves encore ouverts.
        still_open = not path or path[-1] != IncidentStatus.CLOTURE
        if still_open and severity in (Severity.CRITICAL, Severity.HIGH) and path:
            await incidents.escalate(
                session,
                incident.id,
                reason=tr("Investigation approfondie nécessaire", "In-depth investigation needed")
                + f" {tag}",
                author_id=author,
            )
            if len(path) >= 3:
                await incidents.escalate(
                    session,
                    incident.id,
                    reason=tr(
                        "Règle de détection à écrire, réponse avancée",
                        "Detection rule to write, advanced response",
                    )
                    + f" {tag}",
                    author_id=author,
                )
        if report.incidents == 0:
            # Investigation L2 : chasse lancée depuis l'incident, faux positif écarté.
            await hunt_from_incident(
                session, incident.id, author_id=author, settings=settings, fetch=tor_list
            )
            report.hunts += 1
            await create_exclusion(
                session,
                value="www.example.org",
                reason=tr(
                    "Site institutionnel de l'organisation, faux positif récurrent",
                    "The organisation's corporate website, recurring false positive",
                )
                + f" {tag}",
                author_id=author,
                incident_id=incident.id,
            )
        if path and path[-1] != IncidentStatus.CLOTURE:
            await incidents.add_note(
                session,
                incident.id,
                tr(
                    "Hôte isolé du réseau et image mémoire prise.",
                    "Host isolated from the network and memory image taken.",
                ),
                author_id=author,
                kind=IncidentEventType.ACTION_TAKEN,
            )
        loaded = await session.get(Incident, incident.id)
        if loaded is not None:
            loaded.created_at = moment - timedelta(days=days_ago, hours=2)
        report.incidents += 1
    await session.flush()

    # Une session de chasse manuelle (liste Tor de démonstration, aucune requête sortante).
    await run_hunt(
        session,
        settings=settings,
        fetch=tor_list,
        observables=[
            "203.0.113.50",
            TOR_EXIT,
            "beacon.cdn-update.duckdns.org",
            "hxxp://kq3zx9vw7plm2nbt[.]example/gate.php",
            "www.example.org",
            LONG_URL,
        ],
        assets=["FortiOS", "Exchange", "Confluence"],
        author_id=author,
        clock=lambda: moment - timedelta(minutes=20),
    )
    report.hunts += 1

    if await session.scalar(select(func.count()).select_from(EnrichmentDatasetInfo)) == 0:
        origin = tr("démonstration", "demonstration") + f" (RFC 5737, RFC 5398) {tag}"
        for dataset, lines in (
            (EnrichmentDataset.COUNTRY, _DEMO_COUNTRY),
            (EnrichmentDataset.ASN, _demo_asn()),
        ):
            await import_dataset(session, dataset, lines, source=origin, now=moment)
        report.notes.append("enrichissement fictif des plages de documentation")

    if await session.scalar(select(func.count()).select_from(AttackTechnique)) == 0:
        await import_attack(session, demo_attack_data(), now=moment)
        report.notes.append("extrait ATT&CK de démonstration")
    demo_campaign = tr("Distribution QakBot", "QakBot distribution") + f" {tag}"
    if await session.get(AttackActor, "S0650") is not None and not await session.scalar(
        select(Campaign.id).where(Campaign.name == demo_campaign)
    ):
        campaign = await create_campaign(
            session,
            name=demo_campaign,
            description=tr(
                "Infrastructure de distribution et de commande du chargeur QakBot.",
                "Distribution and command infrastructure of the QakBot loader.",
            ),
            actor_id="S0650",
        )
        await attach_to_campaign(session, campaign.id, description_contains="Qakbot")

    for names, product, vendor, criticality, addresses in _DEMO_ASSETS:
        session.add(
            Asset(
                name=tr(*names),
                product=product,
                vendor=vendor,
                criticality=criticality,
                addresses=addresses,
                domains=[],
                notes=tr("Actif fictif", "Fictitious asset") + f" {tag}",
                is_active=True,
            )
        )
    await session.flush()

    # Demandes reçues par le site de présentation (fictives, domaines example.*).
    prospects = [
        ("Lena Vogel", "CERT Nord", "Head of CERT", "DE", DemoInterest.PILOT, "de", 2),
        ("Marc Dubois", "Groupe Exemple SA", "RSSI", "FR", DemoInterest.DEMO, "fr", 20),
        ("Ana Ruiz", "SOC Iberia (MSSP)", "SOC manager", "ES", DemoInterest.SUPPORT, "es", 50),
    ]
    for name, org, title, country, interest, lang, hours in prospects:
        await create_request(
            session,
            name=name,
            email=f"{name.split()[0].lower()}@example.org",
            organisation=org,
            job_title=title,
            country=country,
            interest=interest,
            message=tr(
                "Démonstration souhaitée pour notre équipe.",
                "We would like a demonstration for our team.",
            ),
            language=lang,
            now=moment - timedelta(hours=hours),
        )
    correlation = await run_correlation(
        session, now=moment, min_confidence=settings.correlation_min_confidence
    )
    report.correlations = correlation.created
    await session.flush()
    return report


def demo_users() -> list[tuple[str, UserRole]]:
    """Comptes de démonstration créés par `illwatch demo load --users` (même mot de passe)."""
    return [
        ("admin", UserRole.ADMIN),
        ("analyst", UserRole.ANALYST),
        ("viewer", UserRole.VIEWER),
    ]
