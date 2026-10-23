"""Amorçage des données de référence — `illwatch seed` (RF-03).

Idempotent : relancer la commande ne crée aucun doublon. Seules des sources
publiques et gratuites sont semées. Les clés éventuelles (ABUSECH_AUTH_KEY pour
URLhaus, OTX_API_KEY pour AlienVault OTX) ne sont jamais en base : elles sont lues
dans l'environnement. Sans clé, la source concernée passe en DEGRADED avec un message
explicite au lieu de bloquer les autres.

Chaque source a été **vérifiée avant intégration** (accès, format réel, présence d'IOC) ;
le constat et sa date figurent en commentaire. Une source injoignable est semée
**inactive** : elle reste documentée et se réactive par `illwatch feeds enable`, après une
sonde réussie (`illwatch feeds probe`).
"""

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import ThreatFeed
from illwatch.shared.enums import FeedStatus, FeedType, SourceReliability
from illwatch.shared.server_text import tr


@dataclass(frozen=True, slots=True)
class FeedSeed:
    name: str
    url: str
    feed_type: FeedType
    polling_interval: int
    is_active: bool = True
    # Fiabilité (Amirauté, ADR-017) : B pour les projets reconnus et curés (abuse.ch, IPsum
    # qui exige 5 listes concordantes), C par défaut, D pour les contributions communautaires
    # non vérifiées (pulses OTX).
    reliability: SourceReliability = SourceReliability.C
    # Nom sur une instance non francophone (ADR-027, décision 12). Le nom identifie la source :
    # une source déjà semée sous l'un ou l'autre nom n'est jamais recréée.
    name_en: str = ""

    def label(self) -> str:
        return tr(self.name, self.name_en or self.name)


REFERENCE_FEEDS: tuple[FeedSeed, ...] = (
    FeedSeed(
        name="abuse.ch URLhaus — URL malveillantes récentes",
        name_en="abuse.ch URLhaus — recent malicious URLs",
        # Depuis 2025, abuse.ch exige une clé (Auth-Key) dans l'URL de téléchargement.
        url="https://urlhaus-api.abuse.ch/v2/files/exports/{ABUSECH_AUTH_KEY}/recent.csv",
        feed_type=FeedType.CSV,
        polling_interval=3600,
        reliability=SourceReliability.B,
    ),
    FeedSeed(
        name="abuse.ch Feodo Tracker — serveurs C2 botnet",
        name_en="abuse.ch Feodo Tracker — botnet C2 servers",
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        feed_type=FeedType.CSV,
        polling_interval=3600,
        reliability=SourceReliability.B,
    ),
    # --- Sources publiques sans clé : de quoi constater M2 dès l'installation ------------
    FeedSeed(
        name="C2IntelFeeds — IP de serveurs C2 (30 j)",
        name_en="C2IntelFeeds — C2 server IPs (30 d)",
        # Colonnes `#ip,ioc` : l'IOC est `ip`, `ioc` est un libellé (choix par le contenu).
        url="https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv",
        feed_type=FeedType.CSV,
        polling_interval=6 * 3600,
    ),
    FeedSeed(
        name="C2IntelFeeds — domaines de serveurs C2 (30 j)",
        name_en="C2IntelFeeds — C2 server domains (30 d)",
        url=(
            "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/"
            "domainC2s-30day-filter-abused.csv"
        ),
        feed_type=FeedType.CSV,
        polling_interval=6 * 3600,
    ),
    FeedSeed(
        name="IPsum — IP malveillantes (≥ 5 listes noires)",
        name_en="IPsum — malicious IPs (≥ 5 blocklists)",
        # Agrégat quotidien de 30+ listes publiques (licence Unlicense). Niveau 5 : IP vues
        # sur au moins 5 listes, faux positifs rares. Vérifié le 03/10/2026 : 4 372 IP.
        url="https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt",
        feed_type=FeedType.CSV,
        polling_interval=12 * 3600,
        reliability=SourceReliability.B,
    ),
    FeedSeed(
        name="RedEye — indicateurs de menace STIX 2.1 (TAXII)",
        name_en="RedEye — STIX 2.1 threat indicators (TAXII)",
        # Jeton gratuit (inscription par e-mail) : TAXII_AUTH=feeds.redeyesecurity.com=bearer:…
        # IP, URL, domaines, hashs en indicateurs STIX ; 100 requêtes / h par jeton.
        url=(
            "https://feeds.redeyesecurity.com/taxii2/feed/collections/"
            "redeye-threat-indicators/objects/"
        ),
        feed_type=FeedType.TAXII,
        polling_interval=6 * 3600,
    ),
    FeedSeed(
        name="DigitalSide — URL malveillantes (7 j)",
        name_en="DigitalSide — malicious URLs (7 d)",
        # Injoignable le 03/10/2026 (délai de connexion dépassé depuis deux réseaux) : semée
        # inactive. Réactiver après `illwatch feeds probe` réussie.
        url="https://osint.digitalside.it/Threat-Intel/lists/latesturls.txt",
        feed_type=FeedType.CSV,
        polling_interval=6 * 3600,
        is_active=False,
    ),
    FeedSeed(
        name="DigitalSide — IoC réseau STIX 2.1 (TAXII, 24 h)",
        name_en="DigitalSide — STIX 2.1 network IoCs (TAXII, 24 h)",
        # Accès invité public (guest/guest, TAXII_AUTH par défaut). Même hôte que ci-dessus :
        # injoignable le 03/10/2026, semée inactive.
        url=(
            "https://osint.digitalside.it/taxii2reports/collections/"
            "c1f43330-103b-11ee-9ee3-4b022e286589/objects/"
        ),
        feed_type=FeedType.TAXII,
        polling_interval=6 * 3600,
        is_active=False,
    ),
    FeedSeed(
        name="AlienVault OTX — pulses abonnés",
        name_en="AlienVault OTX — subscribed pulses",
        # Clé OTX_API_KEY envoyée en en-tête ; `modified_since` ajouté à chaque collecte.
        url="https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50",
        feed_type=FeedType.OTX,
        polling_interval=3600,
        reliability=SourceReliability.D,
    ),
)


# URL publiées par d'anciennes versions de `illwatch seed` et devenues invalides :
# remplacées au prochain `illwatch seed`, sans toucher aux URL modifiées à la main.
OBSOLETE_URLS: dict[str, str] = {
    "https://urlhaus.abuse.ch/downloads/csv_recent/": (
        "https://urlhaus-api.abuse.ch/v2/files/exports/{ABUSECH_AUTH_KEY}/recent.csv"
    ),
}


async def seed_reference_feeds(session: AsyncSession) -> list[str]:
    """Insère les flux de référence absents et corrige les URL de référence obsolètes.

    Retourne les noms des flux créés ou mis à jour.
    """
    result = await session.execute(select(ThreatFeed))
    existing = {feed.name: feed for feed in result.scalars().all()}

    created: list[str] = []
    for current in existing.values():
        replacement = OBSOLETE_URLS.get(current.url)
        if replacement is not None:
            current.url = replacement
            current.status = FeedStatus.PENDING
            current.last_error = None
            created.append(f"{current.name} (URL mise à jour)")

    for feed in REFERENCE_FEEDS:
        if feed.name in existing or (feed.name_en and feed.name_en in existing):
            continue
        session.add(
            ThreatFeed(
                name=feed.label(),
                url=feed.url,
                feed_type=feed.feed_type,
                polling_interval=feed.polling_interval,
                is_active=feed.is_active,
                reliability=feed.reliability,
            )
        )
        created.append(feed.label())

    await session.flush()
    return created
