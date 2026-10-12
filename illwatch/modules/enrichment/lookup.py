"""Enrichissement d'une adresse IP : pays et système autonome, lus dans `ip_ranges`.

Aucune requête sortante : la base DB-IP est importée localement (`illwatch enrich update`).
Une adresse privée, réservée ou de documentation est signalée (`public=False`) : ce qu'en dit
la base n'a alors pas de valeur de renseignement.
"""

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import EnrichmentDatasetInfo, IpRange
from illwatch.modules.enrichment.ipkeys import ip_key, is_public
from illwatch.shared.enums import EnrichmentDataset


@dataclass(frozen=True)
class IpEnrichment:
    country: str | None
    asn: int | None
    as_org: str | None
    public: bool


async def _covering(session: AsyncSession, dataset: EnrichmentDataset, key: str) -> IpRange | None:
    candidate = await session.scalar(
        select(IpRange)
        .where(IpRange.dataset == dataset.value, IpRange.start_key <= key)
        .order_by(IpRange.start_key.desc())
        .limit(1)
    )
    return candidate if candidate is not None and candidate.end_key >= key else None


async def enrich_ip(session: AsyncSession, value: str) -> IpEnrichment:
    """Pays et AS d'une adresse ; champs vides si l'adresse n'est pas publique ou inconnue."""
    try:
        key = ip_key(value)
    except ValueError:
        return IpEnrichment(country=None, asn=None, as_org=None, public=False)
    public = is_public(value)
    country = await _covering(session, EnrichmentDataset.COUNTRY, key)
    asn = await _covering(session, EnrichmentDataset.ASN, key)
    return IpEnrichment(
        country=country.country if country else None,
        asn=asn.asn if asn else None,
        as_org=asn.as_org if asn else None,
        public=public,
    )


async def datasets(session: AsyncSession) -> list[EnrichmentDatasetInfo]:
    """Bases importées (vide tant que `illwatch enrich update` n'a pas tourné)."""
    return list(
        (
            await session.scalars(
                select(EnrichmentDatasetInfo).order_by(EnrichmentDatasetInfo.dataset)
            )
        ).all()
    )
