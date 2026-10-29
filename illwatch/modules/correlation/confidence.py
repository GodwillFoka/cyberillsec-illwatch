"""Score de confiance d'un IOC (0-100): M8, ADR-017.

La confiance répond à « peut-on agir sur cet indicateur ? », indépendamment de sa gravité
(qui dit « à quel point ce serait grave »). Trois composantes, chacune justifiable :

1. **Sources** (60 points) : corroboration pondérée par la fiabilité de chaque source
   (échelle de l'Amirauté). Probabilité qu'au moins une source dise vrai :
   1 − Π(1 − wᵢ), avec A = 0,90 … F = 0,10. Deux sources « C » valent plus qu'une seule.
2. **Fraîcheur** (30 points) : décroissance exponentielle depuis la dernière observation,
   avec une demi-vie propre au type : une IP change de main en quelques jours, une empreinte
   de fichier reste vraie des mois.
3. **Récurrence** (10 points) : observations répétées, en échelle logarithmique.

Un IOC soumis à la main sans source compte comme une source « C » : l'analyste l'a reporté
d'un bulletin, sans corroboration par la collecte.
"""

import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import IndicatorSource, ThreatFeed
from illwatch.shared.enums import IndicatorType, SourceReliability

W_SOURCES = 60.0
W_FRESHNESS = 30.0
W_RECURRENCE = 10.0

RELIABILITY_WEIGHT: dict[SourceReliability, float] = {
    SourceReliability.A: 0.90,
    SourceReliability.B: 0.75,
    SourceReliability.C: 0.50,
    SourceReliability.D: 0.30,
    SourceReliability.E: 0.15,
    SourceReliability.F: 0.10,
}

HALF_LIFE_DAYS: dict[IndicatorType, float] = {
    IndicatorType.IPV4: 7,
    IndicatorType.IPV6: 7,
    IndicatorType.NETWORK: 7,
    IndicatorType.URL: 14,
    IndicatorType.DOMAIN: 30,
    IndicatorType.EMAIL: 60,
    IndicatorType.HASH_MD5: 180,
    IndicatorType.HASH_SHA1: 180,
    IndicatorType.HASH_SHA256: 180,
}

HIGH = 70
MEDIUM = 40
MANUAL_RELIABILITY = SourceReliability.C


@dataclass(frozen=True, slots=True)
class ConfidenceBreakdown:
    sources: float
    freshness: float
    recurrence: float
    total: int
    level: str  # ELEVEE, MOYENNE, FAIBLE


def _level(total: int) -> str:
    return "ELEVEE" if total >= HIGH else "MOYENNE" if total >= MEDIUM else "FAIBLE"


def compute_confidence(
    *,
    reliabilities: Sequence[str],
    ioc_type: str,
    last_seen: datetime,
    hit_count: int,
    now: datetime | None = None,
) -> ConfidenceBreakdown:
    """Score de confiance détaillé. `reliabilities` : une cote par source distincte."""
    moment = now or datetime.now(UTC)
    seen = last_seen if last_seen.tzinfo else last_seen.replace(tzinfo=UTC)
    cotes = [SourceReliability(r) for r in reliabilities] or [MANUAL_RELIABILITY]

    doubt = 1.0
    for cote in cotes:
        doubt *= 1.0 - RELIABILITY_WEIGHT[cote]
    sources = W_SOURCES * (1.0 - doubt)

    age_days = max(0.0, (moment - seen).total_seconds() / 86_400)
    half_life = HALF_LIFE_DAYS.get(IndicatorType(ioc_type), 30)
    freshness = W_FRESHNESS * 0.5 ** (age_days / half_life)

    recurrence = min(W_RECURRENCE, 2.5 * math.log2(1 + max(0, hit_count - 1)))

    total = round(sources + freshness + recurrence)
    return ConfidenceBreakdown(
        sources=round(sources, 1),
        freshness=round(freshness, 1),
        recurrence=round(recurrence, 1),
        total=total,
        level=_level(total),
    )


async def source_reliabilities(session: AsyncSession, ids: Iterable[UUID]) -> dict[UUID, list[str]]:
    """Cote de chaque source ayant rapporté chaque IOC (une requête pour une page)."""
    wanted = list(ids)
    if not wanted:
        return {}
    rows = await session.execute(
        select(IndicatorSource.indicator_id, ThreatFeed.reliability)
        .join(ThreatFeed, ThreatFeed.id == IndicatorSource.feed_id)
        .where(IndicatorSource.indicator_id.in_(wanted))
    )
    out: dict[UUID, list[str]] = {}
    for indicator_id, reliability in rows.tuples():
        out.setdefault(indicator_id, []).append(reliability)
    return out
