"""Transparence du renseignement : ADR-031.

Une donnée ancienne ou peu fiable ne doit jamais passer pour une menace actuelle et confirmée.
Ce module rend visibles, partout où un IOC ou une CVE s'affiche, trois faits qui étaient
calculés mais peu montrés :

- **la fraîcheur d'un IOC**, rapportée à la demi-vie de son type (celle qu'utilise déjà le
  score de confiance, ADR-017) : une adresse vue il y a 10 jours est « vieillissante », une
  empreinte vue il y a 10 jours est « récente » ;
- **ses sources**, par nom et par fiabilité, sans ouvrir la fiche ;
- **la fraîcheur des catalogues de vulnérabilités** (NVD, CISA KEV, FIRST EPSS) : une priorité
  calculée sur un EPSS de la semaine dernière n'a pas la même valeur qu'une priorité du jour.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import CollectorState, IndicatorSource, ThreatFeed
from illwatch.modules.correlation.confidence import HALF_LIFE_DAYS
from illwatch.shared.enums import IndicatorType

IocStatus = Literal["fresh", "aging", "stale", "expired"]
CatalogueStatus = Literal["fresh", "stale", "never"]

# Au-delà de trois demi-vies, la fraîcheur ne vaut plus qu'un huitième de sa valeur initiale.
STALE_HALF_LIVES = 3

# Âge maximal d'une synchronisation réussie avant d'avertir. NVD et KEV : le critère de M3
# (données de moins de 24 heures) ; EPSS : la règle déjà appliquée par `illwatch status`.
CATALOGUES: tuple[tuple[str, str, int], ...] = (
    ("nvd", "NIST NVD", 24),
    ("kev", "CISA KEV", 24),
    ("epss", "FIRST EPSS", 48),
)


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class IocFreshness:
    status: IocStatus
    age_days: float
    half_life_days: float


def ioc_freshness(
    *, ioc_type: str, last_seen: datetime, expires_at: datetime | None, now: datetime
) -> IocFreshness:
    """Fraîcheur d'un IOC : récente (moins d'une demi-vie), vieillissante (moins de trois),
    ancienne au-delà, expirée si sa date d'expiration est passée."""
    seen = _utc(last_seen) or now
    age = max(0.0, (now - seen).total_seconds() / 86_400)
    half_life = float(HALF_LIFE_DAYS.get(IndicatorType(ioc_type), 30))
    expiry = _utc(expires_at)
    status: IocStatus
    if expiry is not None and expiry <= now:
        status = "expired"
    elif age <= half_life:
        status = "fresh"
    elif age <= STALE_HALF_LIVES * half_life:
        status = "aging"
    else:
        status = "stale"
    return IocFreshness(status=status, age_days=round(age, 1), half_life_days=half_life)


@dataclass(frozen=True, slots=True)
class SourceBrief:
    name: str
    reliability: str


async def source_briefs(
    session: AsyncSession, ids: Iterable[UUID]
) -> dict[UUID, list[SourceBrief]]:
    """Sources de chaque IOC d'une page, les plus fiables d'abord (une requête par page)."""
    wanted = list(ids)
    if not wanted:
        return {}
    rows = await session.execute(
        select(IndicatorSource.indicator_id, ThreatFeed.name, ThreatFeed.reliability)
        .join(ThreatFeed, ThreatFeed.id == IndicatorSource.feed_id)
        .where(IndicatorSource.indicator_id.in_(wanted))
        .order_by(ThreatFeed.reliability, ThreatFeed.name)
    )
    out: dict[UUID, list[SourceBrief]] = {}
    for indicator_id, name, reliability in rows.tuples():
        out.setdefault(indicator_id, []).append(SourceBrief(name, str(reliability)))
    return out


@dataclass(frozen=True, slots=True)
class CatalogueFreshness:
    key: str
    name: str
    last_success_at: datetime | None
    age_hours: float | None
    max_age_hours: int
    status: CatalogueStatus
    last_error: str | None


async def catalogue_freshness(
    session: AsyncSession, now: datetime | None = None
) -> list[CatalogueFreshness]:
    """Dernière synchronisation réussie de chaque catalogue de vulnérabilités."""
    moment = now or datetime.now(UTC)
    out: list[CatalogueFreshness] = []
    for key, name, max_age in CATALOGUES:
        state = await session.get(CollectorState, key)
        at = None if state is None else _utc(state.last_success_at)
        status: CatalogueStatus
        if at is None:
            status, age = "never", None
        else:
            age = round((moment - at).total_seconds() / 3600, 1)
            status = "stale" if moment - at > timedelta(hours=max_age) else "fresh"
        out.append(
            CatalogueFreshness(
                key=key,
                name=name,
                last_success_at=at,
                age_hours=age,
                max_age_hours=max_age,
                status=status,
                last_error=None if state is None else state.last_error,
            )
        )
    return out
