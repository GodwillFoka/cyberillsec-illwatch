"""État d'avancement mesuré sur les données — `sentry status`.

Le code dit ce que SENTRY *sait faire* ; seule la base dit ce qu'il *a fait*. Ce module
calcule les indicateurs qui permettent de constater un jalon (M2 : ingestion
opérationnelle) au lieu de le supposer.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app.models import (
    CVE,
    CollectorState,
    CVEAlert,
    Indicator,
    IndicatorSource,
    ThreatFeed,
)
from sentry.modules.threat_feeds.indicators import is_active_clause
from sentry.shared.enums import FeedStatus, FeedType

M2_MIN_REAL_IOCS = 500
M2_MIN_HEALTHY_SOURCES = 3
M3_MIN_KEV = 1000  # le catalogue CISA KEV compte plus de 1 400 entrées (2026)
M3_MIN_EPSS_COVERAGE = 0.9
M3_NVD_MAX_AGE = timedelta(hours=24)


@dataclass(frozen=True, slots=True)
class Criterion:
    label: str
    met: bool
    detail: str


@dataclass(slots=True)
class ProjectStatus:
    feeds_total: int = 0
    feeds_active: int = 0
    feeds_by_status: dict[str, int] = field(default_factory=dict)
    iocs_total: int = 0
    iocs_active: int = 0
    iocs_from_feeds: int = 0
    iocs_multi_source: int = 0  # IOC confirmés par au moins deux flux distincts
    iocs_by_type: dict[str, int] = field(default_factory=dict)
    m2: list[Criterion] = field(default_factory=list)
    cves_total: int = 0
    cves_by_priority: dict[str, int] = field(default_factory=dict)
    cves_kev: int = 0
    cves_with_epss: int = 0
    alerts_total: int = 0
    alerts_open: int = 0
    m3: list[Criterion] = field(default_factory=list)

    @property
    def m2_reached(self) -> bool:
        return bool(self.m2) and all(c.met for c in self.m2)

    @property
    def m3_reached(self) -> bool:
        return bool(self.m3) and all(c.met for c in self.m3)


async def compute_status(session: AsyncSession, now: datetime | None = None) -> ProjectStatus:
    moment = now or datetime.now(UTC)
    status = ProjectStatus()

    feeds = (await session.execute(select(ThreatFeed))).scalars().all()
    status.feeds_total = len(feeds)
    status.feeds_active = sum(1 for f in feeds if f.is_active)
    for feed in feeds:
        status.feeds_by_status[feed.status] = status.feeds_by_status.get(feed.status, 0) + 1

    status.iocs_total = await session.scalar(select(func.count()).select_from(Indicator)) or 0
    status.iocs_active = (
        await session.scalar(
            select(func.count()).select_from(Indicator).where(is_active_clause(moment))
        )
        or 0
    )
    status.iocs_from_feeds = (
        await session.scalar(
            select(func.count()).select_from(Indicator).where(Indicator.feed_id.is_not(None))
        )
        or 0
    )
    confirmed = (
        select(IndicatorSource.indicator_id)
        .group_by(IndicatorSource.indicator_id)
        .having(func.count() >= 2)
        .subquery()
    )
    status.iocs_multi_source = (
        await session.scalar(select(func.count()).select_from(confirmed)) or 0
    )
    rows = await session.execute(
        select(Indicator.type, func.count()).group_by(Indicator.type).order_by(Indicator.type)
    )
    status.iocs_by_type = {str(t): int(n) for t, n in rows.all()}

    healthy = [f for f in feeds if f.status == FeedStatus.HEALTHY]
    otx = [f for f in healthy if f.feed_type == FeedType.OTX]
    stix = [f for f in healthy if f.feed_type in (FeedType.STIX, FeedType.TAXII)]
    status.m2 = [
        Criterion(
            f"≥ {M2_MIN_REAL_IOCS} IOC réels collectés",
            status.iocs_from_feeds >= M2_MIN_REAL_IOCS,
            f"{status.iocs_from_feeds} IOC issus de flux",
        ),
        Criterion(
            f"≥ {M2_MIN_HEALTHY_SOURCES} sources collectées avec succès",
            len(healthy) >= M2_MIN_HEALTHY_SOURCES,
            f"{len(healthy)} source(s) HEALTHY",
        ),
        Criterion("Collecteur AlienVault OTX connecté", bool(otx), f"{len(otx)} source OTX saine"),
        Criterion("Flux STIX connecté", bool(stix), f"{len(stix)} source STIX/TAXII saine"),
    ]
    await _compute_m3(session, status, moment)
    return status


async def _compute_m3(session: AsyncSession, status: ProjectStatus, moment: datetime) -> None:
    status.cves_total = await session.scalar(select(func.count()).select_from(CVE)) or 0
    rows = await session.execute(select(CVE.priority, func.count()).group_by(CVE.priority))
    status.cves_by_priority = {str(p): int(n) for p, n in rows.all()}
    status.cves_kev = (
        await session.scalar(select(func.count()).select_from(CVE).where(CVE.is_kev.is_(True))) or 0
    )
    status.cves_with_epss = (
        await session.scalar(
            select(func.count()).select_from(CVE).where(CVE.epss_score.is_not(None))
        )
        or 0
    )
    status.alerts_total = await session.scalar(select(func.count()).select_from(CVEAlert)) or 0
    status.alerts_open = (
        await session.scalar(
            select(func.count()).select_from(CVEAlert).where(CVEAlert.acknowledged_at.is_(None))
        )
        or 0
    )
    nvd = await session.get(CollectorState, "nvd")
    nvd_at = None if nvd is None else nvd.last_success_at
    if nvd_at is not None and nvd_at.tzinfo is None:
        nvd_at = nvd_at.replace(tzinfo=UTC)
    baseline = await session.get(CollectorState, "cve_baseline")
    coverage = status.cves_with_epss / status.cves_total if status.cves_total else 0.0
    status.m3 = [
        Criterion(
            "NVD synchronisé depuis moins de 24 h",
            nvd_at is not None and moment - nvd_at <= M3_NVD_MAX_AGE,
            f"dernier succès : {nvd_at:%Y-%m-%d %H:%M}" if nvd_at else "jamais",
        ),
        Criterion(
            f"Catalogue KEV importé (≥ {M3_MIN_KEV})",
            status.cves_kev >= M3_MIN_KEV,
            f"{status.cves_kev} CVE KEV",
        ),
        Criterion(
            f"EPSS intégré (≥ {M3_MIN_EPSS_COVERAGE:.0%} des CVE)",
            status.cves_total > 0 and coverage >= M3_MIN_EPSS_COVERAGE,
            f"{coverage:.0%} de {status.cves_total} CVE",
        ),
        Criterion(
            "Alerting actif (ligne de base établie)",
            baseline is not None and baseline.last_success_at is not None,
            f"{status.alerts_total} alerte(s), {status.alerts_open} non acquittée(s)",
        ),
    ]
