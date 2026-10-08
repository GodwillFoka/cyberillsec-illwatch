"""Journal des collectes et santé des sources — ADR-016 (écran « Sources CTI »).

Chaque collecte d'un flux laisse une ligne `collection_runs` : durée, nouveaux IOC, IOC déjà
connus (mis à jour), rejets, erreur ou avertissement. Ces lignes alimentent :

- l'historique d'un flux (`GET /api/v1/feeds/{id}/runs`) ;
- la santé de toutes les sources (`GET /api/v1/feeds/health`) : dernière tentative, dernier
  succès, volumes de la dernière collecte, erreurs sur 7 jours.

L'état d'une source décrit sa collecte, jamais la dangerosité des IOC qu'elle fournit.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import CollectionRun, ThreatFeed

RUN_RETENTION_DAYS = 90
ERROR_WINDOW = timedelta(days=7)
MAX_RUNS_PAGE = 100


@dataclass(frozen=True, slots=True)
class FeedHealth:
    feed_id: UUID
    name: str
    feed_type: str
    status: str
    is_active: bool
    last_successful_run: datetime | None
    last_error: str | None
    last_attempt_at: datetime | None
    last_duration_ms: int | None
    last_inserted: int | None
    last_updated: int | None
    last_rejected: int | None
    errors_7d: int
    runs_7d: int


def _utc(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


async def list_runs(
    session: AsyncSession, feed_id: UUID, *, limit: int = 20
) -> Sequence[CollectionRun]:
    """Dernières collectes d'un flux, la plus récente d'abord."""
    stmt = (
        select(CollectionRun)
        .where(CollectionRun.feed_id == feed_id)
        .order_by(CollectionRun.started_at.desc())
        .limit(min(limit, MAX_RUNS_PAGE))
    )
    return (await session.execute(stmt)).scalars().all()


async def feeds_health(session: AsyncSession, *, now: datetime | None = None) -> list[FeedHealth]:
    """Santé de toutes les sources, triées par nom. Trois requêtes, quel que soit le volume."""
    since = (now or datetime.now(UTC)) - ERROR_WINDOW
    feeds = (await session.execute(select(ThreatFeed).order_by(ThreatFeed.name))).scalars().all()

    counts_stmt = (
        select(
            CollectionRun.feed_id,
            func.count().label("runs"),
            func.count().filter(CollectionRun.succeeded.is_(False)).label("errors"),
        )
        .where(CollectionRun.started_at >= since)
        .group_by(CollectionRun.feed_id)
    )
    counts = {row.feed_id: (row.runs, row.errors) for row in await session.execute(counts_stmt)}

    latest = (
        select(CollectionRun.feed_id, func.max(CollectionRun.started_at).label("last"))
        .group_by(CollectionRun.feed_id)
        .subquery()
    )
    last_stmt = select(CollectionRun).join(
        latest,
        (CollectionRun.feed_id == latest.c.feed_id) & (CollectionRun.started_at == latest.c.last),
    )
    last_runs = {run.feed_id: run for run in (await session.execute(last_stmt)).scalars()}

    result = []
    for feed in feeds:
        run = last_runs.get(feed.id)
        runs, errors = counts.get(feed.id, (0, 0))
        result.append(
            FeedHealth(
                feed_id=feed.id,
                name=feed.name,
                feed_type=feed.feed_type,
                status=feed.status,
                is_active=feed.is_active,
                last_successful_run=_utc(feed.last_successful_run),
                last_error=feed.last_error,
                last_attempt_at=_utc(run.started_at) if run else None,
                last_duration_ms=run.duration_ms if run else None,
                last_inserted=run.inserted if run else None,
                last_updated=run.updated if run else None,
                last_rejected=run.rejected if run else None,
                errors_7d=int(errors),
                runs_7d=int(runs),
            )
        )
    return result


async def purge_runs(
    session: AsyncSession, *, now: datetime | None = None, retention_days: int = RUN_RETENTION_DAYS
) -> int:
    """Supprime les collectes plus anciennes que la rétention. Renvoie le nombre supprimé."""
    limit = (now or datetime.now(UTC)) - timedelta(days=retention_days)
    result = await session.execute(delete(CollectionRun).where(CollectionRun.started_at < limit))
    return int(getattr(result, "rowcount", 0) or 0)
