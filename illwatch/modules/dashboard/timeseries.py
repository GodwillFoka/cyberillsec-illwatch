"""Séries temporelles du tableau de bord — ADR-016 (Vue d'ensemble).

Comptage par tranche (heure ou jour, en UTC) des nouveaux IOC, des alertes CVE et des incidents
ouverts, avec la répartition par niveau (sévérité ou priorité). Les tranches vides valent zéro :
une courbe ne doit jamais relier deux points en sautant une heure sans activité.

Le regroupement est fait en base : `date_trunc` sous PostgreSQL, `strftime` sous SQLite (tests).
Les horodatages sont stockés en UTC dans les deux cas.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from illwatch.app.models import CVEAlert, Incident, Indicator


class Metric(StrEnum):
    IOCS = "iocs"
    ALERTS = "alerts"
    INCIDENTS = "incidents"


class Window(StrEnum):
    H24 = "24h"
    D7 = "7d"
    D30 = "30d"


# Fenêtre → (durée, taille de tranche). 24 h par heure ; 7 et 30 jours par jour.
_WINDOWS: dict[Window, tuple[timedelta, timedelta]] = {
    Window.H24: (timedelta(hours=24), timedelta(hours=1)),
    Window.D7: (timedelta(days=7), timedelta(days=1)),
    Window.D30: (timedelta(days=30), timedelta(days=1)),
}

_SOURCES = {
    Metric.IOCS: (Indicator.first_seen, Indicator.severity),
    Metric.ALERTS: (CVEAlert.created_at, CVEAlert.priority),
    Metric.INCIDENTS: (Incident.created_at, Incident.severity),
}


@dataclass(slots=True)
class Point:
    at: datetime
    total: int = 0
    by_level: dict[str, int] = field(default_factory=dict)


@dataclass(slots=True)
class Series:
    metric: Metric
    window: Window
    bucket: str  # "hour" | "day"
    start: datetime
    end: datetime
    points: list[Point]

    @property
    def total(self) -> int:
        return sum(p.total for p in self.points)


def _floor(moment: datetime, step: timedelta) -> datetime:
    moment = moment.astimezone(UTC)
    if step >= timedelta(days=1):
        return moment.replace(hour=0, minute=0, second=0, microsecond=0)
    return moment.replace(minute=0, second=0, microsecond=0)


def _bucket_expr(column: Any, dialect: str, hourly: bool) -> ColumnElement[Any]:
    if dialect == "postgresql":
        # `timezone('UTC', …)` : tronquer en UTC, quel que soit le fuseau de la session.
        return func.date_trunc("hour" if hourly else "day", func.timezone("UTC", column))
    return func.strftime("%Y-%m-%d %H:00:00" if hourly else "%Y-%m-%d 00:00:00", column)


def _as_utc(value: datetime | str) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


async def time_series(
    session: AsyncSession, metric: Metric, window: Window, *, now: datetime | None = None
) -> Series:
    """Série `metric` sur `window`, tranche courante incluse (partielle)."""
    span, step = _WINDOWS[window]
    hourly = step < timedelta(days=1)
    end = _floor(now or datetime.now(UTC), step) + step
    start = end - span
    timestamp, level = _SOURCES[metric]

    bucket = _bucket_expr(timestamp, session.get_bind().dialect.name, hourly).label("bucket")
    stmt = (
        select(bucket, level.label("level"), func.count().label("n"))
        .where(timestamp >= start, timestamp < end)
        .group_by(bucket, level)
    )

    points: dict[datetime, Point] = {}
    moment = start
    while moment < end:
        points[moment] = Point(at=moment)
        moment += step
    for row in await session.execute(stmt):
        point = points.get(_as_utc(row.bucket))
        if point is None:  # garde-fou : arrondi inattendu d'un moteur
            continue
        point.total += int(row.n)
        point.by_level[str(row.level)] = point.by_level.get(str(row.level), 0) + int(row.n)

    return Series(
        metric=metric,
        window=window,
        bucket="hour" if hourly else "day",
        start=start,
        end=end,
        points=list(points.values()),
    )
