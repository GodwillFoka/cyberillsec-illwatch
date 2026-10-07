"""Tableau de bord SOC — MOD-05, RF-21 à RF-24 (phase 5).

Trois produits, tous calculés en base à la demande (pas de cache : les chiffres d'un SOC
doivent être ceux de l'instant) :

- `compute_summary` (RF-21) : IOC actifs, ratio de sévérité des CVE, incidents ouverts par
  criticité, temps moyen de résolution, alertes en attente, santé des collecteurs.
- `recent_activity` (RF-22) : fil consolidé des dernières heures — nouveaux IOC, CVE passées
  en P0/P1, alertes, incidents ouverts.
- `export_rows` (RF-24) : jeux de données exportables en JSON (RFC 8259) ou CSV (RFC 4180),
  lus par paquets pour une mémoire bornée. Les cellules CSV qui commencent par `= + - @`
  sont neutralisées : une valeur venue d'un flux hostile ne doit pas devenir une formule
  exécutée par le tableur de l'analyste (injection CSV, CWE-1236).
"""

import csv
import io
import json
from collections.abc import AsyncIterator, Iterable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Executable

from illwatch.app.models import (
    CVE,
    CollectorState,
    CVEAlert,
    CVEPriorityChange,
    Incident,
    Indicator,
    IndicatorSource,
    ThreatFeed,
)
from illwatch.modules.threat_feeds.indicators import is_active_clause
from illwatch.shared.enums import FeedStatus, IncidentStatus, RiskPriority

RECENT_LIMIT = 200
EXPORT_CHUNK = 1000
# Lignes regroupées par envoi réseau : une écriture par ligne coûtait plus que la ligne elle-même.
STREAM_BATCH = 500
MTTR_WINDOW = timedelta(days=90)


class Dataset(StrEnum):
    IOCS = "iocs"
    CVES = "cves"
    INCIDENTS = "incidents"
    ALERTS = "alerts"


@dataclass(slots=True)
class DashboardSummary:
    generated_at: datetime
    iocs: dict[str, Any] = field(default_factory=dict)
    cves: dict[str, Any] = field(default_factory=dict)
    incidents: dict[str, Any] = field(default_factory=dict)
    alerts: dict[str, Any] = field(default_factory=dict)
    feeds: dict[str, Any] = field(default_factory=dict)
    collectors: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ActivityItem:
    kind: str  # ioc | cve | alert | incident
    at: datetime
    reference: str
    label: str
    level: str  # sévérité ou priorité


def _utc(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


# `Executable` plutôt que `Select[...]` : l'arité générique de `Select` change entre
# SQLAlchemy 2.0 (un paramètre) et 2.1 (paramètres variadiques) ; mypy --strict doit
# passer sur les deux (poste Kali en 2.0, CI en 2.1).
async def _grouped(session: AsyncSession, statement: Executable) -> dict[str, int]:
    return {str(key): int(count) for key, count in (await session.execute(statement)).all()}


async def _count(session: AsyncSession, statement: Executable) -> int:
    return int(await session.scalar(statement) or 0)


# --- RF-21 : synthèse -------------------------------------------------------------------


async def compute_summary(session: AsyncSession, now: datetime | None = None) -> DashboardSummary:
    moment = now or datetime.now(UTC)
    day_ago = moment - timedelta(hours=24)
    summary = DashboardSummary(generated_at=moment)
    active = is_active_clause(moment)

    multi = (
        select(IndicatorSource.indicator_id)
        .group_by(IndicatorSource.indicator_id)
        .having(func.count() >= 2)
        .subquery()
    )
    # Deux lectures de la table des IOC au lieu de cinq (07/10 : 2 à 4 s sur 480 000 IOC) :
    # les totaux en un passage (agrégats filtrés), puis les actifs par type et gravité.
    totals = (
        await session.execute(
            select(
                func.count(),
                func.count().filter(active),
                func.count().filter(Indicator.first_seen >= day_ago),
            ).select_from(Indicator)
        )
    ).one()
    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    grouped = await session.execute(
        select(Indicator.type, Indicator.severity, func.count())
        .where(active)
        .group_by(Indicator.type, Indicator.severity)
    )
    for ioc_type, severity, count in grouped.all():
        by_type[str(ioc_type)] = by_type.get(str(ioc_type), 0) + int(count)
        by_severity[str(severity)] = by_severity.get(str(severity), 0) + int(count)
    summary.iocs = {
        "total": int(totals[0]),
        "active": int(totals[1]),
        "new_24h": int(totals[2]),
        "multi_source": await _count(session, select(func.count()).select_from(multi)),
        "active_by_type": by_type,
        "active_by_severity": by_severity,
    }

    by_priority = await _grouped(session, select(CVE.priority, func.count()).group_by(CVE.priority))
    total_cves = sum(by_priority.values())
    summary.cves = {
        "total": total_cves,
        "by_priority": {p.value: by_priority.get(p.value, 0) for p in RiskPriority},
        "critical_ratio": round(
            (by_priority.get("P0_CRITIQUE", 0) + by_priority.get("P1_ELEVE", 0)) / total_cves, 4
        )
        if total_cves
        else 0.0,
        "kev": await _count(
            session, select(func.count()).select_from(CVE).where(CVE.is_kev.is_(True))
        ),
        "public_exploit": await _count(
            session,
            select(func.count()).select_from(CVE).where(CVE.has_public_exploit.is_(True)),
        ),
        "escalated_24h": await _count(
            session,
            select(func.count(func.distinct(CVEPriorityChange.cve_id))).where(
                CVEPriorityChange.changed_at >= day_ago,
                CVEPriorityChange.new_priority.in_(
                    [RiskPriority.P0_CRITIQUE, RiskPriority.P1_ELEVE]
                ),
                CVEPriorityChange.old_priority.is_not(None),
            ),
        ),
    }

    open_clause = Incident.status != IncidentStatus.CLOTURE
    closed = (
        await session.execute(
            select(Incident.created_at, Incident.closed_at).where(
                Incident.status == IncidentStatus.CLOTURE,
                Incident.closed_at >= moment - MTTR_WINDOW,
            )
        )
    ).all()
    durations = [
        (closed_at - created_at).total_seconds() / 3600
        for created_at, closed_at in ((_utc(c), _utc(d)) for c, d in closed)
        if created_at is not None and closed_at is not None
    ]
    summary.incidents = {
        "open": await _count(
            session, select(func.count()).select_from(Incident).where(open_clause)
        ),
        "open_by_severity": await _grouped(
            session,
            select(Incident.severity, func.count()).where(open_clause).group_by(Incident.severity),
        ),
        "by_status": await _grouped(
            session, select(Incident.status, func.count()).group_by(Incident.status)
        ),
        "opened_24h": await _count(
            session,
            select(func.count()).select_from(Incident).where(Incident.created_at >= day_ago),
        ),
        "mttr_hours_90d": round(sum(durations) / len(durations), 1) if durations else None,
    }

    summary.alerts = {
        "unacknowledged": await _count(
            session,
            select(func.count()).select_from(CVEAlert).where(CVEAlert.acknowledged_at.is_(None)),
        ),
        "last_24h": await _count(
            session,
            select(func.count()).select_from(CVEAlert).where(CVEAlert.created_at >= day_ago),
        ),
        "undelivered": await _count(
            session,
            select(func.count()).select_from(CVEAlert).where(CVEAlert.delivered_at.is_(None)),
        ),
    }

    feeds = (await session.execute(select(ThreatFeed))).scalars().all()
    last_runs = [r for r in (_utc(f.last_successful_run) for f in feeds) if r is not None]
    summary.feeds = {
        "total": len(feeds),
        "active": sum(1 for f in feeds if f.is_active),
        "by_status": {s.value: sum(1 for f in feeds if f.status == s) for s in FeedStatus},
        "degraded": sorted(f.name for f in feeds if f.status == FeedStatus.DEGRADED),
        "last_success": max(last_runs) if last_runs else None,
    }

    states = (await session.execute(select(CollectorState))).scalars().all()
    summary.collectors = {
        s.name: {
            "last_success_at": _utc(s.last_success_at),
            "items": s.items,
            "error": s.last_error,
        }
        for s in states
    }
    return summary


# --- RF-22 : activité récente ------------------------------------------------------------


async def recent_activity(
    session: AsyncSession, *, hours: int = 24, now: datetime | None = None
) -> list[ActivityItem]:
    """Fil consolidé des `hours` dernières heures, du plus récent au plus ancien."""
    moment = now or datetime.now(UTC)
    since = moment - timedelta(hours=hours)
    items: list[ActivityItem] = []

    iocs = await session.execute(
        select(Indicator)
        .where(Indicator.first_seen >= since)
        .order_by(Indicator.first_seen.desc())
        .limit(RECENT_LIMIT)
    )
    items += [
        ActivityItem(
            "ioc", _utc(i.first_seen) or moment, str(i.id), f"{i.type} {i.value}", i.severity
        )
        for i in iocs.scalars()
    ]
    escalations = await session.execute(
        select(CVEPriorityChange)
        .where(
            CVEPriorityChange.changed_at >= since,
            CVEPriorityChange.new_priority.in_([RiskPriority.P0_CRITIQUE, RiskPriority.P1_ELEVE]),
        )
        .order_by(CVEPriorityChange.changed_at.desc())
        .limit(RECENT_LIMIT)
    )
    items += [
        ActivityItem(
            "cve",
            _utc(c.changed_at) or moment,
            c.cve_id,
            f"{c.cve_id} : {c.old_priority or 'nouvelle'} → {c.new_priority} "
            f"(score {float(c.new_score):.1f}, {c.reason})",
            c.new_priority,
        )
        for c in escalations.scalars()
    ]
    alerts = await session.execute(
        select(CVEAlert).where(CVEAlert.created_at >= since).limit(RECENT_LIMIT)
    )
    items += [
        ActivityItem(
            "alert",
            _utc(a.created_at) or moment,
            str(a.id),
            f"Alerte {a.cve_id} — score {float(a.score):.1f}",
            a.priority,
        )
        for a in alerts.scalars()
    ]
    incidents = await session.execute(
        select(Incident).where(Incident.created_at >= since).limit(RECENT_LIMIT)
    )
    items += [
        ActivityItem("incident", _utc(i.created_at) or moment, str(i.id), i.title, i.severity)
        for i in incidents.scalars()
    ]
    items.sort(key=lambda item: item.at, reverse=True)
    return items[:RECENT_LIMIT]


# --- RF-24 : exports -------------------------------------------------------------------


COLUMNS: dict[Dataset, tuple[str, ...]] = {
    Dataset.IOCS: (
        "id",
        "type",
        "value",
        "severity",
        "hit_count",
        "first_seen",
        "last_seen",
        "expires_at",
        "description",
    ),
    Dataset.CVES: (
        "id",
        "composite_risk_score",
        "priority",
        "cvss_score",
        "epss_score",
        "is_kev",
        "has_public_exploit",
        "has_ransomware_campaign",
        "kev_due_date",
        "published_date",
        "last_modified_date",
        "description",
    ),
    Dataset.INCIDENTS: (
        "id",
        "title",
        "severity",
        "status",
        "assigned_to",
        "created_at",
        "closed_at",
        "source_alert_id",
    ),
    Dataset.ALERTS: (
        "id",
        "cve_id",
        "score",
        "previous_score",
        "priority",
        "reason",
        "created_at",
        "delivered_at",
        "acknowledged_at",
    ),
}

_MODELS: dict[Dataset, Any] = {
    Dataset.IOCS: Indicator,
    Dataset.CVES: CVE,
    Dataset.INCIDENTS: Incident,
    Dataset.ALERTS: CVEAlert,
}


def _plain(value: Any) -> Any:
    if isinstance(value, datetime):
        return (_utc(value) or value).isoformat()
    if hasattr(value, "isoformat"):  # date
        return value.isoformat()
    if value is None or isinstance(value, bool | int | float | str):
        return value
    return float(value) if hasattr(value, "as_integer_ratio") else str(value)


async def export_rows(
    session: AsyncSession, dataset: Dataset, *, now: datetime | None = None
) -> AsyncIterator[dict[str, Any]]:
    """Lignes du jeu de données, par paquets de 1 000 (mémoire bornée).

    `iocs` n'exporte que les IOC actifs (non expirés) : un export sert à alimenter un
    équipement de blocage, pas à archiver l'historique.

    Pagination par clé (`WHERE clé > dernière clé`), jamais par `OFFSET` : avec `OFFSET`, la
    page n relisait les n × 1 000 lignes précédentes (coût quadratique : 89 s pour 300 000
    IOC le 07/10). Seules les colonnes exportées sont lues, sans construire d'objets ORM.
    """
    dataset = Dataset(dataset)
    model = _MODELS[dataset]
    columns = COLUMNS[dataset]
    by_score = dataset is Dataset.CVES  # les CVE les plus risquées d'abord
    selected = [getattr(model, c) for c in columns]
    order = (model.composite_risk_score.desc(), model.id) if by_score else (model.id,)
    base = select(*selected).order_by(*order).limit(EXPORT_CHUNK)
    if dataset is Dataset.IOCS:
        base = base.where(is_active_clause(now or datetime.now(UTC)))

    last: Any = None
    while True:
        statement = base
        if last is not None:
            if by_score:
                score, key = last
                statement = statement.where(
                    or_(
                        model.composite_risk_score < score,
                        and_(model.composite_risk_score == score, model.id > key),
                    )
                )
            else:
                statement = statement.where(model.id > last)
        rows: Sequence[Any] = (await session.execute(statement)).all()
        for row in rows:
            values = row._mapping
            yield {column: _plain(values[column]) for column in columns}
        if len(rows) < EXPORT_CHUNK:
            return
        tail = rows[-1]._mapping
        last = (tail["composite_risk_score"], tail["id"]) if by_score else tail["id"]


_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: Any) -> Any:
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


class _CsvRow:
    """Sérialiseur CSV RFC 4180 (CRLF, guillemets si nécessaire), cellules neutralisées."""

    def __init__(self, columns: Iterable[str]) -> None:
        self.columns = list(columns)
        self._buffer = io.StringIO()
        self._writer = csv.writer(self._buffer, lineterminator="\r\n")

    def _line(self, cells: list[Any]) -> str:
        self._buffer.seek(0)
        self._buffer.truncate()
        self._writer.writerow(cells)
        return self._buffer.getvalue()

    def header(self) -> str:
        return self._line(self.columns)

    def row(self, row: dict[str, Any]) -> str:
        return self._line([_csv_safe(row.get(c)) for c in self.columns])


def csv_lines(columns: Iterable[str], rows: Iterable[dict[str, Any]]) -> Iterable[str]:
    """CSV complet (en-tête puis lignes) à partir de lignes déjà en mémoire."""
    writer = _CsvRow(columns)
    yield writer.header()
    for row in rows:
        yield writer.row(row)


async def csv_stream(
    columns: Iterable[str], rows: AsyncIterator[dict[str, Any]]
) -> AsyncIterator[str]:
    """CSV diffusé par paquets de `STREAM_BATCH` lignes depuis un itérateur asynchrone."""
    writer = _CsvRow(columns)
    batch = [writer.header()]
    async for row in rows:
        batch.append(writer.row(row))
        if len(batch) >= STREAM_BATCH:
            yield "".join(batch)
            batch = []
    if batch:
        yield "".join(batch)


async def json_stream(rows: AsyncIterator[dict[str, Any]]) -> AsyncIterator[str]:
    """Tableau JSON (RFC 8259) diffusé par paquets de `STREAM_BATCH` éléments."""
    batch = ["["]
    first = True
    async for row in rows:
        batch.append(("" if first else ",") + json.dumps(row, ensure_ascii=False))
        first = False
        if len(batch) >= STREAM_BATCH:
            yield "".join(batch)
            batch = []
    batch.append("]")
    yield "".join(batch)
