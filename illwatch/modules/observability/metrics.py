"""Métriques au format texte Prometheus (exposition 0.0.4) — M11, ADR-026.

Deux familles :

- **HTTP**, comptées en mémoire par le middleware à chaque requête : requêtes par méthode,
  route (le *modèle* de route, `/api/v1/incidents/{incident_id}`, jamais l'adresse réelle :
  cardinalité bornée) et statut ; histogramme des durées.
- **Métier**, calculées en base à chaque collecte par Prometheus : IOC actifs par type, état
  et dernier succès de chaque source, synchronisations CVE, incidents ouverts, évènements
  corrélés non acquittés, refus d'authentification sur 24 h, base et Redis joignables.

Sans dépendance : le format texte est simple et stable ; `prometheus_client` apporterait un
registre global, des processus multiples et des collecteurs dont ILLWATCH n'a pas besoin.
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import (
    AuditEvent,
    CollectionRun,
    CollectorState,
    CorrelatedEvent,
    Incident,
    Indicator,
    ThreatFeed,
)
from illwatch.modules.threat_feeds.indicators import is_active_clause
from illwatch.shared.enums import AuditOutcome, IncidentStatus

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
BUCKETS: tuple[float, ...] = (0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
# Flux longs (Server-Sent Events) : leur « durée » est celle de la connexion, pas un temps de
# réponse ; ils sont comptés mais restent hors de l'histogramme.
STREAMING_ROUTES = frozenset({"/api/v1/stream"})

Labels = tuple[tuple[str, str], ...]


def escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _labels(labels: Labels) -> str:
    if not labels:
        return ""
    return "{" + ",".join(f'{k}="{escape(v)}"' for k, v in labels) + "}"


def _number(value: float) -> str:
    if math.isinf(value):
        return "+Inf" if value > 0 else "-Inf"
    if float(value).is_integer():
        return str(int(value))
    return repr(float(value))


@dataclass
class _Histogram:
    counts: list[int] = field(default_factory=lambda: [0] * len(BUCKETS))
    total: float = 0.0
    count: int = 0

    def observe(self, value: float) -> None:
        self.total += value
        self.count += 1
        for index, bound in enumerate(BUCKETS):
            if value <= bound:
                self.counts[index] += 1


class HttpMetrics:
    """Compteurs HTTP du processus (une instance par processus API)."""

    def __init__(self) -> None:
        self.requests: dict[Labels, int] = defaultdict(int)
        self.durations: dict[Labels, _Histogram] = defaultdict(_Histogram)
        self.started = datetime.now(UTC)

    def observe(self, method: str, route: str, status: int, seconds: float) -> None:
        self.requests[(("method", method), ("route", route), ("status", str(status)))] += 1
        if route not in STREAMING_ROUTES:
            self.durations[(("method", method), ("route", route))].observe(seconds)

    def render(self) -> list[str]:
        lines = [
            "# HELP illwatch_http_requests_total Requêtes HTTP traitées.",
            "# TYPE illwatch_http_requests_total counter",
        ]
        lines += [
            f"illwatch_http_requests_total{_labels(k)} {v}"
            for k, v in sorted(self.requests.items())
        ]
        lines += [
            "# HELP illwatch_http_request_duration_seconds Durée de traitement des requêtes.",
            "# TYPE illwatch_http_request_duration_seconds histogram",
        ]
        for key, hist in sorted(self.durations.items()):
            for bound, count in zip(BUCKETS, hist.counts, strict=True):
                bucket = (*key, ("le", _number(bound)))
                lines.append(
                    f"illwatch_http_request_duration_seconds_bucket{_labels(bucket)} {count}"
                )
            inf = (*key, ("le", "+Inf"))
            lines.append(
                f"illwatch_http_request_duration_seconds_bucket{_labels(inf)} {hist.count}"
            )
            lines.append(
                f"illwatch_http_request_duration_seconds_sum{_labels(key)} {_number(hist.total)}"
            )
            lines.append(f"illwatch_http_request_duration_seconds_count{_labels(key)} {hist.count}")
        lines += [
            "# HELP illwatch_process_start_time_seconds Démarrage du processus API (epoch).",
            "# TYPE illwatch_process_start_time_seconds gauge",
            f"illwatch_process_start_time_seconds {_number(round(self.started.timestamp(), 3))}",
        ]
        return lines


HTTP = HttpMetrics()


@dataclass(frozen=True, slots=True)
class Gauge:
    name: str
    help: str
    samples: Sequence[tuple[Labels, float]]


def render_gauges(gauges: Iterable[Gauge]) -> list[str]:
    lines: list[str] = []
    for gauge in gauges:
        lines += [f"# HELP {gauge.name} {gauge.help}", f"# TYPE {gauge.name} gauge"]
        lines += [f"{gauge.name}{_labels(labels)} {_number(v)}" for labels, v in gauge.samples]
    return lines


def _epoch(value: datetime | None) -> float | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return round(value.timestamp(), 3)


async def business_gauges(
    session: AsyncSession, *, now: datetime | None = None, redis_up: bool | None = None
) -> list[Gauge]:
    """Jauges métier lues en base (quelques requêtes agrégées, indexées)."""
    moment = now or datetime.now(UTC)
    gauges: list[Gauge] = []
    try:
        await session.execute(text("SELECT 1"))
        database_up = True
    except Exception:  # noqa: BLE001 - base injoignable : seule cette jauge est exposée
        database_up = False
    gauges.append(Gauge("illwatch_database_up", "Base PostgreSQL joignable.", [((), database_up)]))
    if redis_up is not None:
        gauges.append(Gauge("illwatch_redis_up", "Redis joignable.", [((), redis_up)]))
    if not database_up:
        return gauges

    by_type = (
        await session.execute(
            select(Indicator.type, func.count())
            .where(is_active_clause(moment))
            .group_by(Indicator.type)
            .order_by(Indicator.type)
        )
    ).all()
    gauges.append(
        Gauge(
            "illwatch_indicators_active",
            "IOC actifs (non expirés, non exclus) par type.",
            [((("type", str(t)),), n) for t, n in by_type],
        )
    )

    feeds = (
        await session.execute(
            select(
                ThreatFeed.name,
                ThreatFeed.status,
                ThreatFeed.last_successful_run,
                ThreatFeed.polling_interval,
            )
            .where(ThreatFeed.is_active.is_(True))
            .order_by(ThreatFeed.name)
        )
    ).all()
    gauges.append(
        Gauge(
            "illwatch_feed_healthy",
            "Source active en bon état (1), dégradée ou jamais collectée (0).",
            [((("feed", n),), s == "HEALTHY") for n, s, _, _ in feeds],
        )
    )
    gauges.append(
        Gauge(
            "illwatch_feed_last_success_timestamp_seconds",
            "Dernière collecte réussie de chaque source active (epoch).",
            [((("feed", n),), e) for n, _, last, _ in feeds if (e := _epoch(last)) is not None],
        )
    )
    gauges.append(
        Gauge(
            "illwatch_feed_polling_interval_seconds",
            "Intervalle de collecte déclaré de chaque source active.",
            [((("feed", n),), p) for n, _, _, p in feeds],
        )
    )

    since = moment - timedelta(hours=24)
    runs: dict[bool, int] = {
        bool(ok): int(n)
        for ok, n in (
            await session.execute(
                select(CollectionRun.succeeded, func.count())
                .where(CollectionRun.started_at >= since)
                .group_by(CollectionRun.succeeded)
            )
        ).all()
    }
    gauges.append(
        Gauge(
            "illwatch_collection_runs_24h",
            "Collectes des dernières 24 h par résultat.",
            [
                ((("result", "ok"),), runs.get(True, 0)),
                ((("result", "failed"),), runs.get(False, 0)),
            ],
        )
    )
    new_iocs = await session.scalar(
        select(func.coalesce(func.sum(CollectionRun.inserted), 0)).where(
            CollectionRun.started_at >= since
        )
    )
    gauges.append(
        Gauge("illwatch_indicators_new_24h", "Nouveaux IOC sur 24 h.", [((), new_iocs or 0)])
    )

    collectors = (
        await session.execute(
            select(CollectorState.name, CollectorState.last_success_at).order_by(
                CollectorState.name
            )
        )
    ).all()
    gauges.append(
        Gauge(
            "illwatch_collector_last_success_timestamp_seconds",
            "Dernier succès des synchronisations (NVD, KEV, EPSS, entretien…), epoch.",
            [((("collector", n),), e) for n, last in collectors if (e := _epoch(last)) is not None],
        )
    )

    incidents = (
        await session.execute(
            select(Incident.severity, Incident.tier, func.count())
            .where(Incident.status != IncidentStatus.CLOTURE)
            .group_by(Incident.severity, Incident.tier)
            .order_by(Incident.severity, Incident.tier)
        )
    ).all()
    gauges.append(
        Gauge(
            "illwatch_incidents_open",
            "Incidents ouverts par sévérité et niveau SOC.",
            [((("severity", str(s)), ("tier", str(t))), n) for s, t, n in incidents],
        )
    )
    pending = (
        await session.execute(
            select(CorrelatedEvent.priority, func.count())
            .where(CorrelatedEvent.acknowledged_at.is_(None))
            .group_by(CorrelatedEvent.priority)
            .order_by(CorrelatedEvent.priority)
        )
    ).all()
    gauges.append(
        Gauge(
            "illwatch_correlated_events_unacknowledged",
            "Évènements corrélés non acquittés par priorité.",
            [((("priority", str(p)),), n) for p, n in pending],
        )
    )
    refused = (
        await session.execute(
            select(AuditEvent.action, func.count())
            .where(
                AuditEvent.occurred_at >= since,
                AuditEvent.outcome.in_([AuditOutcome.FAILURE, AuditOutcome.DENIED]),
            )
            .group_by(AuditEvent.action)
            .order_by(AuditEvent.action)
        )
    ).all()
    gauges.append(
        Gauge(
            "illwatch_audit_refusals_24h",
            "Échecs et refus consignés au journal d'audit sur 24 h, par action.",
            [((("action", a),), n) for a, n in refused],
        )
    )
    return gauges


def exposition(version: str, environment: str, gauges: Iterable[Gauge]) -> str:
    lines = [
        "# HELP illwatch_build_info Version et environnement de l'instance.",
        "# TYPE illwatch_build_info gauge",
        f'illwatch_build_info{{version="{escape(version)}",environment="{escape(environment)}"}} 1',
        *HTTP.render(),
        *render_gauges(gauges),
    ]
    return "\n".join(lines) + "\n"
