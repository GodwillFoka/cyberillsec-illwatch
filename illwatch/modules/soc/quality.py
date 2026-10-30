"""Qualité des alertes en situation réelle : ADR-029.

La mesure sur jeu figé (M8) dit qu'une règle *sait* détecter. Celle-ci dit si elle *aide*
l'équipe : sur la fenêtre choisie, que sont devenus les signaux qu'elle a produits ?

Trois familles de signaux, chacune avec la même grille d'issues :

- **Alertes CVE**, par déclencheur (`kev`, `epss`, `nvd`) : *confirmée* si un incident a été
  ouvert depuis l'alerte (ou porte la CVE après l'alerte), *ignorée* si elle a été acquittée
  sans suite, *en attente* sinon.
- **Évènements corrélés**, par règle (CORR-01 à 03) : *confirmé* (incident ouvert),
  *faux positif* (qualifié par un analyste), *ignoré* (acquitté sans suite), *clos par le
  moteur* (ne correspondait plus), *en attente*.
- **Correspondances de chasse**, par règle (RULE-01 à 06), comptées par observable distinct
  (la chasse quotidienne retrouve chaque jour les mêmes) : *confirmée* si l'IOC a été associé
  à un incident, *faux positif* si la valeur est en liste d'exclusion, *non qualifiée* sinon.

Par **source**, le même raisonnement porte sur les IOC : combien ont déclenché une
corrélation ou une chasse, combien ont été confirmés dans un incident, combien ont été
exclus comme faux positifs.

Indicateurs dérivés : **précision** = confirmés / (confirmés + faux positifs), calculée
seulement quand au moins un signal a été qualifié ; **bruit** = (faux positifs + ignorés) /
signaux traités par un analyste. Le délai de traitement est l'écart entre l'apparition du
signal et le geste de l'analyste (acquittement, faux positif, ouverture d'incident).

Tout est calculé à la demande sur les tables existantes : aucune donnée nouvelle n'est
stockée, les chiffres restent vérifiables ligne à ligne.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from statistics import mean, median
from typing import Any
from uuid import UUID

from sqlalchemy import and_, distinct, func, select, union
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import (
    CorrelatedEvent,
    CVEAlert,
    Exclusion,
    HuntingMatch,
    HuntingSession,
    Incident,
    IncidentCVE,
    IncidentIndicator,
    Indicator,
    IndicatorSource,
    ThreatFeed,
)
from illwatch.modules.correlation.engine import FALSE_POSITIVE, RESOLVED_AT, RULE_LABEL
from illwatch.shared.enums import CorrelationRule
from illwatch.shared.server_text import tr

WINDOWS = (7, 30, 90)

FAMILY_CVE = "cve_alert"
FAMILY_CORRELATION = "correlation"
FAMILY_HUNT = "hunt"

_ALERT_REASON_LABEL = {
    "kev": ("Entrée au catalogue KEV", "Added to the KEV catalogue"),
    "epss": ("Hausse de la probabilité EPSS", "EPSS probability increase"),
    "nvd": ("Publication ou mise à jour NVD", "NVD publication or update"),
}


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _ratio(part: int, whole: int) -> float | None:
    return None if whole <= 0 else round(part / whole, 3)


@dataclass(slots=True)
class QualityRow:
    """Bilan d'une règle, d'un déclencheur ou d'une source sur la fenêtre."""

    family: str
    key: str
    label: str
    signals: int = 0
    confirmed: int = 0
    false_positive: int = 0
    ignored: int = 0
    auto_closed: int = 0
    pending: int = 0
    precision: float | None = None
    noise: float | None = None
    handling_hours_mean: float | None = None
    handling_hours_median: float | None = None
    _delays: list[float] = field(default_factory=list, repr=False)

    def finish(self) -> "QualityRow":
        handled = self.confirmed + self.false_positive + self.ignored
        self.precision = _ratio(self.confirmed, self.confirmed + self.false_positive)
        self.noise = _ratio(self.false_positive + self.ignored, handled)
        if self._delays:
            self.handling_hours_mean = round(mean(self._delays), 1)
            self.handling_hours_median = round(median(self._delays), 1)
        return self

    def public(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "key": self.key,
            "label": self.label,
            "signals": self.signals,
            "confirmed": self.confirmed,
            "false_positive": self.false_positive,
            "ignored": self.ignored,
            "auto_closed": self.auto_closed,
            "pending": self.pending,
            "precision": self.precision,
            "noise": self.noise,
            "handling_hours_mean": self.handling_hours_mean,
            "handling_hours_median": self.handling_hours_median,
        }


@dataclass(slots=True)
class SourceRow:
    """Bilan d'une source d'IOC : ce qu'ont donné ses indicateurs une fois confrontés au
    terrain."""

    feed_id: UUID
    name: str
    reliability: str | None
    triggered: int = 0  # IOC distincts à l'origine d'une corrélation ou d'une chasse
    confirmed: int = 0  # IOC distincts associés à un incident
    false_positive: int = 0  # IOC distincts mis en liste d'exclusion
    precision: float | None = None

    def public(self) -> dict[str, Any]:
        return {
            "feed_id": self.feed_id,
            "name": self.name,
            "reliability": self.reliability,
            "triggered": self.triggered,
            "confirmed": self.confirmed,
            "false_positive": self.false_positive,
            "precision": self.precision,
        }


@dataclass(slots=True)
class AlertQuality:
    window_days: int
    generated_at: datetime
    since: datetime
    rules: list[QualityRow] = field(default_factory=list)
    sources: list[SourceRow] = field(default_factory=list)
    total: QualityRow = field(default_factory=lambda: QualityRow("total", "total", "Total"))

    def public(self) -> dict[str, Any]:
        return {
            "window_days": self.window_days,
            "generated_at": self.generated_at,
            "since": self.since,
            "rules": [r.public() for r in self.rules],
            "sources": [s.public() for s in self.sources],
            "total": self.total.public(),
        }


def _hours(start: datetime | None, end: datetime | None) -> float | None:
    if start is None or end is None or end < start:
        return None
    return (end - start).total_seconds() / 3600


async def _cve_alert_rows(session: AsyncSession, start: datetime) -> list[QualityRow]:
    alerts = (await session.scalars(select(CVEAlert).where(CVEAlert.created_at >= start))).all()
    if not alerts:
        return []
    ids = [a.id for a in alerts]
    from_alert = dict(
        (
            await session.execute(
                select(Incident.source_alert_id, Incident.created_at).where(
                    Incident.source_alert_id.in_(ids)
                )
            )
        )
        .tuples()
        .all()
    )
    # Une CVE peut aussi être rattachée à la main à un incident ouvert après l'alerte.
    cve_ids = sorted({a.cve_id for a in alerts})
    attached: dict[str, list[datetime]] = defaultdict(list)
    for cve_id, added_at in (
        await session.execute(
            select(IncidentCVE.cve_id, IncidentCVE.added_at).where(IncidentCVE.cve_id.in_(cve_ids))
        )
    ).tuples():
        when = _utc(added_at)
        if when is not None:
            attached[cve_id].append(when)

    rows: dict[str, QualityRow] = {}
    for alert in alerts:
        reason = alert.reason.split("+")[0]  # « kev+floor_kev » : même déclencheur
        fr, en = _ALERT_REASON_LABEL.get(reason, (reason, reason))
        row = rows.setdefault(reason, QualityRow(FAMILY_CVE, reason, tr(fr, en)))
        row.signals += 1
        created = _utc(alert.created_at)
        incident_at = _utc(from_alert.get(alert.id))
        if incident_at is None and created is not None:
            later = [t for t in attached.get(alert.cve_id, []) if t >= created]
            incident_at = min(later) if later else None
        if incident_at is not None:
            row.confirmed += 1
            delay = _hours(created, incident_at)
        elif alert.acknowledged_at is not None:
            row.ignored += 1
            delay = _hours(created, _utc(alert.acknowledged_at))
        else:
            row.pending += 1
            delay = None
        if delay is not None:
            row._delays.append(delay)
    return [rows[k].finish() for k in sorted(rows)]


async def _correlation_rows(session: AsyncSession, start: datetime) -> list[QualityRow]:
    events = (
        await session.scalars(select(CorrelatedEvent).where(CorrelatedEvent.first_seen >= start))
    ).all()
    rows: dict[str, QualityRow] = {}
    for event in events:
        try:
            label = RULE_LABEL[CorrelationRule(event.rule_id)]
        except ValueError:
            label = event.rule_id
        row = rows.setdefault(event.rule_id, QualityRow(FAMILY_CORRELATION, event.rule_id, label))
        row.signals += 1
        detail = event.detail or {}
        first = _utc(event.first_seen)
        acked = _utc(event.acknowledged_at)
        if event.incident_id is not None:
            row.confirmed += 1
        elif detail.get(FALSE_POSITIVE):
            row.false_positive += 1
        elif acked is not None and event.acknowledged_by is None and detail.get(RESOLVED_AT):
            row.auto_closed += 1
            continue  # aucun geste d'analyste : pas de délai de traitement
        elif acked is not None:
            row.ignored += 1
        else:
            row.pending += 1
            continue
        delay = _hours(first, acked)
        if delay is not None:
            row._delays.append(delay)
    return [rows[k].finish() for k in sorted(rows)]


async def _hunt_rows(session: AsyncSession, start: datetime) -> list[QualityRow]:
    """Correspondances de chasse par règle, comptées par observable distinct."""
    from illwatch.modules.threat_hunting.rules import RULES

    base = (
        select(HuntingMatch.rule_id, HuntingMatch.observable, HuntingMatch.indicator_id)
        .join(HuntingSession, HuntingSession.id == HuntingMatch.session_id)
        .where(HuntingSession.started_at >= start)
        .distinct()
        .subquery()
    )
    totals = dict(
        (
            await session.execute(
                select(base.c.rule_id, func.count(distinct(base.c.observable))).group_by(
                    base.c.rule_id
                )
            )
        )
        .tuples()
        .all()
    )
    if not totals:
        return []
    confirmed = dict(
        (
            await session.execute(
                select(base.c.rule_id, func.count(distinct(base.c.observable)))
                .join(IncidentIndicator, IncidentIndicator.indicator_id == base.c.indicator_id)
                .group_by(base.c.rule_id)
            )
        )
        .tuples()
        .all()
    )
    excluded = dict(
        (
            await session.execute(
                select(base.c.rule_id, func.count(distinct(base.c.observable)))
                .join(Exclusion, Exclusion.value == base.c.observable)
                .group_by(base.c.rule_id)
            )
        )
        .tuples()
        .all()
    )
    rows: list[QualityRow] = []
    for rule_id in sorted(totals):
        rule = RULES.get(rule_id)
        row = QualityRow(FAMILY_HUNT, rule_id, rule.label() if rule else rule_id)
        row.signals = int(totals[rule_id])
        row.confirmed = int(confirmed.get(rule_id, 0))
        row.false_positive = min(int(excluded.get(rule_id, 0)), row.signals - row.confirmed)
        row.pending = row.signals - row.confirmed - row.false_positive
        rows.append(row.finish())
    return rows


async def _source_rows(session: AsyncSession, start: datetime) -> list[SourceRow]:
    """IOC de chaque source : déclencheurs, confirmés, faux positifs, sur la fenêtre.

    Agrégats SQL : la chasse quotidienne sur toute la base peut produire des milliers de
    correspondances, qu'on ne charge pas en mémoire."""
    hunted = (
        select(HuntingMatch.indicator_id.label("iid"))
        .join(HuntingSession, HuntingSession.id == HuntingMatch.session_id)
        .where(HuntingSession.started_at >= start, HuntingMatch.indicator_id.is_not(None))
    )
    correlated = select(CorrelatedEvent.indicator_id.label("iid")).where(
        CorrelatedEvent.first_seen >= start, CorrelatedEvent.indicator_id.is_not(None)
    )
    signals = union(hunted, correlated).subquery()

    async def _count(query: Any) -> dict[UUID, int]:
        return {feed: int(n) for feed, n in (await session.execute(query)).tuples().all()}

    triggered = await _count(
        select(IndicatorSource.feed_id, func.count(distinct(signals.c.iid)))
        .join(signals, signals.c.iid == IndicatorSource.indicator_id)
        .group_by(IndicatorSource.feed_id)
    )
    confirmed = await _count(
        select(IndicatorSource.feed_id, func.count(distinct(IncidentIndicator.indicator_id)))
        .join(IndicatorSource, IndicatorSource.indicator_id == IncidentIndicator.indicator_id)
        .where(IncidentIndicator.added_at >= start)
        .group_by(IndicatorSource.feed_id)
    )
    false_pos = await _count(
        select(IndicatorSource.feed_id, func.count(distinct(Indicator.id)))
        .join(
            Exclusion,
            and_(Exclusion.indicator_type == Indicator.type, Exclusion.value == Indicator.value),
        )
        .join(IndicatorSource, IndicatorSource.indicator_id == Indicator.id)
        .where(Exclusion.created_at >= start)
        .group_by(IndicatorSource.feed_id)
    )
    feed_ids = set(triggered) | set(confirmed) | set(false_pos)
    if not feed_ids:
        return []
    feeds = {
        f.id: f
        for f in (
            await session.scalars(select(ThreatFeed).where(ThreatFeed.id.in_(sorted(feed_ids))))
        ).all()
    }
    rows: list[SourceRow] = []
    for feed_id in feed_ids:
        feed = feeds.get(feed_id)
        ok, bad = confirmed.get(feed_id, 0), false_pos.get(feed_id, 0)
        rows.append(
            SourceRow(
                feed_id=feed_id,
                name=feed.name if feed else str(feed_id),
                reliability=feed.reliability if feed else None,
                triggered=triggered.get(feed_id, 0),
                confirmed=ok,
                false_positive=bad,
                precision=_ratio(ok, ok + bad),
            )
        )
    rows.sort(key=lambda r: (-(r.confirmed + r.false_positive), -r.triggered, r.name))
    return rows


async def alert_quality(
    session: AsyncSession, *, days: int = 30, now: datetime | None = None
) -> AlertQuality:
    if days not in WINDOWS:
        raise ValueError(f"Fenêtre de {', '.join(map(str, WINDOWS))} jours.")
    moment = now or datetime.now(UTC)
    start = moment - timedelta(days=days)
    out = AlertQuality(window_days=days, generated_at=moment, since=start)
    cve_rows = await _cve_alert_rows(session, start)
    corr_rows = await _correlation_rows(session, start)
    hunt_rows = await _hunt_rows(session, start)
    out.rules = cve_rows + corr_rows + hunt_rows
    out.sources = await _source_rows(session, start)
    total = QualityRow("total", "total", tr("Total", "Total"))
    for row in out.rules:
        total.signals += row.signals
        total.confirmed += row.confirmed
        total.false_positive += row.false_positive
        total.ignored += row.ignored
        total.auto_closed += row.auto_closed
        total.pending += row.pending
        total._delays.extend(row._delays)
    out.total = total.finish()
    return out
