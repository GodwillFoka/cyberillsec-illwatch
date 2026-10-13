"""Routes du tableau de bord SOC — `/api/v1/dashboard` (MOD-05, RF-21, RF-22, RF-24).

Lecture pour tout utilisateur authentifié. Les exports sont diffusés en flux : un export de
100 000 IOC ne charge jamais tout en mémoire.
"""

from dataclasses import asdict
from datetime import UTC, date, datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from illwatch.app.api.deps import Audit, CurrentUser, DbSession
from illwatch.modules.dashboard.service import (
    COLUMNS,
    Dataset,
    compute_summary,
    csv_stream,
    export_rows,
    json_stream,
    recent_activity,
)
from illwatch.modules.dashboard.timeseries import Metric, Window, time_series
from illwatch.modules.soc.metrics import soc_metrics

router = APIRouter(prefix="/dashboard", tags=["tableau de bord SOC"])


class ActivityRead(BaseModel):
    kind: str
    at: datetime
    reference: str
    label: str
    level: str


class PointRead(BaseModel):
    at: datetime
    total: int
    by_level: dict[str, int]


class SeriesRead(BaseModel):
    metric: Metric
    window: Window
    bucket: Literal["hour", "day"]
    start: datetime
    end: datetime
    total: int
    points: list[PointRead]


@router.get(
    "/timeseries",
    response_model=SeriesRead,
    summary="Série temporelle : nouveaux IOC, alertes CVE ou incidents (ADR-016)",
    description=(
        "Comptage par heure (24 h) ou par jour (7 et 30 jours), en UTC, avec répartition par "
        "sévérité (IOC, incidents) ou priorité (alertes). Tranches vides à zéro ; la dernière "
        "tranche est en cours."
    ),
)
async def timeseries(
    session: DbSession, _: CurrentUser, metric: Metric, window: Window = Window.H24
) -> SeriesRead:
    series = await time_series(session, metric, window)
    return SeriesRead(
        metric=series.metric,
        window=series.window,
        bucket="hour" if series.bucket == "hour" else "day",
        start=series.start,
        end=series.end,
        total=series.total,
        points=[PointRead(at=p.at, total=p.total, by_level=p.by_level) for p in series.points],
    )


class IocSummary(BaseModel):
    total: int
    active: int
    new_24h: int
    multi_source: int
    active_by_type: dict[str, int]
    active_by_severity: dict[str, int]


class CveSummary(BaseModel):
    total: int
    by_priority: dict[str, int]
    critical_ratio: float
    kev: int
    public_exploit: int
    escalated_24h: int


class IncidentSummary(BaseModel):
    open: int
    open_by_severity: dict[str, int]
    by_status: dict[str, int]
    opened_24h: int
    mttr_hours_90d: float | None


class AlertSummary(BaseModel):
    unacknowledged: int
    last_24h: int
    undelivered: int


class FeedSummary(BaseModel):
    total: int
    active: int
    by_status: dict[str, int]
    degraded: list[str]
    last_success: datetime | None


class CollectorSummary(BaseModel):
    last_success_at: datetime | None
    items: int | None
    error: str | None


class CorrelationSummary(BaseModel):
    open: int
    open_by_priority: dict[str, int]


class SummaryRead(BaseModel):
    """Synthèse typée : l'interface web en génère ses types TypeScript (ADR-016)."""

    generated_at: datetime
    iocs: IocSummary
    cves: CveSummary
    incidents: IncidentSummary
    alerts: AlertSummary
    feeds: FeedSummary
    collectors: dict[str, CollectorSummary]
    correlations: CorrelationSummary


@router.get(
    "/summary",
    response_model=SummaryRead,
    summary="Indicateurs clés du SOC en temps réel (RF-21)",
)
async def summary(session: DbSession, _: CurrentUser) -> dict[str, Any]:
    return (await compute_summary(session)).as_dict()


@router.get(
    "/recent",
    response_model=list[ActivityRead],
    summary="Menaces et vulnérabilités des dernières heures (RF-22)",
)
async def recent(
    session: DbSession,
    _: CurrentUser,
    hours: Annotated[int, Query(ge=1, le=24 * 7)] = 24,
) -> list[ActivityRead]:
    return [ActivityRead(**asdict(item)) for item in await recent_activity(session, hours=hours)]


@router.get("/export", summary="Export JSON (RFC 8259) ou CSV (RFC 4180) (RF-24)")
async def export(
    session: DbSession,
    user: CurrentUser,
    audit: Audit,
    dataset: Dataset,
    fmt: Annotated[Literal["json", "csv"], Query(alias="format")] = "csv",
) -> StreamingResponse:
    """Export complet d'un jeu de données. Consigné au journal d'audit (`data.export`) : c'est
    le chemin naturel d'une exfiltration de la base CTI."""
    await audit.record(
        "data.export",
        actor=user,
        target_type="dataset",
        target_id=dataset.value,
        detail={"format": fmt},
    )
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    rows = export_rows(session, dataset)
    body = csv_stream(COLUMNS[dataset], rows) if fmt == "csv" else json_stream(rows)
    return StreamingResponse(
        body,
        media_type="text/csv; charset=utf-8" if fmt == "csv" else "application/json",
        headers={
            "Content-Disposition": f'attachment; filename="illwatch-{dataset.value}-{stamp}.{fmt}"'
        },
    )


# --- Pilotage SOC (M9, ADR-022) --------------------------------------------------------------


class SeverityStatsRead(BaseModel):
    severity: str
    ack_sla_hours: int
    resolution_sla_hours: int
    opened: int
    closed: int
    mtta_minutes: float | None
    mttr_hours: float | None
    ack_within_sla: float | None
    resolved_within_sla: float | None


class BreachRead(BaseModel):
    incident_id: UUID
    title: str
    severity: str
    tier: str
    kind: str
    age_hours: float
    target_hours: int


class WorkloadRead(BaseModel):
    label: str
    open_assigned: int
    closed_in_window: int


class DayCountRead(BaseModel):
    day: date
    opened: int
    closed: int


class SocMetricsRead(BaseModel):
    window_days: int
    generated_at: datetime
    opened: int
    closed: int
    open_now: int
    mtta_minutes: float | None = Field(description="Ouverture → prise en charge (moyenne).")
    mttr_hours: float | None = Field(description="Ouverture → clôture (moyenne).")
    median_ttr_hours: float | None
    by_severity: list[SeverityStatsRead]
    open_by_tier: dict[str, int]
    escalations: dict[str, int]
    workload: list[WorkloadRead]
    breaches: list[BreachRead]
    daily: list[DayCountRead]
    exclusions: int
    false_positive_events: int


@router.get(
    "/soc",
    response_model=SocMetricsRead,
    summary="Pilotage SOC : MTTA, MTTR, délais cibles, niveaux, charge (M9)",
)
async def soc(
    session: DbSession,
    user: CurrentUser,
    days: Annotated[int, Query(description="Fenêtre : 7 ou 30 jours.")] = 7,
) -> SocMetricsRead:
    try:
        metrics = await soc_metrics(session, viewer=user, days=days)
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from None
    return SocMetricsRead.model_validate(asdict(metrics))
