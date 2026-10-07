"""Routes du tableau de bord SOC — `/api/v1/dashboard` (MOD-05, RF-21, RF-22, RF-24).

Lecture pour tout utilisateur authentifié. Les exports sont diffusés en flux : un export de
100 000 IOC ne charge jamais tout en mémoire.
"""

from dataclasses import asdict
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

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

router = APIRouter(prefix="/dashboard", tags=["tableau de bord SOC"])


class ActivityRead(BaseModel):
    kind: str
    at: datetime
    reference: str
    label: str
    level: str


@router.get("/summary", summary="Indicateurs clés du SOC en temps réel (RF-21)")
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
