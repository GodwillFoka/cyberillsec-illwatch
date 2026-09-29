"""Routes du moteur CVE — `/api/v1/cves` et `/api/v1/alerts` (RF-14, RF-15, tâche 2.4).

| Opération                          | ADMIN | ANALYST | VIEWER |
|------------------------------------|:-----:|:-------:|:------:|
| Lister / consulter les CVE         |   ✅  |   ✅    |   ✅   |
| Lister les alertes                 |   ✅  |   ✅    |   ✅   |
| Acquitter une alerte               |   ✅  |   ✅    |   ❌   |

Les CVE ne sont pas modifiables par l'API : elles reflètent NVD, KEV et EPSS. Le détail
d'une CVE expose la **décomposition du score** (ADR-001) : chaque point est justifiable.
"""

from datetime import date, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from pydantic import BaseModel, ConfigDict, Field

from sentry.app.api.deps import CurrentUser, DbSession, require_roles
from sentry.app.models import CVE, User
from sentry.modules.cve_tracker import queries
from sentry.modules.cve_tracker.alerts import AlertNotFoundError, acknowledge
from sentry.modules.cve_tracker.queries import CVENotFoundError
from sentry.modules.cve_tracker.scoring import compute_risk_breakdown, remediation_sla_hours
from sentry.shared.enums import RiskPriority, UserRole

router = APIRouter(prefix="/cves", tags=["vulnérabilités (CVE)"])
alerts_router = APIRouter(prefix="/alerts", tags=["alertes"])

Responder = Annotated[User, Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST))]

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200
CVE_ID_PATTERN = r"^(?i:CVE)-\d{4}-\d{4,}$"


class CVERead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    description: str
    cvss_score: float | None
    cvss_vector: str | None
    epss_score: float | None
    epss_percentile: float | None
    is_kev: bool
    kev_date_added: date | None
    kev_due_date: date | None
    has_public_exploit: bool
    has_ransomware_campaign: bool
    composite_risk_score: float
    priority: RiskPriority
    sla_hours: int = Field(description="Délai de remédiation de la priorité (grille SOC).")
    published_date: datetime
    last_modified_date: datetime


class ScoreBreakdown(BaseModel):
    cvss: float
    epss: float
    kev: float
    exploit: float
    ransomware: float
    total: float


class PriorityChangeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    old_priority: RiskPriority | None
    new_priority: RiskPriority
    old_score: float | None
    new_score: float
    reason: str
    changed_at: datetime


class CVEDetail(CVERead):
    kev_required_action: str | None
    breakdown: ScoreBreakdown
    history: list[PriorityChangeRead]


class CVEPage(BaseModel):
    items: list[CVERead]
    total: int
    limit: int
    offset: int


class AlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    cve_id: str
    score: float
    previous_score: float | None
    priority: RiskPriority
    reason: str
    created_at: datetime
    delivered_at: datetime | None
    delivery_attempts: int
    acknowledged_at: datetime | None
    acknowledged_by: UUID | None


class AlertPage(BaseModel):
    items: list[AlertRead]
    total: int
    limit: int
    offset: int


def _read(cve: CVE) -> CVERead:
    data = CVERead.model_validate(
        {
            **{f: getattr(cve, f) for f in CVERead.model_fields if f != "sla_hours"},
            "sla_hours": remediation_sla_hours(RiskPriority(cve.priority)),
        }
    )
    return data


@router.get("", response_model=CVEPage, summary="Lister les CVE, les plus risquées d'abord")
async def list_cves(
    session: DbSession,
    _: CurrentUser,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
    offset: Annotated[int, Query(ge=0)] = 0,
    priority: RiskPriority | None = None,
    min_score: Annotated[float | None, Query(ge=0, le=100)] = None,
    is_kev: bool | None = None,
    q: Annotated[str | None, Query(max_length=100, description="Identifiant ou texte")] = None,
    modified_since: datetime | None = None,
) -> CVEPage:
    page = await queries.list_cves(
        session,
        limit=limit,
        offset=offset,
        priority=priority,
        min_score=min_score,
        is_kev=is_kev,
        search=q,
        modified_since=modified_since,
    )
    return CVEPage(
        items=[_read(c) for c in page.items], total=page.total, limit=limit, offset=offset
    )


@router.get(
    "/{cve_id}", response_model=CVEDetail, summary="Consulter une CVE et la décomposition du score"
)
async def read_cve(
    cve_id: Annotated[str, Path(pattern=CVE_ID_PATTERN)], session: DbSession, _: CurrentUser
) -> CVEDetail:
    try:
        cve = await queries.get_cve(session, cve_id)
    except CVENotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"{cve_id} introuvable.") from None
    parts = compute_risk_breakdown(
        cvss=None if cve.cvss_score is None else float(cve.cvss_score),
        epss=None if cve.epss_score is None else float(cve.epss_score),
        is_kev=cve.is_kev,
        has_public_exploit=cve.has_public_exploit,
        has_ransomware_campaign=cve.has_ransomware_campaign,
    )
    history = await queries.priority_history(session, cve.id)
    return CVEDetail(
        **_read(cve).model_dump(),
        kev_required_action=cve.kev_required_action,
        breakdown=ScoreBreakdown(
            cvss=parts.cvss_contribution,
            epss=parts.epss_contribution,
            kev=parts.kev_contribution,
            exploit=parts.exploit_contribution,
            ransomware=parts.attack_contribution,
            total=parts.total,
        ),
        history=[PriorityChangeRead.model_validate(h) for h in history],
    )


@alerts_router.get("", response_model=AlertPage, summary="Lister les alertes CVE")
async def list_alerts(
    session: DbSession,
    _: CurrentUser,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
    offset: Annotated[int, Query(ge=0)] = 0,
    acknowledged: bool | None = None,
    cve_id: Annotated[str | None, Query(max_length=30)] = None,
) -> AlertPage:
    page = await queries.list_alerts(
        session, limit=limit, offset=offset, acknowledged=acknowledged, cve_id=cve_id
    )
    return AlertPage(
        items=[AlertRead.model_validate(a) for a in page.items],
        total=page.total,
        limit=limit,
        offset=offset,
    )


@alerts_router.post(
    "/{alert_id}/ack", response_model=AlertRead, summary="Acquitter une alerte (ADMIN, ANALYST)"
)
async def ack_alert(alert_id: UUID, session: DbSession, user: Responder) -> AlertRead:
    try:
        alert = await acknowledge(session, alert_id, user.id)
    except AlertNotFoundError:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, detail=f"Alerte {alert_id} introuvable."
        ) from None
    return AlertRead.model_validate(alert)
