"""Lecture du moteur CVE pour l'API et la CLI — tâche 2.4 (RNF-PERF-01 : P95 < 250 ms).

Les filtres portent sur des colonnes indexées (`priority`, `composite_risk_score`,
`last_modified_date`) ; la recherche plein texte reste un `ILIKE` borné par la pagination.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import ColumnElement, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import CVE, CVEAlert, CVEPriorityChange
from illwatch.shared.enums import RiskPriority


class CVENotFoundError(LookupError):
    """Aucune CVE ne porte cet identifiant."""


@dataclass(frozen=True, slots=True)
class Page[T]:
    items: Sequence[T]
    total: int


def normalize_cve_id(raw: str) -> str:
    return raw.strip().upper()


async def list_cves(
    session: AsyncSession,
    *,
    limit: int,
    offset: int,
    priority: RiskPriority | None = None,
    min_score: float | None = None,
    is_kev: bool | None = None,
    search: str | None = None,
    modified_since: datetime | None = None,
) -> Page[CVE]:
    """CVE les plus risquées d'abord (score décroissant, puis plus récemment modifiées)."""
    conditions: list[ColumnElement[bool]] = []
    if priority is not None:
        conditions.append(CVE.priority == priority)
    if min_score is not None:
        conditions.append(CVE.composite_risk_score >= min_score)
    if is_kev is not None:
        conditions.append(CVE.is_kev.is_(is_kev))
    if modified_since is not None:
        conditions.append(CVE.last_modified_date >= modified_since)
    if search:
        # « % » et « _ » saisis sont cherchés tels quels, pas comme jokers SQL.
        literal = search.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{literal}%"
        conditions.append(
            or_(CVE.id.ilike(pattern, escape="\\"), CVE.description.ilike(pattern, escape="\\"))
        )

    total = await session.scalar(select(func.count()).select_from(CVE).where(*conditions))
    rows = await session.execute(
        select(CVE)
        .where(*conditions)
        .order_by(CVE.composite_risk_score.desc(), CVE.last_modified_date.desc(), CVE.id)
        .limit(limit)
        .offset(offset)
    )
    return Page(items=rows.scalars().all(), total=total or 0)


async def get_cve(session: AsyncSession, cve_id: str) -> CVE:
    cve = await session.get(CVE, normalize_cve_id(cve_id), populate_existing=True)
    if cve is None:
        raise CVENotFoundError(cve_id)
    return cve


async def priority_history(session: AsyncSession, cve_id: str) -> Sequence[CVEPriorityChange]:
    rows = await session.execute(
        select(CVEPriorityChange)
        .where(CVEPriorityChange.cve_id == normalize_cve_id(cve_id))
        .order_by(CVEPriorityChange.changed_at, CVEPriorityChange.id)
    )
    return rows.scalars().all()


async def list_alerts(
    session: AsyncSession,
    *,
    limit: int,
    offset: int,
    acknowledged: bool | None = None,
    cve_id: str | None = None,
) -> Page[CVEAlert]:
    conditions: list[ColumnElement[bool]] = []
    if acknowledged is not None:
        clause = CVEAlert.acknowledged_at.is_not(None)
        conditions.append(clause if acknowledged else CVEAlert.acknowledged_at.is_(None))
    if cve_id is not None:
        conditions.append(CVEAlert.cve_id == normalize_cve_id(cve_id))
    total = await session.scalar(select(func.count()).select_from(CVEAlert).where(*conditions))
    rows = await session.execute(
        select(CVEAlert)
        .where(*conditions)
        .order_by(CVEAlert.created_at.desc(), CVEAlert.id)
        .limit(limit)
        .offset(offset)
    )
    return Page(items=rows.scalars().all(), total=total or 0)
