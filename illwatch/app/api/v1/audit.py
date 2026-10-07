"""Journal d'audit — `GET /api/v1/audit` (ADMIN), M7 Production Hardening (ADR-011)."""

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict

from illwatch.app.api.deps import DbSession, require_roles
from illwatch.app.models import User
from illwatch.modules.foundation.audit import list_audit_events
from illwatch.shared.enums import AuditOutcome, UserRole

router = APIRouter(prefix="/audit", tags=["audit"])

AdminUser = Annotated[User, Depends(require_roles(UserRole.ADMIN))]


class AuditEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    occurred_at: datetime
    actor_id: UUID | None
    actor_name: str | None
    action: str
    outcome: AuditOutcome
    target_type: str | None
    target_id: str | None
    ip: str | None
    request_id: str | None
    detail: dict[str, Any] | None


class AuditPage(BaseModel):
    items: list[AuditEventRead]
    total: int
    limit: int
    offset: int


@router.get("", response_model=AuditPage, summary="Journal d'audit, le plus récent d'abord")
async def list_audit(
    session: DbSession,
    _: AdminUser,
    action: Annotated[str | None, Query(max_length=64, description="Préfixe : `auth.`")] = None,
    actor: Annotated[str | None, Query(max_length=150)] = None,
    outcome: AuditOutcome | None = None,
    since: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AuditPage:
    rows, total = await list_audit_events(
        session,
        action=action,
        actor=actor,
        outcome=outcome,
        since=since,
        limit=limit,
        offset=offset,
    )
    return AuditPage(
        items=[AuditEventRead.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )
