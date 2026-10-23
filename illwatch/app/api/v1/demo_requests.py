"""Demandes de démonstration — `/api/v1/demo-requests` (ADR-027, lot S4).

- `POST` (public) : formulaire du site de présentation. Entrées bornées et validées,
  consentement obligatoire, débit limité par adresse IP (5 par heure, compteur Redis, adresse
  jamais enregistrée) et plafond quotidien global ; un champ piège (`website`) rempli par un
  robot reçoit la même réponse qu'une vraie demande, sans rien enregistrer.
- `GET` et `PATCH` (ADMIN) : consultation et suivi (nouvelle, recontactée, close), consignés
  au journal d'audit.
"""

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field

from illwatch.app.api.deps import Audit, DbSession, require_roles
from illwatch.app.models import User
from illwatch.app.throttle import LoginThrottle, get_login_throttle
from illwatch.modules.sales import demo_requests as service
from illwatch.shared.enums import DemoInterest, DemoRequestStatus, UserRole
from illwatch.shared.i18n import SUPPORTED

router = APIRouter(prefix="/demo-requests", tags=["demandes de démonstration"])

AdminUser = Annotated[User, Depends(require_roles(UserRole.ADMIN))]

_TEXT = r"^[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f<>]*$"  # pas de caractères de contrôle ni de balises


class DemoRequestWrite(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: str = Field(min_length=2, max_length=120, pattern=_TEXT)
    email: str = Field(max_length=254, pattern=r"^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]{2,}$")
    organisation: str = Field(min_length=2, max_length=160, pattern=_TEXT)
    job_title: str | None = Field(default=None, max_length=120, pattern=_TEXT)
    country: str | None = Field(default=None, pattern=r"^[A-Za-z]{2}$")
    interest: DemoInterest = DemoInterest.DEMO
    message: str | None = Field(default=None, max_length=2000)
    language: Literal["fr", "en", "de", "es", "zh"] = "en"
    consent: bool
    website: str | None = Field(default=None, max_length=200)  # champ piège, invisible


class DemoRequestAck(BaseModel):
    status: Literal["received"] = "received"


class DemoRequestRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    email: str
    organisation: str
    job_title: str | None
    country: str | None
    interest: DemoInterest
    message: str | None
    language: str
    consent_at: datetime
    created_at: datetime
    status: DemoRequestStatus
    handled_at: datetime | None


class DemoRequestPage(BaseModel):
    items: list[DemoRequestRead]
    total: int
    limit: int
    offset: int


class DemoRequestUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: DemoRequestStatus


@router.post(
    "",
    response_model=DemoRequestAck,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Demande de démonstration (public, site de présentation)",
)
async def submit(
    payload: DemoRequestWrite,
    request: Request,
    session: DbSession,
    throttle: Annotated[LoginThrottle, Depends(get_login_throttle)],
) -> DemoRequestAck:
    if not payload.consent:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Consentement requis pour être recontacté.",
        )
    if payload.website:  # robot : même réponse, rien n'est enregistré
        return DemoRequestAck()
    counter = throttle.counter
    ip = request.client.host if request.client else "inconnue"
    key = f"demo:ip:{ip}"
    if await counter.failures(key) >= service.PER_IP_LIMIT or (
        await service.received_today(session) >= service.DAILY_LIMIT
    ):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Trop de demandes : réessayez plus tard.",
            headers={"Retry-After": str(service.PER_IP_WINDOW)},
        )
    await counter.record(key, service.PER_IP_WINDOW)
    language = payload.language if payload.language in SUPPORTED else "en"
    await service.create_request(
        session,
        name=payload.name,
        email=payload.email,
        organisation=payload.organisation,
        job_title=payload.job_title,
        country=payload.country,
        interest=payload.interest,
        message=payload.message,
        language=language,
    )
    return DemoRequestAck()


@router.get("", response_model=DemoRequestPage, summary="Demandes reçues")
async def list_requests(
    session: DbSession,
    user: AdminUser,
    audit: Audit,
    state: Annotated[DemoRequestStatus | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> DemoRequestPage:
    rows, total = await service.list_requests(session, status=state, limit=limit, offset=offset)
    # Données personnelles de prospects : chaque consultation est tracée.
    await audit.record("demo_request.list", actor=user, detail={"count": len(rows)})
    return DemoRequestPage(
        items=[DemoRequestRead.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.patch("/{request_id}", response_model=DemoRequestRead, summary="Suivi d'une demande")
async def update(
    request_id: UUID,
    payload: DemoRequestUpdate,
    session: DbSession,
    user: AdminUser,
    audit: Audit,
) -> DemoRequestRead:
    try:
        row = await service.set_status(session, request_id, payload.status, user_id=user.id)
    except service.DemoRequestNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    await audit.record(
        "demo_request.update",
        actor=user,
        target_type="demo_request",
        target_id=request_id,
        detail={"status": payload.status.value},
    )
    return DemoRequestRead.model_validate(row)
