"""Routes du threat hunting — `/api/v1/hunting` (MOD-06, RF-25 à RF-28).

| Opération                                   | ADMIN | ANALYST | VIEWER |
|---------------------------------------------|:-----:|:-------:|:------:|
| Catalogue de règles, sessions et résultats  |   ✅  |   ✅    |   ✅   |
| Lancer une session de chasse                |   ✅  |   ✅    |   ❌   |

Une session s'exécute pendant la requête (10 000 observables au plus) : le résultat est
immédiatement consultable et reste enregistré.
"""

from collections.abc import Sequence
from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.api.deps import Audit, CurrentUser, DbSession, require_roles
from illwatch.app.api.v1.attack import AttackContextRead, TechniqueRefRead, attack_context
from illwatch.app.config import get_settings
from illwatch.app.models import HuntingMatch, HuntingSession, User
from illwatch.modules.attack.catalog import RULE_TECHNIQUES
from illwatch.modules.attack.service import TechniqueRef, actor_index, technique_refs
from illwatch.modules.threat_feeds.fetcher import fetch_feed_content
from illwatch.modules.threat_hunting import engine
from illwatch.modules.threat_hunting.engine import (
    MAX_ASSETS,
    MAX_OBSERVABLES,
    HuntNotFoundError,
)
from illwatch.modules.threat_hunting.rules import CATALOG
from illwatch.shared.enums import HuntStatus, HuntTrigger, Severity, UserRole

router = APIRouter(prefix="/hunting", tags=["threat hunting"])

Hunter = Annotated[User, Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST))]


class RuleRead(BaseModel):
    id: str
    name: str
    description: str
    severity: Severity
    version: int = Field(description="Version de la règle (règles versionnées, M9).")
    techniques: list[str] = Field(description="Techniques ATT&CK révélées par la règle (M10).")
    changes: list[str] = Field(description="Historique des versions, de la plus ancienne.")


class HuntRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observables: list[str] = Field(
        default_factory=list,
        max_length=MAX_OBSERVABLES,
        description="IP, domaines, URL, hashs, e-mails ; vide = chasse sur la base d'IOC.",
    )
    assets: list[str] = Field(
        default_factory=list,
        max_length=MAX_ASSETS,
        description="Produits de l'inventaire (ex. « FortiOS », « Exchange ») pour RULE-05.",
    )
    rules: list[str] | None = Field(default=None, description="Défaut : tout le catalogue.")


class MatchRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    rule_id: str
    severity: Severity
    observable: str
    detail: str
    indicator_id: UUID | None
    cve_id: str | None
    attack: AttackContextRead | None = Field(
        default=None, description="Technique ATT&CK de la règle, acteurs cités (M10)."
    )


class HuntRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    trigger: HuntTrigger
    status: HuntStatus
    rules: str
    observables_count: int
    rejected_count: int
    assets: str | None
    matches_count: int
    errors: str | None
    started_at: datetime
    finished_at: datetime | None
    rule_versions: dict[str, int] | None = None
    incident_id: UUID | None = None


class HuntDetail(HuntRead):
    matches: list[MatchRead]


class MatchPage(BaseModel):
    items: list[MatchRead]
    total: int
    limit: int
    offset: int
    by_rule: dict[str, int] = Field(
        description="Correspondances par règle (filtre de sévérité appliqué, pas celui de règle)."
    )


async def _with_attack(session: AsyncSession, matches: Sequence[HuntingMatch]) -> list[MatchRead]:
    """Contexte ATT&CK de chaque correspondance : techniques de la règle (lues une fois par
    règle) et acteurs cités dans le détail (techniques lues une fois par acteur)."""
    by_rule: dict[str, list[TechniqueRefRead]] = {}
    memo: dict[str, tuple[TechniqueRef, ...]] = {}
    index = await actor_index(session) if matches else None
    out = []
    for m in matches:
        if m.rule_id not in by_rule:
            refs = await technique_refs(session, RULE_TECHNIQUES.get(m.rule_id, ()))
            by_rule[m.rule_id] = [TechniqueRefRead(id=t.id, name=t.name, url=t.url) for t in refs]
        item = MatchRead.model_validate(m)
        context = await attack_context(
            session, texts=[m.detail], memo=memo, index=index, indicator_ids=[m.indicator_id]
        )
        item.attack = AttackContextRead(
            techniques=by_rule[m.rule_id], actors=context.actors, campaigns=context.campaigns
        )
        out.append(item)
    return out


async def _detail(session: AsyncSession, hunt: HuntingSession) -> HuntDetail:
    return HuntDetail(
        **HuntRead.model_validate(hunt).model_dump(),
        matches=await _with_attack(session, hunt.matches),
    )


@router.get("/rules", response_model=list[RuleRead], summary="Catalogue de règles (RF-26)")
async def rules(_: CurrentUser) -> list[RuleRead]:
    return [
        RuleRead(
            id=r.id,
            name=r.name,
            description=r.description,
            severity=r.severity,
            version=r.version,
            changes=list(r.changes),
            techniques=list(RULE_TECHNIQUES.get(r.id, ())),
        )
        for r in CATALOG
    ]


@router.post(
    "/sessions",
    response_model=HuntDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Lancer une session de chasse (RF-27)",
)
async def run(payload: HuntRequest, session: DbSession, user: Hunter, audit: Audit) -> HuntDetail:
    try:
        hunt = await engine.run_hunt(
            session,
            settings=get_settings(),
            fetch=fetch_feed_content,
            observables=payload.observables,
            assets=payload.assets,
            rule_ids=payload.rules,
            author_id=user.id,
        )
    except ValueError as exc:  # règle inconnue, limites
        raise HTTPException(422, detail=str(exc)) from None
    await audit.record(
        "hunt.run",
        actor=user,
        target_type="hunt",
        target_id=hunt.id,
        detail={
            "rules": hunt.rules,
            "observables": hunt.observables_count,
            "matches": hunt.matches_count,
            "status": hunt.status,
        },
    )
    return await _detail(session, await engine.get_hunt(session, hunt.id))


@router.get("/sessions", response_model=list[HuntRead], summary="Sessions de chasse (RF-28)")
async def sessions(
    session: DbSession,
    _: CurrentUser,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[HuntRead]:
    return [
        HuntRead.model_validate(h)
        for h in await engine.list_hunts(session, limit=limit, offset=offset)
    ]


@router.get("/sessions/{hunt_id}", response_model=HuntDetail, summary="Résultats d'une session")
async def read(hunt_id: UUID, session: DbSession, _: CurrentUser) -> HuntDetail:
    try:
        return await _detail(session, await engine.get_hunt(session, hunt_id))
    except HuntNotFoundError:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, detail=f"Session {hunt_id} introuvable."
        ) from None


@router.get(
    "/sessions/{hunt_id}/matches",
    response_model=MatchPage,
    summary="Correspondances d'une session, paginées (les plus graves d'abord)",
)
async def matches(
    hunt_id: UUID,
    session: DbSession,
    _: CurrentUser,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    rule_id: Annotated[str | None, Query(max_length=20)] = None,
    severity: Severity | None = None,
) -> MatchPage:
    try:
        page = await engine.list_matches(
            session, hunt_id, limit=limit, offset=offset, rule_id=rule_id, severity=severity
        )
    except HuntNotFoundError:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, detail=f"Session {hunt_id} introuvable."
        ) from None
    return MatchPage(
        items=await _with_attack(session, page.items),
        total=page.total,
        limit=limit,
        offset=offset,
        by_rule=page.by_rule,
    )
