"""Contexte MITRE ATT&CK — `/api/v1/attack` (M10, ADR-023).

Lecture pour tout utilisateur authentifié. Les détections (correspondances de chasse,
évènements corrélés, incidents) portent leur contexte ATT&CK dans leur propre réponse ;
ces routes donnent l'état du référentiel et le détail d'une technique.
"""

from collections.abc import Iterable, Sequence
from datetime import datetime

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.api.deps import CurrentUser, DbSession
from illwatch.app.models import AttackActor, AttackTechnique, AttackUse
from illwatch.modules.attack import service
from illwatch.modules.attack.catalog import actor_url, technique_url

router = APIRouter(prefix="/attack", tags=["MITRE ATT&CK"])

ATTRIBUTION = "ATT&CK® © The MITRE Corporation, reproduit avec son autorisation."


class TechniqueRefRead(BaseModel):
    id: str
    name: str
    url: str


class ActorRefRead(BaseModel):
    id: str
    kind: str = Field(description="group (groupe d'attaquants) ou malware.")
    name: str
    url: str
    matched: str = Field(description="Libellé trouvé dans le renseignement.")
    techniques: list[TechniqueRefRead]


class AttackContextRead(BaseModel):
    techniques: list[TechniqueRefRead] = Field(description="Techniques révélées par la détection.")
    actors: list[ActorRefRead] = Field(
        description="Groupes ou logiciels cités dans le renseignement, avec leurs techniques."
    )


class AttackStatusRead(BaseModel):
    imported_at: datetime | None
    techniques: int
    actors: int
    attribution: str = ATTRIBUTION


class TechniqueDetailRead(BaseModel):
    id: str
    name: str
    url: str
    tactics: list[str]
    actors: list[ActorRefRead]


async def attack_context(
    session: AsyncSession,
    *,
    rule_ids: Iterable[str] = (),
    techniques: Iterable[str] = (),
    texts: Sequence[str | None] = (),
    memo: dict[str, tuple[service.TechniqueRef, ...]] | None = None,
    index: service.ActorIndex | None = None,
) -> AttackContextRead:
    ids = [*service.rule_techniques(rule_ids), *techniques]
    refs = await service.technique_refs(session, ids)
    actors = await service.actors_in(session, texts, memo, index)
    return AttackContextRead(
        techniques=[TechniqueRefRead(id=t.id, name=t.name, url=t.url) for t in refs],
        actors=[
            ActorRefRead(
                id=a.id,
                kind=a.kind,
                name=a.name,
                url=a.url,
                matched=a.matched,
                techniques=[
                    TechniqueRefRead(id=t.id, name=t.name, url=t.url) for t in a.techniques
                ],
            )
            for a in actors
        ],
    )


@router.get("/status", response_model=AttackStatusRead, summary="État du référentiel ATT&CK")
async def attack_status(session: DbSession, _: CurrentUser) -> AttackStatusRead:
    state = await service.attack_status(session)
    return AttackStatusRead(
        imported_at=state.imported_at, techniques=state.techniques, actors=state.actors
    )


@router.get(
    "/techniques/{technique_id}",
    response_model=TechniqueDetailRead,
    summary="Une technique et les groupes ou logiciels qui l'emploient",
)
async def technique(technique_id: str, session: DbSession, _: CurrentUser) -> TechniqueDetailRead:
    found = await session.get(AttackTechnique, technique_id.upper()[:16])
    if found is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, detail=f"{technique_id} inconnue du référentiel importé."
        )
    rows = (
        await session.execute(
            select(AttackActor.id, AttackActor.kind, AttackActor.name)
            .join(AttackUse, AttackUse.actor_id == AttackActor.id)
            .where(AttackUse.technique_id == found.id, AttackActor.kind.in_(["group", "malware"]))
            .order_by(AttackActor.kind, AttackActor.name)
            .limit(200)
        )
    ).all()
    return TechniqueDetailRead(
        id=found.id,
        name=found.name,
        url=technique_url(found.id),
        tactics=found.tactics,
        actors=[
            ActorRefRead(id=i, kind=k, name=n, url=actor_url(i, k), matched=n, techniques=[])
            for i, k, n in rows
        ],
    )
