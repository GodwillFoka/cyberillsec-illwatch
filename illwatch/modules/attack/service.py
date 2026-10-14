"""Référentiel ATT&CK : import, techniques d'une détection, acteurs cités — M10, ADR-023.

Attribution prudente : un acteur n'est proposé que si son nom (ou un alias) figure en toutes
lettres dans le renseignement attaché à la détection (description de l'IOC par sa source,
détail de la règle). Groupes et logiciels malveillants seulement : les outils génériques
(« Net », « Ping », « Tor ») ne désignent personne. Libellés de 4 caractères au moins, mot
entier, hors liste de mots courants.
"""

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import delete, func, insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import AttackActor, AttackTechnique, AttackUse, CollectorState
from illwatch.modules.attack.catalog import (
    BUILTIN_TECHNIQUES,
    RULE_TECHNIQUES,
    actor_url,
    technique_url,
)
from illwatch.modules.attack.stix import AttackData

STATE = "attack"
MIN_NAME = 4
MAX_ACTORS = 5
MAX_TECHNIQUES_PER_ACTOR = 8
_CHUNK = 500
# Noms d'acteurs ou alias qui sont aussi des mots courants : jamais attribués sur le seul texte.
COMMON_WORDS = frozenset(
    {
        "admin",
        "agent",
        "android",
        "apple",
        "bank",
        "cloud",
        "dark",
        "data",
        "hive",
        "inception",
        "machete",
        "medusa",
        "mobile",
        "office",
        "play",
        "royal",
        "sharp",
        "spider",
        "storm",
        "update",
        "windows",
    }
)


@dataclass(frozen=True, slots=True)
class TechniqueRef:
    id: str
    name: str
    url: str


@dataclass(frozen=True, slots=True)
class ActorRef:
    id: str
    kind: str
    name: str
    url: str
    matched: str  # libellé trouvé dans le renseignement
    techniques: tuple[TechniqueRef, ...]


async def import_attack(
    session: AsyncSession, data: AttackData, *, now: datetime | None = None
) -> dict[str, int | str | None]:
    """Remplace le référentiel par cette version (une transaction, l'appelant valide)."""
    await session.execute(delete(AttackUse))
    await session.execute(delete(AttackActor))
    await session.execute(delete(AttackTechnique))
    techniques = [
        {"id": t.id, "name": t.name, "tactics": t.tactics, "is_subtechnique": t.is_subtechnique}
        for t in data.techniques.values()
    ]
    actors = [
        {
            "id": a.id,
            "kind": a.kind,
            "name": a.name,
            "aliases": a.aliases,
            "description": a.description,
        }
        for a in data.actors.values()
    ]
    uses = [{"actor_id": a, "technique_id": t} for a, t in sorted(data.uses)]
    for table, rows in ((AttackTechnique, techniques), (AttackActor, actors), (AttackUse, uses)):
        for start in range(0, len(rows), _CHUNK):
            await session.execute(insert(table), rows[start : start + _CHUNK])
    moment = now or datetime.now(UTC)
    state = await session.get(CollectorState, STATE)
    if state is None:
        state = CollectorState(name=STATE)
        session.add(state)
    state.last_success_at = moment
    state.items = len(techniques)
    state.last_error = None
    await session.flush()
    _ACTOR_CACHE.clear()
    return {
        "version": data.version,
        "techniques": len(techniques),
        "actors": len(actors),
        "uses": len(uses),
    }


@dataclass(frozen=True, slots=True)
class AttackStatus:
    imported_at: datetime | None
    techniques: int
    actors: int


async def attack_status(session: AsyncSession) -> AttackStatus:
    state = await session.get(CollectorState, STATE)
    actors = await session.scalar(select(func.count()).select_from(AttackActor))
    return AttackStatus(
        state.last_success_at if state else None, state.items if state else 0, actors or 0
    )


async def technique_refs(session: AsyncSession, ids: Iterable[str]) -> list[TechniqueRef]:
    wanted = list(dict.fromkeys(i for i in ids if i))
    if not wanted:
        return []
    names = dict(
        (
            await session.execute(
                select(AttackTechnique.id, AttackTechnique.name).where(
                    AttackTechnique.id.in_(wanted)
                )
            )
        ).all()
    )
    return [
        TechniqueRef(t, names.get(t) or BUILTIN_TECHNIQUES.get(t, t), technique_url(t))
        for t in wanted
    ]


def rule_techniques(rule_ids: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(t for r in rule_ids for t in RULE_TECHNIQUES.get(r, ())))


# --- Acteurs cités dans le renseignement ------------------------------------------------------

ActorIndex = tuple[re.Pattern[str] | None, dict[str, tuple[str, str, str]]]
# Index des libellés, reconstruit quand le référentiel change (import dans un autre processus).
_ACTOR_CACHE: dict[tuple[object, int], ActorIndex] = {}


async def actor_index(session: AsyncSession) -> ActorIndex:
    """Expression régulière de tous les libellés utilisables, et libellé → (id, type, nom)."""
    state = await session.get(CollectorState, STATE)
    count = await session.scalar(select(func.count()).select_from(AttackActor)) or 0
    key = (state.last_success_at if state else None, count)
    if key in _ACTOR_CACHE:
        return _ACTOR_CACHE[key]
    rows = (
        await session.execute(
            select(AttackActor.id, AttackActor.kind, AttackActor.name, AttackActor.aliases).where(
                AttackActor.kind.in_(["group", "malware"])
            )
        )
    ).all()
    labels: dict[str, tuple[str, str, str]] = {}
    for actor_id, kind, name, aliases in rows:
        for label in [name, *(aliases or [])]:
            text = " ".join(str(label).split()).lower()
            if len(text) >= MIN_NAME and text not in COMMON_WORDS:
                labels.setdefault(text, (actor_id, kind, name))
    pattern = None
    if labels:
        alternatives = sorted(labels, key=len, reverse=True)
        pattern = re.compile(
            r"(?<![\w-])("
            + "|".join(re.escape(a).replace(r"\ ", r"\s+") for a in alternatives)
            + r")(?![\w-])",
            re.IGNORECASE,
        )
    _ACTOR_CACHE.clear()
    _ACTOR_CACHE[key] = (pattern, labels)
    return pattern, labels


async def actors_in(
    session: AsyncSession,
    texts: Sequence[str | None],
    memo: dict[str, tuple[TechniqueRef, ...]] | None = None,
    index: ActorIndex | None = None,
) -> list[ActorRef]:
    """Acteurs ATT&CK cités en toutes lettres dans ces textes, avec leurs techniques.

    `memo` et `index` : techniques déjà lues par acteur et index des libellés, partagés entre
    les appels d'une même page (une liste de correspondances) pour ne relire la base qu'une fois.
    """
    pattern, labels = index if index is not None else await actor_index(session)
    if pattern is None:
        return []
    found: dict[str, tuple[str, str, str]] = {}
    for text in texts:
        for match in pattern.finditer(text or ""):
            key = " ".join(match.group(1).split()).lower()
            actor_id, kind, name = labels[key]
            found.setdefault(actor_id, (kind, name, match.group(1)))
            if len(found) >= MAX_ACTORS:
                break
    cache = memo if memo is not None else {}
    out: list[ActorRef] = []
    for actor_id, (kind, name, matched) in found.items():
        if actor_id not in cache:
            rows = (
                await session.execute(
                    select(AttackTechnique.id, AttackTechnique.name)
                    .join(AttackUse, AttackUse.technique_id == AttackTechnique.id)
                    .where(AttackUse.actor_id == actor_id)
                    .order_by(AttackTechnique.id)
                    .limit(MAX_TECHNIQUES_PER_ACTOR)
                )
            ).all()
            cache[actor_id] = tuple(TechniqueRef(t, n, technique_url(t)) for t, n in rows)
        out.append(
            ActorRef(actor_id, kind, name, actor_url(actor_id, kind), matched, cache[actor_id])
        )
    return out
