"""Lecture du bundle STIX 2.1 d'ATT&CK Enterprise (mitre-attack/attack-stix-data).

Retenus : `attack-pattern` (techniques), `intrusion-set` (groupes), `malware` et `tool`
(logiciels), et les relations `uses` d'un groupe ou logiciel vers une technique. Écartés :
objets révoqués ou dépréciés, et tout ce qui n'a pas d'identifiant ATT&CK externe.
"""

import json
from dataclasses import dataclass, field
from typing import Any

MAX_DESCRIPTION = 600


class AttackBundleError(ValueError):
    pass


@dataclass(slots=True)
class Technique:
    id: str
    name: str
    tactics: list[str]
    is_subtechnique: bool


@dataclass(slots=True)
class Actor:
    id: str
    kind: str
    name: str
    aliases: list[str]
    description: str | None


@dataclass(slots=True)
class AttackData:
    version: str | None = None
    techniques: dict[str, Technique] = field(default_factory=dict)
    actors: dict[str, Actor] = field(default_factory=dict)
    uses: set[tuple[str, str]] = field(default_factory=set)


def _external_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack":
            value = ref.get("external_id")
            return str(value) if value else None
    return None


def _live(obj: dict[str, Any]) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def _short(text: object) -> str | None:
    value = " ".join(str(text or "").split())
    if not value:
        return None
    # Les descriptions ATT&CK citent leurs sources « (Citation: …) » : retirées pour la lecture.
    while "(Citation:" in value:
        start = value.index("(Citation:")
        end = value.find(")", start)
        value = value[:start].rstrip() + (value[end + 1 :] if end != -1 else "")
    return value[:MAX_DESCRIPTION] or None


def parse_bundle(content: bytes) -> AttackData:
    try:
        document = json.loads(content)
    except ValueError as exc:
        raise AttackBundleError(f"Bundle ATT&CK illisible : {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("objects"), list):
        raise AttackBundleError("Bundle ATT&CK attendu (objet STIX `bundle` avec `objects`).")
    data = AttackData()
    by_stix: dict[str, str] = {}
    relations: list[tuple[str, str]] = []
    for obj in document["objects"]:
        if not isinstance(obj, dict) or not _live(obj):
            continue
        kind = obj.get("type")
        if kind == "x-mitre-collection":
            data.version = str(obj.get("x_mitre_version") or "") or data.version
            continue
        if kind == "relationship":
            if obj.get("relationship_type") == "uses":
                relations.append((str(obj.get("source_ref")), str(obj.get("target_ref"))))
            continue
        external = _external_id(obj)
        if external is None:
            continue
        if kind == "attack-pattern":
            tactics = [
                str(p.get("phase_name"))
                for p in obj.get("kill_chain_phases") or []
                if isinstance(p, dict) and p.get("kill_chain_name") == "mitre-attack"
            ]
            data.techniques[external] = Technique(
                external, str(obj.get("name") or external)[:200], tactics, "." in external
            )
        elif kind in ("intrusion-set", "malware", "tool"):
            aliases = [str(a) for a in (obj.get("aliases") or obj.get("x_mitre_aliases") or [])]
            name = str(obj.get("name") or external)[:200]
            data.actors[external] = Actor(
                external,
                "group" if kind == "intrusion-set" else str(kind),
                name,
                sorted({a[:120] for a in aliases if a and a != name}),
                _short(obj.get("description")),
            )
        else:
            continue
        by_stix[str(obj.get("id"))] = external
    for source, target in relations:
        actor, technique = by_stix.get(source), by_stix.get(target)
        if actor in data.actors and technique in data.techniques:
            data.uses.add((actor, technique))
    if not data.techniques:
        raise AttackBundleError("Aucune technique ATT&CK dans ce bundle.")
    return data
