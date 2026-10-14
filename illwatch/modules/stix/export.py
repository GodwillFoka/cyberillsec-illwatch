"""Export STIX 2.1 du renseignement d'ILL Watch — M10, incrément 3 (ADR-025).

- **Indicateurs** : un objet `indicator` par IOC actif (non expiré, non exclu), motif STIX
  selon son type, confiance 0–100 (ADR-017), sévérité en étiquette, validité (`valid_until`)
  à l'expiration. Identifiants **déterministes** (UUID v5 du type et de la valeur) : un même
  IOC garde le même identifiant d'un export à l'autre, ce que les consommateurs TAXII
  utilisent pour dédupliquer.
- **Campagnes** : objets `campaign`, leur acteur (`intrusion-set` pour un groupe ATT&CK,
  `malware` pour un logiciel, avec la référence `mitre-attack`), relations « attribuée à » ou
  « utilise », et « indique » de chaque IOC de leur infrastructure vers la campagne.

Tout objet est signé par l'identité « ILL Watch » (`created_by_ref`).
"""

import base64
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid5

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import AttackActor, Campaign, CampaignIndicator, Indicator
from illwatch.modules.attack.catalog import actor_url
from illwatch.modules.correlation.confidence import compute_confidence, source_reliabilities
from illwatch.modules.threat_feeds.indicators import is_active_clause
from illwatch.shared.enums import IndicatorType

NAMESPACE = UUID("21ff17a3-f8f1-4969-983a-99cad4b0f7a9")
SPEC = "2.1"
IDENTITY_ID = f"identity--{uuid5(NAMESPACE, 'identity:illwatch')}"
MAX_PAGE = 1000

_OBSERVABLE = {
    IndicatorType.IPV4: "ipv4-addr:value",
    IndicatorType.IPV6: "ipv6-addr:value",
    IndicatorType.NETWORK: "{net}:value",  # ipv4-addr ou ipv6-addr selon la plage
    IndicatorType.DOMAIN: "domain-name:value",
    IndicatorType.URL: "url:value",
    IndicatorType.EMAIL: "email-addr:value",
    IndicatorType.HASH_SHA256: "file:hashes.'SHA-256'",
    IndicatorType.HASH_SHA1: "file:hashes.'SHA-1'",
    IndicatorType.HASH_MD5: "file:hashes.MD5",
}


def timestamp(value: datetime | None) -> str:
    moment = value or datetime.now(UTC)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return (
        moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"
    )


def stix_id(kind: str, key: str) -> str:
    return f"{kind}--{uuid5(NAMESPACE, f'{kind}:{key}')}"


def pattern(ioc_type: str, value: str) -> str:
    """Motif STIX d'un IOC : `[ipv4-addr:value = '203.0.113.7']` (guillemets échappés)."""
    kind = IndicatorType(ioc_type)
    path = _OBSERVABLE[kind]
    if kind is IndicatorType.NETWORK:
        path = path.format(net="ipv6-addr" if ":" in value else "ipv4-addr")
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return f"[{path} = '{escaped}']"


def identity() -> dict[str, Any]:
    created = "2026-10-15T00:00:00.000Z"
    return {
        "type": "identity",
        "spec_version": SPEC,
        "id": IDENTITY_ID,
        "created": created,
        "modified": created,
        "name": "ILL Watch",
        "identity_class": "system",
        "description": "Plateforme CTI/SOC ILL Watch (CyberillSec).",
    }


def indicator_object(ioc: Indicator, confidence: int) -> dict[str, Any]:
    first = timestamp(ioc.first_seen)
    obj: dict[str, Any] = {
        "type": "indicator",
        "spec_version": SPEC,
        "id": stix_id("indicator", f"{ioc.type}:{ioc.value}"),
        "created_by_ref": IDENTITY_ID,
        "created": first,
        "modified": timestamp(ioc.last_seen),
        "name": ioc.value[:250],
        "indicator_types": ["malicious-activity"],
        "pattern": pattern(str(ioc.type), ioc.value),
        "pattern_type": "stix",
        "valid_from": first,
        "confidence": max(0, min(100, int(confidence))),
        "labels": [f"severity:{str(ioc.severity).lower()}"],
    }
    if ioc.description:
        obj["description"] = ioc.description[:2000]
    expires = ioc.expires_at
    if expires is not None and timestamp(expires) > first:
        obj["valid_until"] = timestamp(expires)
    return obj


@dataclass(frozen=True, slots=True)
class Page:
    objects: list[dict[str, Any]]
    more: bool
    next: str | None
    first_added: datetime | None
    last_added: datetime | None


def _cursor(seen: datetime, ident: UUID) -> str:
    raw = f"{seen.isoformat()}|{ident}"  # précision complète (µs) : curseur exact
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def _decode_cursor(token: str) -> tuple[datetime, UUID]:
    padded = token + "=" * (-len(token) % 4)
    try:
        moment, ident = base64.urlsafe_b64decode(padded.encode()).decode().split("|", 1)
        return datetime.fromisoformat(moment), UUID(ident)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("Curseur de pagination invalide.") from exc


async def _confidences(
    session: AsyncSession, iocs: Sequence[Indicator], now: datetime
) -> dict[UUID, int]:
    cotes = await source_reliabilities(session, [i.id for i in iocs])
    return {
        i.id: compute_confidence(
            reliabilities=cotes.get(i.id, []),
            ioc_type=i.type,
            last_seen=i.last_seen,
            hit_count=i.hit_count,
            now=now,
        ).total
        for i in iocs
    }


async def indicator_page(
    session: AsyncSession,
    *,
    now: datetime | None = None,
    added_after: datetime | None = None,
    limit: int = 500,
    next_token: str | None = None,
) -> Page:
    """IOC actifs, des plus anciennement modifiés aux plus récents (« date d'ajout » TAXII =
    dernière observation), pagination par curseur stable."""
    moment = now or datetime.now(UTC)
    size = max(1, min(MAX_PAGE, limit))
    conditions = [is_active_clause(moment)]
    if added_after is not None:
        conditions.append(Indicator.last_seen > added_after)
    if next_token:
        seen, ident = _decode_cursor(next_token)
        conditions.append(
            or_(Indicator.last_seen > seen, and_(Indicator.last_seen == seen, Indicator.id > ident))
        )
    rows = list(
        (
            await session.scalars(
                select(Indicator)
                .where(*conditions)
                .order_by(Indicator.last_seen, Indicator.id)
                .limit(size + 1)
            )
        ).all()
    )
    more = len(rows) > size
    rows = rows[:size]
    confidences = await _confidences(session, rows, moment)
    objects = [indicator_object(i, confidences[i.id]) for i in rows]
    last = rows[-1] if rows else None
    return Page(
        objects=objects,
        more=more,
        next=_cursor(last.last_seen, last.id) if more and last else None,
        first_added=rows[0].last_seen if rows else None,
        last_added=last.last_seen if last else None,
    )


async def campaign_objects(
    session: AsyncSession, *, now: datetime | None = None
) -> list[dict[str, Any]]:
    """Campagnes, leurs acteurs, leur infrastructure et les relations qui les relient."""
    moment = now or datetime.now(UTC)
    campaigns = (await session.scalars(select(Campaign).order_by(Campaign.name))).all()
    objects: list[dict[str, Any]] = []
    actors_done: set[str] = set()
    for campaign in campaigns:
        campaign_id = stix_id("campaign", str(campaign.id))
        created = timestamp(campaign.created_at)
        objects.append(
            {
                "type": "campaign",
                "spec_version": SPEC,
                "id": campaign_id,
                "created_by_ref": IDENTITY_ID,
                "created": created,
                "modified": timestamp(campaign.updated_at),
                "name": campaign.name,
                **({"description": campaign.description} if campaign.description else {}),
            }
        )
        if campaign.actor_id:
            actor = await session.get(AttackActor, campaign.actor_id)
            if actor is not None:
                kind = "intrusion-set" if actor.kind == "group" else "malware"
                actor_ref = stix_id(kind, actor.id)
                if actor.id not in actors_done:
                    actors_done.add(actor.id)
                    actor_obj: dict[str, Any] = {
                        "type": kind,
                        "spec_version": SPEC,
                        "id": actor_ref,
                        "created_by_ref": IDENTITY_ID,
                        "created": created,
                        "modified": created,
                        "name": actor.name,
                        "external_references": [
                            {
                                "source_name": "mitre-attack",
                                "external_id": actor.id,
                                "url": actor_url(actor.id, actor.kind),
                            }
                        ],
                    }
                    if actor.aliases:
                        actor_obj["aliases"] = actor.aliases[:20]
                    if kind == "malware":
                        actor_obj["is_family"] = True
                    objects.append(actor_obj)
                relation = "attributed-to" if kind == "intrusion-set" else "uses"
                objects.append(_relationship(campaign_id, relation, actor_ref, created))
        iocs = list(
            (
                await session.scalars(
                    select(Indicator)
                    .join(CampaignIndicator, CampaignIndicator.indicator_id == Indicator.id)
                    .where(CampaignIndicator.campaign_id == campaign.id, is_active_clause(moment))
                    .order_by(Indicator.last_seen.desc())
                    .limit(5000)
                )
            ).all()
        )
        confidences = await _confidences(session, iocs, moment)
        for ioc in iocs:
            indicator = indicator_object(ioc, confidences[ioc.id])
            objects.append(indicator)
            objects.append(_relationship(indicator["id"], "indicates", campaign_id, created))
    # Un IOC rattaché à deux campagnes n'apparaît qu'une fois.
    unique: dict[str, dict[str, Any]] = {}
    for obj in objects:
        unique.setdefault(obj["id"], obj)
    return list(unique.values())


def _relationship(source: str, kind: str, target: str, created: str) -> dict[str, Any]:
    return {
        "type": "relationship",
        "spec_version": SPEC,
        "id": stix_id("relationship", f"{source}|{kind}|{target}"),
        "created_by_ref": IDENTITY_ID,
        "created": created,
        "modified": created,
        "relationship_type": kind,
        "source_ref": source,
        "target_ref": target,
    }


def bundle(objects: Sequence[dict[str, Any]]) -> dict[str, Any]:
    ids = ",".join(sorted(o["id"] for o in objects))
    return {
        "type": "bundle",
        "id": f"bundle--{uuid5(NAMESPACE, ids or 'vide')}",
        "objects": [identity(), *objects],
    }


EXPORT_CONTENTS = ("tout", "indicateurs", "campagnes")


async def export_bundle(
    session: AsyncSession, *, content: str = "tout", limit: int = MAX_PAGE
) -> dict[str, Any]:
    """Bundle STIX 2.1 prêt à importer : IOC actifs les plus récents et/ou campagnes."""
    if content not in EXPORT_CONTENTS:
        raise ValueError(f"Contenu inconnu : {content} ({', '.join(EXPORT_CONTENTS)}).")
    objects: list[dict[str, Any]] = []
    if content in ("tout", "campagnes"):
        objects += await campaign_objects(session)
    if content in ("tout", "indicateurs"):
        moment = datetime.now(UTC)
        rows = list(
            (
                await session.scalars(
                    select(Indicator)
                    .where(is_active_clause(moment))
                    .order_by(Indicator.last_seen.desc(), Indicator.id)
                    .limit(max(1, min(50_000, limit)))
                )
            ).all()
        )
        confidences = await _confidences(session, rows, moment)
        known = {o["id"] for o in objects}
        objects += [
            o
            for o in (indicator_object(i, confidences[i.id]) for i in rows)
            if o["id"] not in known
        ]
    return bundle(objects)
