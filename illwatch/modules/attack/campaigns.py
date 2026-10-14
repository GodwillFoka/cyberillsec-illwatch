"""Campagnes : création, rattachement de l'infrastructure, contexte des détections — M10,
incrément 2 (ADR-024).

Rattacher, c'est dire « ces IOC appartiennent à cette opération ». Deux façons : par valeurs
(liste collée par l'analyste) ou par description (tous les IOC dont la description par leur
source contient un texte : nom d'un pulse OTX, d'un rapport). Une détection qui touche un IOC
rattaché hérite de la campagne et de son acteur.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import AttackActor, Campaign, CampaignIndicator, Indicator
from illwatch.modules.threat_feeds.validators import InvalidIndicatorError, normalize_indicator

MAX_ATTACH = 5000
MIN_PATTERN = 4


class CampaignError(ValueError):
    """Saisie refusée (message destiné à l'analyste)."""


class CampaignExistsError(CampaignError):
    pass


class CampaignNotFoundError(LookupError):
    pass


@dataclass(frozen=True, slots=True)
class CampaignRef:
    id: UUID
    name: str
    actor_id: str | None


def _like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


async def _check_actor(session: AsyncSession, actor_id: str | None) -> str | None:
    if not actor_id:
        return None
    actor_id = actor_id.strip().upper()
    if await session.get(AttackActor, actor_id) is None:
        raise CampaignError(
            f"{actor_id} inconnu du référentiel ATT&CK importé (`illwatch attack import`)."
        )
    return actor_id


async def create_campaign(
    session: AsyncSession,
    *,
    name: str,
    description: str | None = None,
    actor_id: str | None = None,
    author_id: UUID | None = None,
) -> Campaign:
    clean = " ".join((name or "").split())[:160]
    if len(clean) < 3:
        raise CampaignError("Nom de campagne obligatoire (3 caractères au moins).")
    if await session.scalar(select(Campaign.id).where(Campaign.name == clean)):
        raise CampaignExistsError(f"La campagne « {clean} » existe déjà.")
    campaign = Campaign(
        name=clean,
        description=(description or "").strip()[:4000] or None,
        actor_id=await _check_actor(session, actor_id),
        created_by=author_id,
    )
    session.add(campaign)
    try:
        await session.flush()
    except IntegrityError:
        raise CampaignExistsError(f"La campagne « {clean} » existe déjà.") from None
    return campaign


async def update_campaign(
    session: AsyncSession,
    campaign_id: UUID,
    *,
    description: str | None,
    actor_id: str | None,
) -> Campaign:
    campaign = await get_campaign(session, campaign_id)
    campaign.description = (description or "").strip()[:4000] or None
    campaign.actor_id = await _check_actor(session, actor_id)
    await session.flush()
    return campaign


async def get_campaign(session: AsyncSession, campaign_id: UUID) -> Campaign:
    campaign = await session.get(Campaign, campaign_id)
    if campaign is None:
        raise CampaignNotFoundError(f"Campagne {campaign_id} introuvable.")
    return campaign


async def delete_campaign(session: AsyncSession, campaign_id: UUID) -> Campaign:
    campaign = await get_campaign(session, campaign_id)
    await session.delete(campaign)
    await session.flush()
    return campaign


async def _link(session: AsyncSession, campaign_id: UUID, ids: Sequence[UUID]) -> int:
    """Rattache sans doublon ; renvoie le nombre de nouveaux rattachements."""
    if not ids:
        return 0
    existing = set(
        (
            await session.scalars(
                select(CampaignIndicator.indicator_id).where(
                    CampaignIndicator.campaign_id == campaign_id,
                    CampaignIndicator.indicator_id.in_(list(ids)),
                )
            )
        ).all()
    )
    now = datetime.now(UTC)
    new = [i for i in dict.fromkeys(ids) if i not in existing]
    for start in range(0, len(new), 500):
        session.add_all(
            CampaignIndicator(campaign_id=campaign_id, indicator_id=i, added_at=now)
            for i in new[start : start + 500]
        )
        await session.flush()
    return len(new)


async def attach(
    session: AsyncSession,
    campaign_id: UUID,
    *,
    values: Sequence[str] = (),
    description_contains: str | None = None,
) -> tuple[int, int]:
    """Rattache des IOC connus, par valeur ou par description. Renvoie (rattachés, inconnus)."""
    await get_campaign(session, campaign_id)
    ids: list[UUID] = []
    unknown = 0
    keys: list[tuple[str, str]] = []
    for raw in values:
        try:
            kind, value = normalize_indicator(raw)
        except InvalidIndicatorError:
            unknown += 1
            continue
        keys.append((kind.value, value))
    for start in range(0, len(keys), 500):
        chunk = keys[start : start + 500]
        found = (
            await session.execute(
                select(Indicator.id, Indicator.type, Indicator.value).where(
                    Indicator.value.in_([v for _, v in chunk])
                )
            )
        ).all()
        known = {(str(t), v): i for i, t, v in found}
        for key in chunk:
            if key in known:
                ids.append(known[key])
            else:
                unknown += 1
    if description_contains is not None:
        pattern = " ".join(description_contains.split())
        if len(pattern) < MIN_PATTERN:
            raise CampaignError(f"Texte de description : {MIN_PATTERN} caractères au moins.")
        matched = (
            await session.scalars(
                select(Indicator.id)
                .where(Indicator.description.ilike(f"%{_like(pattern)}%", escape="\\"))
                .limit(MAX_ATTACH + 1)
            )
        ).all()
        if len(matched) > MAX_ATTACH:
            raise CampaignError(
                f"Plus de {MAX_ATTACH} IOC décrits par « {pattern} » : précisez le texte."
            )
        ids += list(matched)
    if len(ids) > MAX_ATTACH:
        raise CampaignError(f"{MAX_ATTACH} IOC au plus par rattachement.")
    return await _link(session, campaign_id, ids), unknown


async def detach(session: AsyncSession, campaign_id: UUID, indicator_id: UUID) -> bool:
    link = await session.get(CampaignIndicator, (campaign_id, indicator_id))
    if link is None:
        return False
    await session.delete(link)
    await session.flush()
    return True


@dataclass(frozen=True, slots=True)
class CampaignSummary:
    campaign: Campaign
    indicators: int
    by_type: dict[str, int]
    last_seen: datetime | None


async def list_campaigns(session: AsyncSession) -> list[CampaignSummary]:
    campaigns = (await session.scalars(select(Campaign).order_by(Campaign.name))).all()
    rows = (
        await session.execute(
            select(
                CampaignIndicator.campaign_id,
                Indicator.type,
                func.count(),
                func.max(Indicator.last_seen),
            )
            .join(Indicator, Indicator.id == CampaignIndicator.indicator_id)
            .group_by(CampaignIndicator.campaign_id, Indicator.type)
        )
    ).all()
    stats: dict[UUID, tuple[dict[str, int], datetime | None]] = {}
    for campaign_id, kind, count, last in rows:
        by_type, seen = stats.get(campaign_id, ({}, None))
        by_type[str(kind)] = int(count)
        stats[campaign_id] = (by_type, max(filter(None, [seen, last]), default=None))
    return [
        CampaignSummary(
            c,
            sum(stats.get(c.id, ({}, None))[0].values()),
            stats.get(c.id, ({}, None))[0],
            stats.get(c.id, ({}, None))[1],
        )
        for c in campaigns
    ]


async def campaign_indicators(
    session: AsyncSession, campaign_id: UUID, *, limit: int = 200
) -> list[Indicator]:
    return list(
        (
            await session.scalars(
                select(Indicator)
                .join(CampaignIndicator, CampaignIndicator.indicator_id == Indicator.id)
                .where(CampaignIndicator.campaign_id == campaign_id)
                .order_by(Indicator.last_seen.desc())
                .limit(limit)
            )
        ).all()
    )


async def campaigns_of(session: AsyncSession, indicator_ids: Iterable[UUID]) -> list[CampaignRef]:
    """Campagnes dont ces IOC font partie (contexte d'une détection ou d'un incident)."""
    ids = [i for i in dict.fromkeys(indicator_ids) if i is not None]
    if not ids:
        return []
    rows = (
        await session.execute(
            select(Campaign.id, Campaign.name, Campaign.actor_id)
            .join(CampaignIndicator, CampaignIndicator.campaign_id == Campaign.id)
            .where(CampaignIndicator.indicator_id.in_(ids))
            .distinct()
            .order_by(Campaign.name)
            .limit(10)
        )
    ).all()
    return [CampaignRef(i, n, a) for i, n, a in rows]
