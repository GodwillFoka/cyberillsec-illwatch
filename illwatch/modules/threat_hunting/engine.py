"""Moteur de threat hunting — RF-25 à RF-28 (phase 6, ADR-009).

    observables soumis (ou IOC de la base) ─┐
    inventaire d'actifs ────────────────────┼─▶ règles du catalogue ─▶ correspondances
    listes de référence (Tor) ──────────────┘                         ─▶ hunting_matches

Chaque exécution est une **session** enregistrée (RF-27, RF-28) : périmètre, règles,
nombre d'observables rejetés, correspondances, erreurs, durée. Une règle en échec (ex. liste
Tor injoignable) n'empêche pas les autres : la session est alors `PARTIELLE`.
"""

import logging
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import ColumnElement, case, func, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from illwatch.app.config import Settings
from illwatch.app.models import CVE, CollectorState, HuntingMatch, HuntingSession, Indicator
from illwatch.modules.threat_feeds.indicators import is_active_clause
from illwatch.modules.threat_feeds.secrets import mask_secrets
from illwatch.modules.threat_feeds.validators import InvalidIndicatorError, normalize_indicator
from illwatch.modules.threat_hunting.rules import (
    CATALOG,
    RULES,
    HuntContext,
    KnownCVE,
    Match,
    Observable,
)
from illwatch.shared.enums import HuntStatus, HuntTrigger, IndicatorType, RiskPriority, Severity
from illwatch.shared.logging import peak_rss_mb

log = logging.getLogger("illwatch.hunting")

MAX_OBSERVABLES = 10_000
MAX_ASSETS = 200
# Règles qui n'examinent que l'inventaire d'actifs, jamais les observables.
ASSET_ONLY_RULES = frozenset({"RULE-05"})
_CHUNK = 500
HUNT_STATE = "hunt"

Fetch = Callable[[str], Awaitable[bytes]]


class UnknownRuleError(ValueError):
    """Identifiant de règle absent du catalogue."""


class HuntNotFoundError(LookupError):
    """Aucune session de chasse ne porte cet identifiant."""


def _normalize(raw: Sequence[str]) -> tuple[list[Observable], int]:
    seen: dict[tuple[IndicatorType, str], Observable] = {}
    rejected = 0
    for value in raw:
        if not value or not value.strip():
            continue
        try:
            ioc_type, normalized = normalize_indicator(value.strip())
        except InvalidIndicatorError:
            rejected += 1
            continue
        seen.setdefault((ioc_type, normalized), Observable(ioc_type, normalized))
    return list(seen.values()), rejected


async def _known_for(
    session: AsyncSession, observables: Sequence[Observable], now: datetime
) -> dict[tuple[IndicatorType, str], Observable]:
    known: dict[tuple[IndicatorType, str], Observable] = {}
    keys = [(o.type.value, o.value) for o in observables]
    for start in range(0, len(keys), _CHUNK):
        rows = await session.execute(
            select(Indicator.id, Indicator.type, Indicator.value, Indicator.description).where(
                tuple_(Indicator.type, Indicator.value).in_(keys[start : start + _CHUNK]),
                is_active_clause(now),
            )
        )
        for ioc_id, ioc_type, value, description in rows.all():
            kind = IndicatorType(ioc_type)
            known[(kind, value)] = Observable(kind, value, ioc_id, description)
    return known


async def _base_iocs(session: AsyncSession, now: datetime) -> list[Observable]:
    rows = await session.execute(
        select(Indicator.id, Indicator.type, Indicator.value, Indicator.description)
        .where(is_active_clause(now))
        .order_by(Indicator.id)
    )
    return [Observable(IndicatorType(t), v, i, d) for i, t, v, d in rows.all()]


async def _exploitable(session: AsyncSession) -> list[KnownCVE]:
    rows = await session.execute(
        select(CVE.id, CVE.description, CVE.composite_risk_score, CVE.priority).where(
            CVE.has_public_exploit.is_(True),
            CVE.priority.in_([RiskPriority.P0_CRITIQUE, RiskPriority.P1_ELEVE]),
        )
    )
    return [KnownCVE(i, d, float(s), p) for i, d, s, p in rows.all()]


def parse_tor_list(content: bytes) -> frozenset[str]:
    exits: set[str] = set()
    for line in content.decode("utf-8", errors="replace").splitlines():
        candidate = line.strip()
        if not candidate or candidate.startswith("#"):
            continue
        try:
            ioc_type, value = normalize_indicator(candidate)
        except InvalidIndicatorError:
            continue
        if ioc_type in (IndicatorType.IPV4, IndicatorType.IPV6):
            exits.add(value)
    return frozenset(exits)


async def run_hunt(
    session: AsyncSession,
    *,
    settings: Settings,
    fetch: Fetch,
    observables: Sequence[str] | None = None,
    assets: Sequence[str] = (),
    rule_ids: Sequence[str] | None = None,
    trigger: HuntTrigger = HuntTrigger.MANUAL,
    author_id: UUID | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> HuntingSession:
    """Exécute une session de chasse et l'enregistre (RF-27, RF-28).

    Raises:
        UnknownRuleError: règle demandée absente du catalogue.
        ValueError: trop d'observables ou d'actifs.
    """
    unknown = [r for r in rule_ids or () if r not in RULES]
    if unknown:
        raise UnknownRuleError(f"Règle(s) inconnue(s) : {', '.join(unknown)}.")
    selected = [RULES[r] for r in dict.fromkeys(rule_ids)] if rule_ids else list(CATALOG)
    if observables is not None and len(observables) > MAX_OBSERVABLES:
        raise ValueError(f"{MAX_OBSERVABLES} observables au plus par session.")
    clean_assets = [a.strip() for a in assets if a and a.strip()]
    if len(clean_assets) > MAX_ASSETS:
        raise ValueError(f"{MAX_ASSETS} actifs au plus par session.")

    now = clock()
    hunt = HuntingSession(
        trigger=trigger,
        status=HuntStatus.EN_COURS,
        author_id=author_id,
        rules=",".join(r.id for r in selected),
        assets=", ".join(clean_assets) or None,
        started_at=now,
    )
    session.add(hunt)
    await session.flush()

    submitted = observables is not None and len(observables) > 0
    if submitted:
        items, hunt.rejected_count = _normalize(observables or [])
        known = await _known_for(session, items, now)
        # Un observable connu porte son identifiant d'IOC et sa description de source.
        items = [known.get((o.type, o.value), o) for o in items]
    elif all(r.id in ASSET_ONLY_RULES for r in selected):
        # RULE-05 seule confronte l'inventaire aux CVE : inutile de charger toute la base d'IOC.
        items, known = [], {}
    else:
        items = await _base_iocs(session, now)
        known = {(o.type, o.value): o for o in items}
    hunt.observables_count = len(items)

    context = HuntContext(
        observables=items,
        known_iocs=known,
        submitted=submitted,
        assets=clean_assets,
        exploitable_cves=await _exploitable(session) if clean_assets else (),
    )
    errors: dict[str, str] = {}
    if any(r.needs_tor_list for r in selected):
        try:
            context.tor_exits = parse_tor_list(await fetch(settings.tor_exit_list_url))
        except Exception as exc:  # noqa: BLE001 - la liste Tor ne doit pas bloquer les autres règles
            errors["RULE-01"] = mask_secrets(f"liste Tor indisponible : {exc}", settings)[:300]

    matches: dict[tuple[str, str, str | None], Match] = {}
    for rule in selected:
        if rule.id in errors:
            continue
        try:
            for match in rule.evaluate(context):
                matches.setdefault((match.rule_id, match.observable, match.cve_id), match)
        except Exception as exc:  # noqa: BLE001 - une règle défaillante n'arrête pas la session
            errors[rule.id] = f"{type(exc).__name__} : {exc}"[:300]

    for m in matches.values():
        session.add(
            HuntingMatch(
                session_id=hunt.id,
                rule_id=m.rule_id,
                severity=m.severity,
                observable=m.observable[:2048],
                detail=m.detail,
                indicator_id=m.indicator_id,
                cve_id=m.cve_id,
            )
        )
    hunt.matches_count = len(matches)
    hunt.errors = "\n".join(f"{k} : {v}" for k, v in errors.items()) or None
    if not errors:
        hunt.status = HuntStatus.TERMINEE
    elif len(errors) < len(selected):
        hunt.status = HuntStatus.PARTIELLE
    else:
        hunt.status = HuntStatus.ECHEC
    hunt.finished_at = clock()
    await session.flush()
    log.info(
        "hunt.finished",
        extra={
            "fields": {
                "session_id": str(hunt.id),
                "trigger": str(trigger),
                "status": str(hunt.status),
                "observables": hunt.observables_count,
                "rejected": hunt.rejected_count,
                "matches": hunt.matches_count,
                "errors": list(errors) or None,
                "peak_rss_mb": peak_rss_mb(),
            }
        },
    )
    return hunt


async def get_hunt(session: AsyncSession, hunt_id: UUID) -> HuntingSession:
    hunt = await session.get(
        HuntingSession,
        hunt_id,
        populate_existing=True,
        options=[selectinload(HuntingSession.matches)],
    )
    if hunt is None:
        raise HuntNotFoundError(str(hunt_id))
    return hunt


_SEVERITY_RANK = case(
    (HuntingMatch.severity == Severity.CRITICAL.value, 4),
    (HuntingMatch.severity == Severity.HIGH.value, 3),
    (HuntingMatch.severity == Severity.MEDIUM.value, 2),
    (HuntingMatch.severity == Severity.LOW.value, 1),
    else_=0,
)


@dataclass(slots=True)
class MatchPage:
    items: list[HuntingMatch]
    total: int
    by_rule: dict[str, int]


async def list_matches(
    session: AsyncSession,
    hunt_id: UUID,
    *,
    limit: int,
    offset: int,
    rule_id: str | None = None,
    severity: Severity | None = None,
) -> MatchPage:
    """Correspondances d'une session, les plus graves d'abord, filtrables et paginées.

    Une chasse planifiée sur toute la base peut en produire des milliers : l'interface les
    lit par pages. `by_rule` compte les correspondances de chaque règle (filtres compris,
    hors filtre de règle) pour présenter les filtres avec leurs effectifs.
    """
    if await session.get(HuntingSession, hunt_id) is None:
        raise HuntNotFoundError(str(hunt_id))
    base: list[ColumnElement[bool]] = [HuntingMatch.session_id == hunt_id]
    if severity is not None:
        base.append(HuntingMatch.severity == severity.value)
    counts = await session.execute(
        select(HuntingMatch.rule_id, func.count()).where(*base).group_by(HuntingMatch.rule_id)
    )
    by_rule: dict[str, int] = dict(counts.tuples().all())
    conditions = [*base, HuntingMatch.rule_id == rule_id] if rule_id else base
    total = by_rule.get(rule_id, 0) if rule_id else sum(by_rule.values())
    rows = await session.execute(
        select(HuntingMatch)
        .where(*conditions)
        .order_by(
            _SEVERITY_RANK.desc(), HuntingMatch.rule_id, HuntingMatch.observable, HuntingMatch.id
        )
        .limit(limit)
        .offset(offset)
    )
    return MatchPage(items=list(rows.scalars().all()), total=total, by_rule=by_rule)


async def list_hunts(session: AsyncSession, *, limit: int, offset: int) -> list[HuntingSession]:
    rows = await session.execute(
        select(HuntingSession)
        .order_by(HuntingSession.started_at.desc(), HuntingSession.id)
        .limit(limit)
        .offset(offset)
    )
    return list(rows.scalars().all())


async def hunt_due(session: AsyncSession, *, interval_seconds: int, now: datetime) -> bool:
    state = await session.get(CollectorState, HUNT_STATE)
    last = None if state is None else state.last_success_at
    if last is not None and last.tzinfo is None:
        last = last.replace(tzinfo=UTC)
    return last is None or last + timedelta(seconds=interval_seconds) <= now


async def mark_hunt_attempt(session: AsyncSession, now: datetime) -> None:
    state = await session.get(CollectorState, HUNT_STATE)
    if state is None:
        state = CollectorState(name=HUNT_STATE, items=0)
        session.add(state)
    state.last_success_at = now
    await session.flush()
