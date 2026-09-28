"""Cycle de vie des IOC : ingestion dédupliquée et lecture — RF-07, RF-08, T2.5 (ADR-005).

Sémantique des colonnes (fixée par l'ADR-005) :

- ``first_seen`` : plus ancienne observation connue. Elle ne peut que reculer dans le
  temps (une source qui rapporte tardivement une observation ancienne la corrige).
- ``last_seen`` : observation la plus récente ; ne recule jamais.
- ``hit_count`` : nombre d'**ingestions** ayant rapporté l'IOC. Un même IOC répété
  dans un lot compte pour une observation : le lot est dédupliqué avant écriture.
- ``severity`` : la plus haute sévérité jamais rapportée (une source prudente ne doit
  pas faire baisser l'alerte d'une source mieux informée).
- ``expires_at`` : fin de validité opérationnelle, repoussée à chaque ré-observation.
  ``NULL`` = sans expiration. Un IOC expiré est **conservé** (historique, enquêtes),
  il est seulement exclu des vues « actives ».
- ``feed_id`` : première source connue. Une seule colonne ne peut pas représenter
  plusieurs sources ; la provenance multi-sources relève d'une table de liaison future.

Déduplication : garantie par la contrainte ``UNIQUE (type, value)`` et appliquée par un
``INSERT … ON CONFLICT DO UPDATE`` groupé — une seule instruction SQL par paquet, sans
lecture préalable ligne à ligne (RNF-PERF-02 : 1 000 IOC en moins de 5 s).
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import ColumnElement, and_, case, func, or_, select, tuple_
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app.models import Indicator
from sentry.modules.threat_feeds.validators import InvalidIndicatorError, normalize_indicator
from sentry.shared.enums import IndicatorType, Severity

MAX_BATCH_SIZE = 1000
MAX_REJECTION_SAMPLES = 100  # au-delà, seules les valeurs sont comptées (mémoire bornée)
_CHUNK_SIZE = 500  # 500 lignes x 9 colonnes : loin des 32 767 paramètres de PostgreSQL

# Durée de validité par défaut après la dernière observation (ADR-005). Les
# infrastructures réseau changent de mains vite ; un hash reste la preuve d'un fichier.
DEFAULT_TTL: dict[IndicatorType, timedelta | None] = {
    IndicatorType.IPV4: timedelta(days=30),
    IndicatorType.IPV6: timedelta(days=30),
    IndicatorType.URL: timedelta(days=30),
    IndicatorType.DOMAIN: timedelta(days=90),
    IndicatorType.EMAIL: timedelta(days=90),
    IndicatorType.HASH_MD5: None,
    IndicatorType.HASH_SHA1: None,
    IndicatorType.HASH_SHA256: None,
}

SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class IndicatorNotFoundError(LookupError):
    """Aucun IOC ne porte cet identifiant."""


@dataclass(frozen=True, slots=True)
class Observation:
    """Un IOC tel que rapporté par une source, avant normalisation."""

    value: str
    type: IndicatorType | None = None  # si fourni, doit correspondre au type détecté
    severity: Severity = Severity.MEDIUM
    description: str | None = None
    observed_at: datetime | None = None  # défaut : instant de l'ingestion


@dataclass(frozen=True, slots=True)
class Rejection:
    value: str
    reason: str


@dataclass(slots=True)
class IngestResult:
    received: int = 0
    inserted: int = 0
    updated: int = 0
    duplicates_in_batch: int = 0
    rejected_count: int = 0
    rejected: list[Rejection] = field(default_factory=list)  # échantillon, MAX_REJECTION_SAMPLES

    def reject(self, value: str, reason: str) -> None:
        self.rejected_count += 1
        if len(self.rejected) < MAX_REJECTION_SAMPLES:
            self.rejected.append(Rejection(value, reason))


@dataclass(slots=True)
class _Row:
    type: IndicatorType
    value: str
    severity: Severity
    description: str | None
    first_seen: datetime
    last_seen: datetime
    expires_at: datetime | None


@dataclass(frozen=True, slots=True)
class IndicatorPage:
    items: Sequence[Indicator]
    total: int


# --- Préparation du lot --------------------------------------------------------


def _expiry(ioc_type: IndicatorType, last_seen: datetime) -> datetime | None:
    ttl = DEFAULT_TTL[ioc_type]
    return None if ttl is None else last_seen + ttl


def _prepare(
    observations: Iterable[Observation], now: datetime, result: IngestResult
) -> list[_Row]:
    """Normalise, valide et fusionne les doublons du lot (clé = type + valeur normalisée)."""
    rows: dict[tuple[IndicatorType, str], _Row] = {}
    for obs in observations:
        result.received += 1
        try:
            ioc_type, value = normalize_indicator(obs.value)
        except InvalidIndicatorError as exc:
            result.reject(obs.value, str(exc))
            continue
        if obs.type is not None and IndicatorType(obs.type) is not ioc_type:
            result.reject(obs.value, f"Type annoncé {obs.type}, type détecté {ioc_type}.")
            continue

        seen = obs.observed_at or now
        if seen.tzinfo is None:
            seen = seen.replace(tzinfo=UTC)
        seen = min(seen, now)  # une date future est une erreur de source, pas une observation

        key = (ioc_type, value)
        current = rows.get(key)
        if current is None:
            rows[key] = _Row(
                ioc_type, value, obs.severity, obs.description, seen, seen, _expiry(ioc_type, seen)
            )
            continue

        result.duplicates_in_batch += 1
        current.first_seen = min(current.first_seen, seen)
        if seen > current.last_seen:
            current.last_seen = seen
            current.expires_at = _expiry(ioc_type, seen)
        if SEVERITY_RANK[obs.severity] > SEVERITY_RANK[current.severity]:
            current.severity = obs.severity
        current.description = current.description or obs.description
    return list(rows.values())


# --- Écriture ------------------------------------------------------------------


def _rank(column: Any) -> ColumnElement[int]:
    return case(
        *((column == severity.value, rank) for severity, rank in SEVERITY_RANK.items()),
        else_=0,
    )


def _upsert_statement(dialect: str, values: list[dict[str, Any]]) -> Any:
    if dialect == "postgresql":
        stmt: Any = postgresql.insert(Indicator).values(values)
        greatest: Any = func.greatest
        least: Any = func.least
    elif dialect == "sqlite":
        stmt = sqlite.insert(Indicator).values(values)
        greatest, least = func.max, func.min  # max()/min() scalaires à plusieurs arguments
    else:  # pragma: no cover - seules les bases supportées par le projet
        raise NotImplementedError(f"Dialecte non supporté : {dialect}")

    table, new = Indicator.__table__.c, stmt.excluded
    return stmt.on_conflict_do_update(
        index_elements=[table.type, table.value],
        set_={
            "first_seen": least(table.first_seen, new.first_seen),
            "last_seen": greatest(table.last_seen, new.last_seen),
            "hit_count": table.hit_count + 1,
            "severity": case(
                (_rank(new.severity) > _rank(table.severity), new.severity),
                else_=table.severity,
            ),
            "expires_at": case(
                (or_(table.expires_at.is_(None), new.expires_at.is_(None)), None),
                else_=greatest(table.expires_at, new.expires_at),
            ),
            "feed_id": func.coalesce(table.feed_id, new.feed_id),
            "description": func.coalesce(table.description, new.description),
        },
    )


async def ingest_indicators(
    session: AsyncSession,
    observations: Iterable[Observation],
    *,
    feed_id: UUID | None = None,
    now: datetime | None = None,
) -> IngestResult:
    """Ingère un lot d'observations : normalisation, rejet des invalides, déduplication.

    Les valeurs invalides sont **rejetées et listées**, jamais silencieusement ignorées :
    un flux qui se met à produire des déchets doit se voir dans le résultat.
    """
    moment = now or datetime.now(UTC)
    result = IngestResult()
    rows = _prepare(observations, moment, result)
    dialect = session.get_bind().dialect.name

    for start in range(0, len(rows), _CHUNK_SIZE):
        chunk = rows[start : start + _CHUNK_SIZE]
        keys = [(r.type.value, r.value) for r in chunk]
        existing = await session.scalar(
            select(func.count())
            .select_from(Indicator)
            .where(tuple_(Indicator.type, Indicator.value).in_(keys))
        )
        values = [
            {
                "id": uuid4(),
                "type": r.type.value,
                "value": r.value,
                "severity": r.severity.value,
                "description": r.description,
                "first_seen": r.first_seen,
                "last_seen": r.last_seen,
                "expires_at": r.expires_at,
                "hit_count": 1,
                "feed_id": feed_id,
            }
            for r in chunk
        ]
        await session.execute(_upsert_statement(dialect, values))
        result.updated += existing or 0
        result.inserted += len(chunk) - (existing or 0)

    # L'UPSERT contourne l'ORM : les IOC déjà chargés en mémoire sont périmés. Seuls
    # ceux-là sont invalidés ; les autres objets de l'appelant restent intacts.
    for obj in list(session.identity_map.values()):
        if isinstance(obj, Indicator):
            session.expire(obj)
    return result


# --- Lecture -------------------------------------------------------------------


def is_active_clause(now: datetime) -> ColumnElement[bool]:
    return or_(Indicator.expires_at.is_(None), Indicator.expires_at > now)


async def get_indicator(session: AsyncSession, indicator_id: UUID) -> Indicator:
    indicator = await session.get(Indicator, indicator_id, populate_existing=True)
    if indicator is None:
        raise IndicatorNotFoundError(str(indicator_id))
    return indicator


async def list_indicators(
    session: AsyncSession,
    *,
    limit: int,
    offset: int,
    now: datetime | None = None,
    ioc_type: IndicatorType | None = None,
    severity: Severity | None = None,
    min_severity: Severity | None = None,
    feed_id: UUID | None = None,
    active: bool | None = None,
    value: str | None = None,
) -> IndicatorPage:
    """Liste paginée, les plus récemment observés d'abord.

    `value` est normalisée avant la recherche : chercher `Evil[.]COM` trouve `evil.com`.
    """
    moment = now or datetime.now(UTC)
    conditions: list[ColumnElement[bool]] = []
    if ioc_type is not None:
        conditions.append(Indicator.type == ioc_type)
    if severity is not None:
        conditions.append(Indicator.severity == severity)
    if min_severity is not None:
        allowed = [s.value for s, r in SEVERITY_RANK.items() if r >= SEVERITY_RANK[min_severity]]
        conditions.append(Indicator.severity.in_(allowed))
    if feed_id is not None:
        conditions.append(Indicator.feed_id == feed_id)
    if active is not None:
        clause = is_active_clause(moment)
        conditions.append(clause if active else ~clause)
    if value is not None:
        try:
            norm_type, norm_value = normalize_indicator(value)
        except InvalidIndicatorError:
            return IndicatorPage(items=[], total=0)
        conditions.append(and_(Indicator.type == norm_type, Indicator.value == norm_value))

    total = await session.scalar(select(func.count()).select_from(Indicator).where(*conditions))
    result = await session.execute(
        select(Indicator)
        .where(*conditions)
        .order_by(Indicator.last_seen.desc(), Indicator.id)
        .limit(limit)
        .offset(offset)
    )
    return IndicatorPage(items=result.scalars().all(), total=total or 0)
