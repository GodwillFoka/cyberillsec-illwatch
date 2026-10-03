"""Moteur CVE — synchronisation, recalcul du score et alerting (phase 3, ADR-007).

    KEV (catalogue complet) → NVD (hasKev à la 1re synchro, puis fenêtres incrémentales)
    → EPSS (toutes les CVE suivies) → recalcul du score des CVE touchées → alertes

Règles :

- **Recalcul systématique (tâche 2.3)** : toute CVE dont une entrée change (CVSS, exploit,
  KEV, ransomware, EPSS) voit son score et sa priorité recalculés par `compute_risk_breakdown`
  (ADR-001). Un changement de priorité est historisé avec l'ancien/nouveau score et la source.
- **Alerte (tâche 2.5)** : quand une CVE **franchit** `RISK_ALERT_THRESHOLD` vers le haut
  (ou apparaît au-dessus). Rester au-dessus ne réalerte pas.
- **Ligne de base** : la toute première synchronisation n'émet aucune alerte. Sans cette
  règle, l'import initial du catalogue KEV produirait des centaines d'alertes le premier
  jour, et l'astreinte apprendrait à les ignorer. Les CVE critiques restent visibles par
  `GET /api/v1/cves?priority=P0_CRITIQUE`.
- **Reprise** : le curseur NVD n'avance qu'après le succès complet d'une fenêtre ; chaque
  page est validée en base (une interruption ne perd que la page en cours).
"""

import logging
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, time, timedelta

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app.config import Settings
from sentry.app.models import CVE, CollectorState, CVEAlert, CVEPriorityChange
from sentry.modules.cve_tracker.scoring import compute_risk_breakdown
from sentry.modules.cve_tracker.sources import (
    HeaderFetcher,
    KevEntry,
    NvdPage,
    Sleep,
    fetch_epss,
    fetch_nvd,
    nvd_windows,
    parse_kev,
)
from sentry.modules.threat_feeds.fetcher import FetchError
from sentry.modules.threat_feeds.secrets import mask_secrets
from sentry.shared.logging import peak_rss_mb

log = logging.getLogger("sentry.cve")

BASELINE_STATE = "cve_baseline"
ATTEMPT_STATE = "cve_sync"  # dernière tentative (réussie ou non) : cadence du worker
_CHUNK = 500

Clock = Callable[[], datetime]


@dataclass(slots=True)
class SyncReport:
    kev: int = 0
    nvd: int = 0
    epss: int = 0
    created: int = 0
    rescored: int = 0
    priority_changes: int = 0
    alerts: int = 0
    baseline: bool = False
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def succeeded(self) -> bool:
        return not self.errors


def _utc(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


async def _state(session: AsyncSession, name: str) -> CollectorState:
    state = await session.get(CollectorState, name)
    if state is None:
        state = CollectorState(name=name, items=0)
        session.add(state)
        await session.flush()
    return state


# --- Écritures ------------------------------------------------------------------


async def _load(session: AsyncSession, ids: Iterable[str]) -> dict[str, CVE]:
    wanted = list(dict.fromkeys(ids))
    found: dict[str, CVE] = {}
    for start in range(0, len(wanted), _CHUNK):
        rows = await session.execute(select(CVE).where(CVE.id.in_(wanted[start : start + _CHUNK])))
        found.update({c.id: c for c in rows.scalars()})
    return found


async def apply_nvd_page(session: AsyncSession, page: NvdPage, touched: dict[str, str]) -> set[str]:
    """Insère ou met à jour les CVE d'une page NVD. Retourne les identifiants créés."""
    existing = await _load(session, (r.id for r in page.records))
    created: set[str] = set()
    for record in page.records:
        cve = existing.get(record.id)
        if cve is None:
            cve = CVE(id=record.id, is_kev=False, has_ransomware_campaign=False)
            session.add(cve)
            existing[record.id] = cve  # doublon éventuel dans la même page
            created.add(record.id)
        cve.description = record.description or cve.description or record.id
        cve.published_date = record.published
        cve.last_modified_date = record.last_modified
        cve.cvss_score = record.cvss_score
        cve.cvss_vector = record.cvss_vector
        cve.has_public_exploit = record.has_public_exploit
        if record.kev_date_added is not None:  # NVD recopie les champs KEV de la CISA
            cve.is_kev = True
            cve.kev_date_added = cve.kev_date_added or record.kev_date_added
            cve.kev_due_date = cve.kev_due_date or record.kev_due_date
            cve.kev_required_action = cve.kev_required_action or record.kev_required_action
        touched.setdefault(record.id, "nvd")
    await session.flush()
    return created


async def apply_kev(
    session: AsyncSession, catalog: dict[str, KevEntry], touched: dict[str, str]
) -> set[str]:
    """Aligne le statut KEV sur le catalogue. Retourne les identifiants des CVE créées.

    Une CVE du catalogue encore inconnue est créée avec les informations de la CISA ; la
    synchronisation NVD la complète (CVSS, références). Une CVE retirée du catalogue perd
    son statut KEV (cas rare, mais la CISA corrige parfois des erreurs).
    """
    existing = await _load(session, catalog)
    created: set[str] = set()
    for entry in catalog.values():
        cve = existing.get(entry.id)
        if cve is None:
            moment = datetime.combine(entry.date_added, time(), tzinfo=UTC)
            cve = CVE(
                id=entry.id,
                description=entry.description or entry.id,
                published_date=moment,
                last_modified_date=moment,
                has_public_exploit=False,
            )
            session.add(cve)
            created.add(entry.id)
        changed = (
            not cve.is_kev
            or cve.has_ransomware_campaign != entry.ransomware
            or cve.kev_due_date != entry.due_date
        )
        cve.is_kev = True
        cve.kev_date_added = entry.date_added
        cve.kev_due_date = entry.due_date
        cve.kev_required_action = entry.required_action
        cve.has_ransomware_campaign = entry.ransomware
        if changed or entry.id in created:
            touched[entry.id] = "kev"

    removed = await session.execute(
        select(CVE.id).where(CVE.is_kev.is_(True), CVE.id.not_in(list(catalog)))
    )
    removed_ids = list(removed.scalars())
    if removed_ids:
        await session.execute(
            update(CVE)
            .where(CVE.id.in_(removed_ids))
            .values(is_kev=False, has_ransomware_campaign=False)
            .execution_options(synchronize_session="fetch")
        )
        for cve_id in removed_ids:
            touched[cve_id] = "kev"
    await session.flush()
    return created


# --- Recalcul et alertes ---------------------------------------------------------


async def rescore(
    session: AsyncSession,
    touched: dict[str, str],
    *,
    settings: Settings,
    alerts_enabled: bool,
    report: SyncReport,
    new_ids: set[str] | None = None,
) -> None:
    """Recalcule score et priorité des CVE touchées ; historise ; crée les alertes."""
    fresh = new_ids or set()
    threshold = settings.risk_alert_threshold
    cves = await _load(session, touched)
    for cve_id, reason in touched.items():
        cve = cves.get(cve_id)
        if cve is None:
            continue
        breakdown = compute_risk_breakdown(
            cvss=None if cve.cvss_score is None else float(cve.cvss_score),
            epss=None if cve.epss_score is None else float(cve.epss_score),
            is_kev=cve.is_kev,
            has_public_exploit=cve.has_public_exploit,
            has_ransomware_campaign=cve.has_ransomware_campaign,
        )
        is_new = cve_id in fresh
        old_score = None if is_new else float(cve.composite_risk_score or 0)
        old_priority = None if is_new else cve.priority
        report.rescored += 1
        cve.composite_risk_score = breakdown.total
        cve.priority = breakdown.priority

        if old_priority != breakdown.priority:
            report.priority_changes += 1
            session.add(
                CVEPriorityChange(
                    cve_id=cve_id,
                    old_priority=old_priority,
                    new_priority=breakdown.priority,
                    old_score=old_score,
                    new_score=breakdown.total,
                    reason=reason,
                )
            )
        crossed = breakdown.total >= threshold and (old_score is None or old_score < threshold)
        if crossed and alerts_enabled:
            report.alerts += 1
            session.add(
                CVEAlert(
                    cve_id=cve_id,
                    score=breakdown.total,
                    previous_score=old_score,
                    priority=breakdown.priority,
                    reason=reason,
                    delivery_attempts=0,
                )
            )
            log.warning(
                "cve.alert",
                extra={
                    "fields": {
                        "cve": cve_id,
                        "score": breakdown.total,
                        "previous_score": old_score,
                        "priority": str(breakdown.priority),
                        "reason": reason,
                    }
                },
            )
    await session.flush()


# --- Orchestration ---------------------------------------------------------------


async def sync_cves(
    session: AsyncSession,
    *,
    settings: Settings,
    fetch: HeaderFetcher,
    sleep: Sleep,
    clock: Clock = lambda: datetime.now(UTC),
    steps: tuple[str, ...] = ("kev", "nvd", "epss"),
    on_progress: Callable[[], Awaitable[None]] | None = None,
) -> SyncReport:
    """Synchronisation complète. Une source en échec n'empêche pas les autres (RSK-02).

    `on_progress` est appelé après chaque étape et chaque page NVD (validation en base par
    l'appelant) ; par défaut, `session.commit`.
    """
    commit = on_progress or session.commit
    report = SyncReport()
    now = clock()
    baseline = await _state(session, BASELINE_STATE)
    alerts_enabled = baseline.last_success_at is not None
    report.baseline = not alerts_enabled

    async def _step(name: str, work: Callable[[], Awaitable[int]]) -> None:
        state = await _state(session, name)
        try:
            state.items = await work()
            state.last_success_at = clock()
            state.last_error = None
        except Exception as exc:  # noqa: BLE001 - RSK-02 : une source ne bloque pas les autres
            await session.rollback()
            state = await _state(session, name)
            message = mask_secrets(f"{type(exc).__name__} : {exc}", settings)[:1000]
            state.last_error = report.errors[name] = message
            log.error("cve.sync_failed", extra={"fields": {"source": name, "error": message}})
        await commit()

    async def _kev() -> int:
        catalog = parse_kev(await fetch(settings.kev_catalog_url, headers=None))
        touched: dict[str, str] = {}
        created = await apply_kev(session, catalog, touched)
        report.created += len(created)
        await rescore(
            session,
            touched,
            settings=settings,
            alerts_enabled=alerts_enabled,
            report=report,
            new_ids=created,
        )
        report.kev = len(catalog)
        return len(catalog)

    async def _nvd() -> int:
        state = await _state(session, "nvd")
        cursor = _utc(state.cursor)
        received = 0

        async def _page(page: NvdPage) -> None:
            touched: dict[str, str] = {}
            created = await apply_nvd_page(session, page, touched)
            report.created += len(created)
            await rescore(
                session,
                touched,
                settings=settings,
                alerts_enabled=alerts_enabled,
                report=report,
                new_ids=created,
            )
            await commit()

        if cursor is None:  # première synchro : toutes les CVE KEV, quelle que soit leur date
            try:
                received += await fetch_nvd(settings, fetch, sleep, has_kev=True, on_page=_page)
            except FetchError as exc:
                # Filtre `hasKev` refusé : les CVE KEV restent créées depuis le catalogue
                # (sans CVSS) et seront complétées à leur prochaine modification NVD.
                log.warning(
                    "cve.nvd_haskev_unavailable",
                    extra={"fields": {"error": mask_secrets(str(exc), settings)[:500]}},
                )
            cursor = now - timedelta(days=settings.nvd_initial_days)
        for window in nvd_windows(cursor, now):
            received += await fetch_nvd(settings, fetch, sleep, window=window, on_page=_page)
            state = await _state(session, "nvd")
            state.cursor = window[1]
            await commit()
        report.nvd = received
        return received

    async def _epss() -> int:
        ids = list((await session.execute(select(CVE.id).order_by(CVE.id))).scalars())
        scores = await fetch_epss(settings, fetch, sleep, ids)
        cves = await _load(session, scores)
        touched: dict[str, str] = {}
        for cve_id, entry in scores.items():
            cve = cves.get(cve_id)
            if cve is None:
                continue
            if cve.epss_score is None or abs(float(cve.epss_score) - entry.score) >= 0.0001:
                touched[cve_id] = "epss"
            cve.epss_score = round(entry.score, 4)
            cve.epss_percentile = round(entry.percentile, 4)
        await session.flush()
        await rescore(
            session, touched, settings=settings, alerts_enabled=alerts_enabled, report=report
        )
        report.epss = len(scores)
        return len(scores)

    work = {"kev": _kev, "nvd": _nvd, "epss": _epss}
    for name in steps:
        await _step(name, work[name])

    if report.succeeded and not alerts_enabled and set(steps) >= {"kev", "nvd", "epss"}:
        baseline = await _state(session, BASELINE_STATE)
        baseline.last_success_at = clock()
        await commit()

    log.info(
        "cve.synced",
        extra={
            "fields": {
                "kev": report.kev,
                "nvd": report.nvd,
                "epss": report.epss,
                "created": report.created,
                "rescored": report.rescored,
                "priority_changes": report.priority_changes,
                "alerts": report.alerts,
                "baseline": report.baseline,
                "errors": report.errors or None,
                "peak_rss_mb": peak_rss_mb(),
            }
        },
    )
    return report


async def cve_sync_due(session: AsyncSession, *, interval_seconds: int, now: datetime) -> bool:
    """Vrai si la dernière tentative de synchronisation date de plus de `interval_seconds`."""
    state = await session.get(CollectorState, ATTEMPT_STATE)
    last = None if state is None else _utc(state.last_success_at)
    return last is None or last + timedelta(seconds=interval_seconds) <= now


async def mark_cve_sync_attempt(session: AsyncSession, now: datetime) -> None:
    state = await _state(session, ATTEMPT_STATE)
    state.last_success_at = now
    await session.flush()
