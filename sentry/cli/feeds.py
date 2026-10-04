"""CLI `sentry feeds` — T2.7 : gestion et collecte des sources de flux.

    sentry feeds list                  # état de toutes les sources
    sentry feeds add --name … --url … --type CSV [--interval 3600]
    sentry feeds fetch <nom|id>        # collecte immédiate d'une source
    sentry feeds fetch-all [--force]   # sources échues (toutes les actives avec --force)
    sentry feeds worker [--tick 60]    # planificateur intégré : collecte en continu
    sentry feeds probe <nom|url>       # collecte d'essai sans écriture (source joignable ?)
    sentry feeds enable|disable <nom>  # activer / suspendre une source

Code de sortie de `fetch` / `fetch-all` : 0 si toutes les collectes demandées réussissent,
1 sinon. Une planification externe (cron, systemd timer) peut donc alerter sur un échec.

Chaque collecte écrit aussi une ligne JSON sur la sortie d'erreur (`feed.collected`) :
`sentry feeds fetch-all 2>> collecte.jsonl` constitue un journal exploitable avec `jq`.
"""

import asyncio
import contextlib
import signal
from collections.abc import Awaitable, Callable
from uuid import UUID

import click
from rich.console import Console
from rich.table import Table
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app.config import get_settings
from sentry.app.models import ThreatFeed
from sentry.modules.threat_feeds import collector, service
from sentry.modules.threat_feeds.collector import CollectionReport
from sentry.modules.threat_feeds.fetcher import fetch_feed_content
from sentry.modules.threat_feeds.locks import FeedLock, open_feed_lock
from sentry.shared.enums import FeedStatus, FeedType
from sentry.shared.logging import configure_logging

console = Console()

_STATUS_STYLE = {
    FeedStatus.HEALTHY: "green",
    FeedStatus.PENDING: "yellow",
    FeedStatus.DEGRADED: "red",
}


def _run[T](work: Callable[[AsyncSession], Awaitable[T]]) -> T:
    """Exécute `work` dans une session, valide la transaction, libère le pool."""
    from sentry.app.database import dispose_engine, get_session_factory

    async def _main() -> T:
        try:
            async with get_session_factory()() as session:
                result = await work(session)
                await session.commit()
                return result
        finally:
            await dispose_engine()

    return asyncio.run(_main())


def _print_reports(reports: list[CollectionReport]) -> None:
    table = Table(title="Collecte des flux")
    for column in ("Flux", "Statut", "Octets", "Lus", "Nouveaux", "Mis à jour", "Rejetés"):
        table.add_column(column, justify="left" if column in ("Flux", "Statut") else "right")
    for r in reports:
        style = _STATUS_STYLE.get(r.status, "white")
        table.add_row(
            r.feed_name,
            f"[{style}]{r.status}[/]",
            str(r.fetched_bytes),
            str(r.parsed),
            str(r.inserted),
            str(r.updated),
            str(r.rejected),
        )
    console.print(table)
    for r in reports:
        if r.warning:
            console.print(f"[yellow]! {r.feed_name} :[/] {r.warning}")
        if r.error:
            console.print(f"[red]✗ {r.feed_name} :[/] {r.error}")
        elif r.rejected_samples:
            console.print(
                f"[yellow]! {r.feed_name} : {r.rejected} valeur(s) rejetée(s), ex. "
                f"{', '.join(r.rejected_samples[:3])}[/]"
            )


@click.group()
def feeds() -> None:
    """Sources de flux de menaces : gestion et collecte."""
    configure_logging(get_settings().log_level)


@feeds.command("list")
def feeds_list() -> None:
    """Affiche toutes les sources et leur état."""

    async def _list(session: AsyncSession) -> list[ThreatFeed]:
        return list(
            (await session.execute(select(ThreatFeed).order_by(func.lower(ThreatFeed.name))))
            .scalars()
            .all()
        )

    rows = _run(_list)
    if not rows:
        console.print("Aucune source. Ajoutez-en avec `sentry feeds add` ou `sentry seed`.")
        return
    table = Table(title="Sources de flux")
    for column in ("Nom", "Format", "Active", "Statut", "Intervalle", "Dernier succès"):
        table.add_column(column)
    for f in rows:
        style = _STATUS_STYLE.get(FeedStatus(f.status), "white")
        last = f.last_successful_run.strftime("%Y-%m-%d %H:%M") if f.last_successful_run else "—"
        table.add_row(
            f.name,
            f.feed_type,
            "oui" if f.is_active else "non",
            f"[{style}]{f.status}[/]",
            f"{f.polling_interval} s",
            last,
        )
    console.print(table)


@feeds.command("add")
@click.option("--name", required=True, help="Nom unique de la source.")
@click.option("--url", required=True, help="URL HTTPS publique du flux.")
@click.option(
    "--type",
    "feed_type",
    required=True,
    type=click.Choice([t.value for t in FeedType], case_sensitive=False),
)
@click.option("--interval", default=3600, show_default=True, help="Intervalle de collecte (s).")
@click.option("--inactive", is_flag=True, help="Enregistrer sans activer la collecte.")
def feeds_add(name: str, url: str, feed_type: str, interval: int, inactive: bool) -> None:
    """Enregistre une nouvelle source (mêmes règles que l'API : HTTPS public, nom unique)."""
    if not service.MIN_POLLING_INTERVAL <= interval <= service.MAX_POLLING_INTERVAL:
        raise click.BadParameter(
            f"entre {service.MIN_POLLING_INTERVAL} et {service.MAX_POLLING_INTERVAL} s",
            param_hint="--interval",
        )

    async def _add(session: AsyncSession) -> ThreatFeed:
        return await service.create_feed(
            session,
            name=name,
            url=url,
            feed_type=FeedType(feed_type.upper()),
            polling_interval=interval,
            is_active=not inactive,
        )

    try:
        feed = _run(_add)
    except (service.UnsafeFeedURLError, service.FeedNameConflictError, ValueError) as exc:
        console.print(f"[red]Refusé :[/] {exc}")
        raise SystemExit(1) from exc
    console.print(f"[green]Source enregistrée :[/] {feed.name} ({feed.id})")


async def _find_feed(session: AsyncSession, reference: str) -> ThreatFeed | None:
    try:
        return await session.get(ThreatFeed, UUID(reference))
    except ValueError:
        pass
    result = await session.execute(
        select(ThreatFeed).where(func.lower(ThreatFeed.name) == reference.strip().lower())
    )
    return result.scalar_one_or_none()


@feeds.command("probe")
@click.argument("reference")
@click.option(
    "--type",
    "feed_type",
    type=click.Choice([t.value for t in FeedType], case_sensitive=False),
    default=None,
    help="Format, obligatoire si REFERENCE est une URL.",
)
def feeds_probe(reference: str, feed_type: str | None) -> None:
    """Vérifie qu'une source répond et produit des IOC, sans rien écrire en base.

    REFERENCE : nom ou identifiant d'une source enregistrée, ou URL (avec --type).
    Code de sortie 0 si la source est exploitable, 1 sinon.
    """
    from sentry.modules.threat_feeds.probe import probe_source

    async def _target(session: AsyncSession) -> tuple[str, FeedType] | None:
        feed = await _find_feed(session, reference)
        return None if feed is None else (feed.url, FeedType(feed.feed_type))

    if reference.startswith(("https://", "http://")):
        if feed_type is None:
            raise click.BadParameter("--type est obligatoire avec une URL.", param_hint="--type")
        target: tuple[str, FeedType] | None = (reference, FeedType(feed_type.upper()))
    else:
        target = _run(_target)
    if target is None:
        console.print(f"[red]Source introuvable :[/] {reference}")
        raise SystemExit(1)

    report = asyncio.run(probe_source(target[0], target[1], settings=get_settings()))
    table = Table(title=f"Sonde — {target[1]}", show_header=False)
    table.add_row("URL", target[0])
    table.add_row("Joignable", "[green]oui[/]" if report.reachable else "[red]non[/]")
    table.add_row("Durée", f"{report.duration_ms} ms")
    table.add_row("Pages lues", f"{report.pages}{' (tronqué)' if report.truncated else ''}")
    table.add_row("Observations / ignorées", f"{report.observations} / {report.skipped}")
    table.add_row(
        "IOC valides par type", ", ".join(f"{k}: {v}" for k, v in report.by_type.items()) or "aucun"
    )
    table.add_row("Valeurs rejetées", str(report.rejected))
    if report.samples:
        table.add_row("Exemples", ", ".join(report.samples))
    console.print(table)
    if report.error:
        console.print(f"[red]✗[/] {report.error}")
    if report.usable:
        console.print("[green]✔ Source exploitable.[/]")
    else:
        if report.reachable and not report.error:
            console.print("[yellow]! Source joignable mais sans IOC exploitable.[/]")
        raise SystemExit(1)


def _set_active(reference: str, active: bool) -> None:
    async def _toggle(session: AsyncSession) -> ThreatFeed | None:
        feed = await _find_feed(session, reference)
        if feed is not None:
            await service.update_feed(session, feed.id, is_active=active)
        return feed

    feed = _run(_toggle)
    if feed is None:
        console.print(f"[red]Source introuvable :[/] {reference}")
        raise SystemExit(1)
    state = "[green]activée[/]" if active else "[yellow]suspendue[/]"
    console.print(f"{feed.name} : {state}")


@feeds.command("enable")
@click.argument("reference")
def feeds_enable(reference: str) -> None:
    """Active la collecte d'une source (nom ou identifiant)."""
    _set_active(reference, True)


@feeds.command("disable")
@click.argument("reference")
def feeds_disable(reference: str) -> None:
    """Suspend la collecte d'une source sans la supprimer (historique conservé)."""
    _set_active(reference, False)


class _Busy:
    """Marqueur : la source est déjà en cours de collecte ailleurs."""


@feeds.command("fetch")
@click.argument("reference")
def feeds_fetch(reference: str) -> None:
    """Collecte immédiatement une source, désignée par son nom ou son identifiant."""

    async def _fetch(session: AsyncSession) -> CollectionReport | _Busy | None:
        feed = await _find_feed(session, reference)
        if feed is None:
            return None
        lock = await open_feed_lock(get_settings().redis_url)
        try:
            token = await lock.acquire(str(feed.id), get_settings().collect_lock_ttl_seconds)
            if token is None:
                return _Busy()
            try:
                return await collector.collect_feed(session, feed, fetch=fetch_feed_content)
            finally:
                await lock.release(str(feed.id), token)
        finally:
            await lock.close()

    report = _run(_fetch)
    if report is None:
        console.print(f"[red]Source introuvable :[/] {reference}")
        raise SystemExit(1)
    if isinstance(report, _Busy):
        console.print(f"[yellow]Collecte déjà en cours ailleurs :[/] {reference}")
        raise SystemExit(1)
    _print_reports([report])
    if not report.succeeded:
        raise SystemExit(1)


@feeds.command("fetch-all")
@click.option(
    "--force", is_flag=True, help="Collecter toutes les sources actives, même non échues."
)
def feeds_fetch_all(force: bool) -> None:
    """Collecte les sources échues. Conçu pour être planifié (cron, timer systemd)."""

    async def _fetch_all(session: AsyncSession) -> list[CollectionReport]:
        lock = await open_feed_lock(get_settings().redis_url)
        try:
            return await collector.collect_due_feeds(
                session, force=force, fetch=fetch_feed_content, lock=lock
            )
        finally:
            await lock.close()

    reports = _run(_fetch_all)
    if not reports:
        console.print("Aucune source échue : rien à collecter.")
        return
    _print_reports(reports)
    if not all(r.succeeded for r in reports):
        raise SystemExit(1)


async def _maybe_sync_cves(lock: FeedLock) -> None:
    """Synchronisation CVE si elle est échue ; un seul worker à la fois (verrou)."""
    from datetime import UTC, datetime

    from sentry.app.database import get_session_factory
    from sentry.cli.cves import run_cve_sync
    from sentry.modules.cve_tracker.engine import cve_sync_due, mark_cve_sync_attempt

    settings = get_settings()
    now = datetime.now(UTC)
    async with get_session_factory()() as session:
        if not await cve_sync_due(
            session, interval_seconds=settings.cve_sync_interval_seconds, now=now
        ):
            return
    # Le verrou couvre toute la synchronisation : NVD sans clé peut durer plusieurs minutes.
    token = await lock.acquire("cve-sync", max(settings.collect_lock_ttl_seconds, 3600))
    if token is None:
        return
    try:
        async with get_session_factory()() as session:
            await mark_cve_sync_attempt(session, now)
            await session.commit()
            await run_cve_sync(session, ("kev", "nvd", "epss"))
            await session.commit()
    finally:
        await lock.release("cve-sync", token)


async def _maybe_hunt(lock: FeedLock) -> None:
    """Chasse planifiée sur la base d'IOC (RF-27), une fois par HUNT_INTERVAL_SECONDS."""
    from datetime import UTC, datetime

    from sentry.app.database import get_session_factory
    from sentry.modules.threat_hunting import engine
    from sentry.shared.enums import HuntTrigger

    settings = get_settings()
    if settings.hunt_interval_seconds == 0:
        return
    now = datetime.now(UTC)
    async with get_session_factory()() as session:
        if not await engine.hunt_due(
            session, interval_seconds=settings.hunt_interval_seconds, now=now
        ):
            return
    token = await lock.acquire("hunt", settings.collect_lock_ttl_seconds)
    if token is None:
        return
    try:
        async with get_session_factory()() as session:
            await engine.mark_hunt_attempt(session, now)
            await engine.run_hunt(
                session, settings=settings, fetch=fetch_feed_content, trigger=HuntTrigger.SCHEDULED
            )
            await session.commit()
    finally:
        await lock.release("hunt", token)


HOUSEKEEPING_STATE = "housekeeping"
HOUSEKEEPING_INTERVAL_SECONDS = 24 * 3600


async def _maybe_housekeeping(lock: FeedLock) -> None:
    """Une fois par jour : purge des sessions périmées, contrôle de fraîcheur d'EPSS (M7 lot 3)."""
    from datetime import UTC, datetime, timedelta

    from sentry.app.database import get_session_factory
    from sentry.app.models import CollectorState
    from sentry.modules.foundation.sessions import purge_refresh_tokens
    from sentry.modules.foundation.status import epss_staleness

    settings = get_settings()
    now = datetime.now(UTC)
    async with get_session_factory()() as session:
        state = await session.get(CollectorState, HOUSEKEEPING_STATE)
        last = None if state is None else state.last_success_at
        if last is not None and last.tzinfo is None:
            last = last.replace(tzinfo=UTC)
        if last is not None and now - last < timedelta(seconds=HOUSEKEEPING_INTERVAL_SECONDS):
            return
    token = await lock.acquire(HOUSEKEEPING_STATE, settings.collect_lock_ttl_seconds)
    if token is None:
        return
    try:
        async with get_session_factory()() as session:
            purged = await purge_refresh_tokens(session, now=now)
            stale, age = await epss_staleness(session, now)
            state = await session.get(CollectorState, HOUSEKEEPING_STATE)
            if state is None:
                state = CollectorState(name=HOUSEKEEPING_STATE, items=0)
                session.add(state)
            state.last_success_at = now
            state.items = purged
            await session.commit()
        collector.log.info("worker.housekeeping", extra={"fields": {"sessions_purged": purged}})
        if stale:
            collector.log.warning(
                "cve.epss_stale",
                extra={
                    "fields": {
                        "age_hours": None if age is None else round(age.total_seconds() / 3600),
                        "impact": "score plafonné à 75 : aucune CVE ne peut atteindre P0",
                    }
                },
            )
    finally:
        await lock.release(HOUSEKEEPING_STATE, token)


async def run_worker(
    *,
    tick_seconds: int,
    max_cycles: int | None = None,
    lock: FeedLock | None = None,
    stop: asyncio.Event | None = None,
    include_cves: bool = True,
    include_hunting: bool = True,
) -> int:
    """Boucle du planificateur : un cycle `collect_due_feeds` toutes les `tick_seconds`,
    et la synchronisation CVE toutes les `CVE_SYNC_INTERVAL_SECONDS` (si `include_cves`).

    Chaque cycle ouvre sa propre session (aucune transaction longue). Un cycle en échec
    (base indisponible…) est journalisé et retenté au cycle suivant : le worker ne meurt
    pas sur une panne passagère. Retourne le nombre de cycles exécutés.
    """
    from sentry.app.database import dispose_engine, get_session_factory
    from sentry.shared.logging import peak_rss_mb

    settings = get_settings()
    stop = stop or asyncio.Event()
    own_lock = lock is None
    active_lock = lock or await open_feed_lock(settings.redis_url)
    cycles = 0
    try:
        while not stop.is_set() and (max_cycles is None or cycles < max_cycles):
            cycles += 1
            try:
                async with get_session_factory()() as session:
                    reports = await collector.collect_due_feeds(
                        session, fetch=fetch_feed_content, lock=active_lock
                    )
                    await session.commit()
                if include_cves:
                    await _maybe_sync_cves(active_lock)
                if include_hunting:
                    await _maybe_hunt(active_lock)
                await _maybe_housekeeping(active_lock)
                collector.log.info(
                    "worker.cycle",
                    extra={
                        "fields": {
                            "cycle": cycles,
                            "collected": len(reports),
                            "failed": sum(1 for r in reports if not r.succeeded),
                            "peak_rss_mb": peak_rss_mb(),
                        }
                    },
                )
            except Exception:  # noqa: BLE001 - le planificateur survit aux pannes passagères
                collector.log.exception("worker.cycle_failed", extra={"fields": {"cycle": cycles}})
            if max_cycles is not None and cycles >= max_cycles:
                break
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=tick_seconds)
    finally:
        if own_lock:
            await active_lock.close()
        await dispose_engine()
    return cycles


@feeds.command("worker")
@click.option(
    "--tick",
    type=click.IntRange(min=5),
    default=None,
    help="Période de réveil en secondes (défaut : WORKER_TICK_SECONDS, 60).",
)
@click.option("--max-cycles", type=click.IntRange(min=1), default=None, hidden=True)
@click.option(
    "--cves/--no-cves",
    default=True,
    show_default=True,
    help="Synchronisation CVE (KEV, NVD, EPSS) toutes les CVE_SYNC_INTERVAL_SECONDS.",
)
@click.option(
    "--hunt/--no-hunt",
    default=True,
    show_default=True,
    help="Chasse planifiée sur la base d'IOC toutes les HUNT_INTERVAL_SECONDS.",
)
def feeds_worker(tick: int | None, max_cycles: int | None, cves: bool, hunt: bool) -> None:
    """Planificateur intégré : collecte en continu les sources échues (T2.6).

    Plusieurs workers peuvent tourner : le verrou Redis par flux empêche qu'un même flux
    soit collecté deux fois en même temps. Arrêt propre par Ctrl+C ou SIGTERM.
    """
    tick_seconds = tick or get_settings().worker_tick_seconds
    console.print(f"[cyan]Worker SENTRY démarré[/] : cycle toutes les {tick_seconds} s.")

    async def _main() -> int:
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            # Windows : add_signal_handler n'existe pas, Ctrl+C lève KeyboardInterrupt.
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, stop.set)
        return await run_worker(
            tick_seconds=tick_seconds,
            max_cycles=max_cycles,
            stop=stop,
            include_cves=cves,
            include_hunting=hunt,
        )

    with contextlib.suppress(KeyboardInterrupt):
        cycles = asyncio.run(_main())
        console.print(f"Worker arrêté après {cycles} cycle(s).")
