"""CLI `sentry feeds` — T2.7 : gestion et collecte des sources de flux.

    sentry feeds list                  # état de toutes les sources
    sentry feeds add --name … --url … --type CSV [--interval 3600]
    sentry feeds fetch <nom|id>        # collecte immédiate d'une source
    sentry feeds fetch-all [--force]   # sources échues (toutes les actives avec --force)

Code de sortie : 0 si toutes les collectes demandées réussissent, 1 sinon. Une
planification externe (cron, systemd timer) peut donc alerter sur un échec.
"""

import asyncio
from collections.abc import Awaitable, Callable
from uuid import UUID

import click
from rich.console import Console
from rich.table import Table
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app.models import ThreatFeed
from sentry.modules.threat_feeds import collector, service
from sentry.modules.threat_feeds.collector import CollectionReport
from sentry.modules.threat_feeds.fetcher import fetch_feed_content
from sentry.shared.enums import FeedStatus, FeedType

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


@feeds.command("fetch")
@click.argument("reference")
def feeds_fetch(reference: str) -> None:
    """Collecte immédiatement une source, désignée par son nom ou son identifiant."""

    async def _fetch(session: AsyncSession) -> CollectionReport | None:
        feed = await _find_feed(session, reference)
        if feed is None:
            return None
        return await collector.collect_feed(session, feed, fetch=fetch_feed_content)

    report = _run(_fetch)
    if report is None:
        console.print(f"[red]Source introuvable :[/] {reference}")
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
        return await collector.collect_due_feeds(session, force=force, fetch=fetch_feed_content)

    reports = _run(_fetch_all)
    if not reports:
        console.print("Aucune source échue : rien à collecter.")
        return
    _print_reports(reports)
    if not all(r.succeeded for r in reports):
        raise SystemExit(1)
