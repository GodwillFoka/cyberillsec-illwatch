"""CLI `sentry status` — niveau d'avancement mesuré (base, sources, IOC, jalon M2)."""

import asyncio

import click
from rich.console import Console
from rich.table import Table

from sentry import __version__
from sentry.app.config import get_settings

console = Console()


@click.command()
def status() -> None:
    """Affiche l'état réel de l'instance : migrations, sources, IOC et critères du jalon M2."""
    from sentry.app import migrations
    from sentry.app.database import dispose_engine, get_session_factory
    from sentry.modules.foundation.status import ProjectStatus, compute_status

    async def _collect() -> tuple[str | None, ProjectStatus]:
        try:
            current = await migrations.current_revision()
            async with get_session_factory()() as session:
                return current, await compute_status(session)
        finally:
            await dispose_engine()

    try:
        current, state = asyncio.run(_collect())
        head = migrations.head_revision()
    except Exception as exc:  # noqa: BLE001 - diagnostic CLI : l'erreur est affichée
        console.print(f"[red]Base injoignable ou non initialisée :[/] {exc}")
        raise SystemExit(1) from exc

    settings = get_settings()
    console.print(f"[bold cyan]SENTRY[/] v{__version__} · environnement {settings.environment}")
    schema_ok = current == head
    console.print(
        f"Schéma : {'[green]à jour[/]' if schema_ok else '[red]en retard[/]'} "
        f"(appliqué {current or 'aucun'}, cible {head})"
    )

    feeds = Table(title="Sources de flux", show_header=False)
    feeds.add_row("Total / actives", f"{state.feeds_total} / {state.feeds_active}")
    for name in ("HEALTHY", "PENDING", "DEGRADED"):
        feeds.add_row(name, str(state.feeds_by_status.get(name, 0)))
    console.print(feeds)

    iocs = Table(title="Indicateurs (IOC)", show_header=False)
    iocs.add_row("Total", str(state.iocs_total))
    iocs.add_row("Actifs (non expirés)", str(state.iocs_active))
    iocs.add_row("Issus de flux", str(state.iocs_from_feeds))
    for ioc_type, count in state.iocs_by_type.items():
        iocs.add_row(f"  {ioc_type}", str(count))
    console.print(iocs)

    m2 = Table(title="Jalon M2 — Ingestion opérationnelle")
    m2.add_column("Critère")
    m2.add_column("État")
    m2.add_column("Constat")
    for criterion in state.m2:
        m2.add_row(
            criterion.label, "[green]✔[/]" if criterion.met else "[red]✘[/]", criterion.detail
        )
    console.print(m2)
    verdict = "[green]atteint[/]" if state.m2_reached else "[yellow]non atteint[/]"
    console.print(f"Jalon M2 : {verdict}")
