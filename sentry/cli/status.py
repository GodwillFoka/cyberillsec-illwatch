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
    """Affiche l'état réel : migrations, sources, IOC, CVE et critères des jalons M2 et M3."""
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
    iocs.add_row("Confirmés par ≥ 2 sources", str(state.iocs_multi_source))
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

    cves = Table(title="Vulnérabilités (CVE)", show_header=False)
    cves.add_row("Total", str(state.cves_total))
    for name in ("P0_CRITIQUE", "P1_ELEVE", "P2_MOYEN", "P3_FAIBLE"):
        cves.add_row(f"  {name}", str(state.cves_by_priority.get(name, 0)))
    cves.add_row("Catalogue KEV", str(state.cves_kev))
    cves.add_row("Avec score EPSS", str(state.cves_with_epss))
    cves.add_row("Alertes / non acquittées", f"{state.alerts_total} / {state.alerts_open}")
    console.print(cves)

    m3 = Table(title="Jalon M3 — Moteur CVE & alerting")
    m3.add_column("Critère")
    m3.add_column("État")
    m3.add_column("Constat")
    for criterion in state.m3:
        m3.add_row(
            criterion.label, "[green]✔[/]" if criterion.met else "[red]✘[/]", criterion.detail
        )
    console.print(m3)
    verdict = "[green]atteint[/]" if state.m3_reached else "[yellow]non atteint[/]"
    console.print(f"Jalon M3 : {verdict}")
    for warning in state.warnings:
        console.print(f"[yellow]⚠ {warning}[/]")

    later = Table(title="Jalons M4 et M6 — Incidents et threat hunting")
    later.add_column("Critère")
    later.add_column("État")
    later.add_column("Constat")
    for criterion in state.later:
        later.add_row(
            criterion.label, "[green]✔[/]" if criterion.met else "[red]✘[/]", criterion.detail
        )
    console.print(later)
