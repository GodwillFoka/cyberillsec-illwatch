"""CLI `sentry hunt` — threat hunting (phase 6, RF-25 à RF-28).

    sentry hunt rules                                    # catalogue
    sentry hunt run                                      # chasse sur la base d'IOC
    sentry hunt run --observables firewall-ips.txt       # chasse sur des observables
    sentry hunt run --asset FortiOS --asset Exchange     # RULE-05 sur l'inventaire
    sentry hunt show <session>

Le fichier d'observables contient une valeur par ligne (IP, domaine, URL, hash, e-mail) ;
les lignes vides et les commentaires `#` sont ignorés. Code de sortie 2 si la session trouve
au moins une correspondance CRITICAL (utilisable dans un script d'astreinte).
"""

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path
from uuid import UUID

import click
from rich.console import Console
from rich.table import Table
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app.config import get_settings
from sentry.app.models import HuntingSession
from sentry.modules.threat_feeds.fetcher import fetch_feed_content
from sentry.modules.threat_hunting import engine
from sentry.modules.threat_hunting.rules import CATALOG
from sentry.shared.enums import Severity
from sentry.shared.logging import configure_logging

console = Console()


def _run[T](work: Callable[[AsyncSession], Awaitable[T]]) -> T:
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


@click.group()
def hunt() -> None:
    """Threat hunting : règles de détection appliquées aux observables ou à la base d'IOC."""
    configure_logging(get_settings().log_level)


@hunt.command("rules")
def hunt_rules() -> None:
    """Catalogue des règles (RF-26)."""
    table = Table(title="Règles de threat hunting")
    for column in ("Règle", "Nom", "Sévérité", "Détection"):
        table.add_column(column)
    for rule in CATALOG:
        table.add_row(rule.id, rule.name, rule.severity, rule.description)
    console.print(table)


def _print(h: HuntingSession) -> None:
    console.print(
        f"[bold]Session {h.id}[/] — {h.status} · {h.observables_count} observable(s), "
        f"{h.rejected_count} rejeté(s) · {h.matches_count} correspondance(s)"
    )
    if h.errors:
        console.print(f"[yellow]Erreurs :[/] {h.errors}")
    if not h.matches:
        return
    table = Table(title="Correspondances")
    for column in ("Règle", "Sévérité", "Observable", "Détail"):
        table.add_column(column, overflow="fold")
    for m in h.matches:
        table.add_row(m.rule_id, m.severity, m.observable, m.detail)
    console.print(table)


@hunt.command("run")
@click.option(
    "--observables",
    "observables_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Fichier d'observables (une valeur par ligne). Sans fichier : base d'IOC.",
)
@click.option("--asset", "assets", multiple=True, help="Produit de l'inventaire (répétable).")
@click.option("--rule", "rules", multiple=True, help="Restreindre à une règle (répétable).")
def hunt_run(
    observables_file: Path | None, assets: tuple[str, ...], rules: tuple[str, ...]
) -> None:
    """Lance une session de chasse (RF-27) et affiche ses correspondances (RF-28)."""
    observables = None
    if observables_file is not None:
        lines = observables_file.read_text(encoding="utf-8", errors="replace").splitlines()
        observables = [line.strip() for line in lines if line.strip() and not line.startswith("#")]

    async def _hunt(session: AsyncSession) -> HuntingSession:
        result = await engine.run_hunt(
            session,
            settings=get_settings(),
            fetch=fetch_feed_content,
            observables=observables,
            assets=list(assets),
            rule_ids=list(rules) or None,
        )
        return await engine.get_hunt(session, result.id)

    try:
        result = _run(_hunt)
    except ValueError as exc:
        console.print(f"[red]Refusé :[/] {exc}")
        raise SystemExit(1) from exc
    _print(result)
    if any(m.severity == Severity.CRITICAL for m in result.matches):
        raise SystemExit(2)


@hunt.command("show")
@click.argument("hunt_id")
def hunt_show(hunt_id: str) -> None:
    """Résultats d'une session enregistrée."""
    try:
        identifier = UUID(hunt_id)
    except ValueError as exc:
        raise click.BadParameter(f"identifiant invalide : {hunt_id}") from exc

    async def _show(session: AsyncSession) -> HuntingSession:
        return await engine.get_hunt(session, identifier)

    try:
        _print(_run(_show))
    except engine.HuntNotFoundError as exc:
        console.print(f"[red]Session introuvable :[/] {hunt_id}")
        raise SystemExit(1) from exc
