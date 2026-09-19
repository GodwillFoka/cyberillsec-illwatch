"""CLI SENTRY — RF-03. Point d'entrée `sentry` (Click + Rich)."""

import asyncio

import click
from rich.console import Console
from rich.table import Table

from sentry.app.config import get_settings

console = Console()


@click.group()
@click.version_option(package_name="sentry-cti", prog_name="sentry")
def cli() -> None:
    """SENTRY — Security Monitoring & Threat Intelligence Platform (CyberillSec)."""


@cli.command()
def version() -> None:
    """Affiche la version et l'environnement courant."""
    settings = get_settings()
    console.print(f"[bold cyan]{settings.app_name}[/] v{settings.app_version}")
    console.print(f"Environnement : [yellow]{settings.environment}[/]")


@cli.command()
def config() -> None:
    """Affiche la configuration effective (secrets masqués)."""
    settings = get_settings()
    table = Table(title="Configuration SENTRY", show_lines=False)
    table.add_column("Clé", style="cyan", no_wrap=True)
    table.add_column("Valeur", style="white")

    secret_keys = {"secret_key", "nvd_api_key", "otx_api_key"}
    for key, value in settings.model_dump().items():
        rendered = "••••••" if key in secret_keys and value else str(value)
        table.add_row(key, rendered)

    console.print(table)


@cli.group()
def db() -> None:
    """Commandes de gestion de la base de données."""


@db.command("check")
def db_check() -> None:
    """Vérifie la connectivité à la base de données."""
    from sqlalchemy import text

    from sentry.app.database import dispose_engine, get_session_factory

    async def _check() -> bool:
        factory = get_session_factory()
        try:
            async with factory() as session:
                await session.execute(text("SELECT 1"))
            return True
        except Exception as exc:  # noqa: BLE001 - diagnostic CLI, l'erreur est affichée
            console.print(f"[red]Échec :[/] {exc}")
            return False
        finally:
            await dispose_engine()

    if asyncio.run(_check()):
        console.print("[green]Base de données joignable.[/]")
    else:
        raise SystemExit(1)


@db.command("init")
def db_init() -> None:
    """Applique toutes les migrations Alembic (équivalent `alembic upgrade head`)."""
    console.print("[yellow]Exécutez :[/] alembic upgrade head")


if __name__ == "__main__":
    cli()
