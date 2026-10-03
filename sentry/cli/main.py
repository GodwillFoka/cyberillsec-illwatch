"""CLI SENTRY — RF-03. Point d'entrée `sentry` (Click + Rich)."""

import asyncio

import click
from rich.console import Console
from rich.table import Table

from sentry.app.config import get_settings
from sentry.app.security import MIN_PASSWORD_LENGTH
from sentry.shared.enums import UserRole

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

    secret_keys = {
        "secret_key",
        "nvd_api_key",
        "otx_api_key",
        "abusech_auth_key",
        "taxii_auth",
        "alert_webhook_url",
    }
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


def _run_migration(action: str, revision: str) -> None:
    """Exécute une opération Alembic et convertit toute erreur en code retour non nul."""
    from sentry.app import migrations

    try:
        if action == "upgrade":
            migrations.upgrade(revision)
        else:
            migrations.downgrade(revision)
    except Exception as exc:  # noqa: BLE001 - diagnostic CLI, l'erreur est affichée puis propagée
        console.print(f"[red]Échec de la migration :[/] {exc}")
        raise SystemExit(1) from exc
    console.print(f"[green]Migration {action} → {revision} appliquée.[/]")


@db.command("init")
def db_init() -> None:
    """Initialise le schéma : applique toutes les migrations (alembic upgrade head)."""
    _run_migration("upgrade", "head")


@db.command("upgrade")
@click.argument("revision", default="head")
def db_upgrade(revision: str) -> None:
    """Applique les migrations jusqu'à REVISION (défaut : head)."""
    _run_migration("upgrade", revision)


@db.command("downgrade")
@click.argument("revision")
@click.confirmation_option(prompt="Revenir en arrière peut détruire des données. Continuer ?")
def db_downgrade(revision: str) -> None:
    """Annule les migrations jusqu'à REVISION (ex. -1, base)."""
    _run_migration("downgrade", revision)


@db.command("current")
def db_current() -> None:
    """Affiche la révision appliquée et la révision cible."""
    from sentry.app import migrations
    from sentry.app.database import dispose_engine

    async def _current() -> str | None:
        try:
            return await migrations.current_revision()
        finally:
            await dispose_engine()

    try:
        current = asyncio.run(_current())
        head = migrations.head_revision()
    except Exception as exc:  # noqa: BLE001 - diagnostic CLI
        console.print(f"[red]Échec :[/] {exc}")
        raise SystemExit(1) from exc

    console.print(f"Révision appliquée : [cyan]{current or 'aucune (base vierge)'}[/]")
    console.print(f"Révision cible     : [cyan]{head}[/]")
    if current != head:
        console.print("[yellow]Base en retard : exécutez `sentry db upgrade`.[/]")


@cli.command()
def seed() -> None:
    """Insère les sources de référence (abuse.ch) et corrige les URL obsolètes. Idempotent."""
    from sentry.app.database import dispose_engine, get_session_factory
    from sentry.modules.foundation.seed import seed_reference_feeds

    async def _seed() -> list[str]:
        try:
            async with get_session_factory()() as session:
                created = await seed_reference_feeds(session)
                await session.commit()
                return created
        finally:
            await dispose_engine()

    created = asyncio.run(_seed())
    if created:
        for name in created:
            console.print(f"[green]+[/] {name}")
    else:
        console.print("Données de référence déjà présentes, rien à faire.")


@cli.group()
def users() -> None:
    """Gestion des comptes utilisateurs."""


@users.command("create")
@click.option("--username", required=True, help="Identifiant de connexion.")
@click.option("--email", required=True, help="Adresse e-mail.")
@click.option(
    "--role",
    type=click.Choice([r.value for r in UserRole], case_sensitive=False),
    default=UserRole.ANALYST.value,
    show_default=True,
)
@click.password_option(
    "--password",
    help=f"Mot de passe (≥ {MIN_PASSWORD_LENGTH} caractères). Demandé si absent.",
)
def users_create(username: str, email: str, role: str, password: str) -> None:
    """Crée un compte. Le mot de passe est saisi de façon masquée et confirmé."""
    from sentry.app.database import dispose_engine, get_session_factory
    from sentry.app.security import WeakPasswordError
    from sentry.modules.foundation.users import UserAlreadyExistsError, create_user

    async def _create() -> str:
        try:
            async with get_session_factory()() as session:
                user = await create_user(
                    session,
                    username=username,
                    email=email,
                    password=password,
                    role=UserRole(role.upper()),
                )
                await session.commit()
                return user.username
        finally:
            await dispose_engine()

    try:
        created = asyncio.run(_create())
    except (WeakPasswordError, UserAlreadyExistsError) as exc:
        console.print(f"[red]Refusé :[/] {exc}")
        raise SystemExit(1) from exc
    console.print(f"[green]Compte créé :[/] {created} ({role.upper()})")


def _register_subcommands() -> None:
    from sentry.cli.cves import cves
    from sentry.cli.dashboard import dashboard
    from sentry.cli.feeds import feeds
    from sentry.cli.hunt import hunt
    from sentry.cli.incidents import incidents
    from sentry.cli.status import status
    from sentry.cli.taxii import taxii

    cli.add_command(cves)
    cli.add_command(dashboard)
    cli.add_command(feeds)
    cli.add_command(hunt)
    cli.add_command(incidents)
    cli.add_command(taxii)
    cli.add_command(status)


_register_subcommands()


if __name__ == "__main__":
    cli()
