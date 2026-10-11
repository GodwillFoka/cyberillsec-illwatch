"""`illwatch demo` — jeu de données de démonstration (préproduction locale, captures).

Valeurs fictives uniquement ; refusé sur une base qui contient déjà des IOC.
"""

import asyncio
import os

import click
from rich.console import Console

console = Console()


@click.group()
def demo() -> None:
    """Données de démonstration fictives (base vide uniquement)."""


@demo.command("load")
@click.option(
    "--users/--no-users",
    default=False,
    help="Crée aussi les comptes admin, analyst, viewer (mot de passe : DEMO_PASSWORD).",
)
def demo_load(users: bool) -> None:
    """Charge IOC, CVE, alertes, incidents et une chasse fictifs, datés autour de maintenant."""
    from illwatch.app.config import get_settings
    from illwatch.app.database import dispose_engine, get_session_factory
    from illwatch.modules.foundation.demo import DemoRefusedError, demo_users, load_demo_data
    from illwatch.modules.foundation.users import (
        UserAlreadyExistsError,
        create_user,
        get_user_by_username,
    )

    password = os.environ.get("DEMO_PASSWORD", "")
    if users and len(password) < 12:
        raise click.ClickException("DEMO_PASSWORD (12 caractères au moins) requis avec --users.")

    async def _load() -> tuple[list[str], object]:
        created: list[str] = []
        try:
            async with get_session_factory()() as session:
                if users:
                    for name, role in demo_users():
                        if await get_user_by_username(session, name) is not None:
                            continue
                        try:
                            await create_user(
                                session,
                                username=name,
                                email=f"{name}@demo.illwatch.test",
                                password=password,
                                role=role,
                            )
                            created.append(f"{name} ({role.value})")
                        except UserAlreadyExistsError:
                            continue
                    await session.flush()
                report = await load_demo_data(session, settings=get_settings())
                await session.commit()
                return created, report
        finally:
            await dispose_engine()

    try:
        created, report = asyncio.run(_load())
    except DemoRefusedError as exc:
        console.print(f"[yellow]Refusé :[/] {exc}")
        raise SystemExit(1) from exc
    for name in created:
        console.print(f"[green]+ compte[/] {name}")
    console.print(f"[green]Démonstration chargée :[/] {report}")
