"""CLI `illwatch demo-requests` : demandes reçues du site de présentation (ADR-027, lot S4).

illwatch demo-requests list [--status NEW]
illwatch demo-requests purge [--older-than 365]
"""

import asyncio

import click
from rich.console import Console
from rich.table import Table

from illwatch.modules.sales import demo_requests as service
from illwatch.shared.enums import DemoRequestStatus

console = Console()


@click.group("demo-requests")
def demo_requests() -> None:
    """Demandes de démonstration : consultation et purge (conservation bornée)."""


@demo_requests.command("list")
@click.option("--status", type=click.Choice([s.value for s in DemoRequestStatus]))
@click.option("--limit", type=click.IntRange(1, 200), default=30, show_default=True)
def demo_list(status: str | None, limit: int) -> None:
    """Dernières demandes, les plus récentes d'abord."""
    from illwatch.app.database import dispose_engine, get_session_factory

    async def _load() -> tuple[list[tuple[str, ...]], int]:
        try:
            async with get_session_factory()() as session:
                rows, total = await service.list_requests(
                    session,
                    status=DemoRequestStatus(status) if status else None,
                    limit=limit,
                )
                return [
                    (
                        f"{r.created_at:%Y-%m-%d %H:%M}",
                        r.status,
                        r.interest,
                        r.name,
                        r.organisation,
                        r.email,
                        r.language,
                    )
                    for r in rows
                ], total
        finally:
            await dispose_engine()

    rows, total = asyncio.run(_load())
    table = Table(title=f"Demandes de démonstration ({len(rows)} sur {total})")
    for column in ("Reçue (UTC)", "État", "Objet", "Nom", "Organisation", "E-mail", "Langue"):
        table.add_column(column)
    for row in rows:
        table.add_row(*row)
    console.print(table)


@demo_requests.command("purge")
@click.option(
    "--older-than",
    "days",
    type=click.IntRange(1, 3650),
    default=service.RETENTION_DAYS,
    show_default=True,
    help="Âge en jours au-delà duquel une demande est supprimée.",
)
def demo_purge(days: int) -> None:
    """Supprime les demandes plus anciennes que la durée de conservation."""
    from illwatch.app.database import dispose_engine, get_session_factory

    async def _purge() -> int:
        try:
            async with get_session_factory()() as session:
                count = await service.purge(session, older_than_days=days)
                await session.commit()
                return count
        finally:
            await dispose_engine()

    console.print(f"{asyncio.run(_purge())} demande(s) supprimée(s).")
