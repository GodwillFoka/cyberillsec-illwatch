"""CLI `sentry audit` — consultation du journal d'audit de sécurité (M7, ADR-011).

sentry audit list                          # 30 dernières actions
sentry audit list --action auth. --outcome FAILURE --since 24
"""

import asyncio
from datetime import UTC, datetime, timedelta

import click
from rich.console import Console
from rich.table import Table

from sentry.modules.foundation.audit import list_audit_events
from sentry.shared.enums import AuditOutcome

console = Console()

_COLORS = {"SUCCESS": "green", "FAILURE": "yellow", "DENIED": "red"}


@click.group()
def audit() -> None:
    """Journal d'audit : connexions, administration, exports, refus d'accès."""


@audit.command("list")
@click.option("--action", help="Préfixe d'action : auth., feed., data.export…")
@click.option("--actor", help="Nom de l'acteur (insensible à la casse).")
@click.option("--outcome", type=click.Choice([o.value for o in AuditOutcome]))
@click.option("--since", "hours", type=click.IntRange(1, 24 * 365), help="Dernières N heures.")
@click.option("--limit", type=click.IntRange(1, 500), default=30, show_default=True)
def audit_list(
    action: str | None, actor: str | None, outcome: str | None, hours: int | None, limit: int
) -> None:
    """Dernières actions consignées, les plus récentes d'abord."""
    from sentry.app.database import dispose_engine, get_session_factory

    since = datetime.now(UTC) - timedelta(hours=hours) if hours else None

    async def _load() -> tuple[list[tuple[str, ...]], int]:
        try:
            async with get_session_factory()() as session:
                rows, total = await list_audit_events(
                    session,
                    action=action,
                    actor=actor,
                    outcome=AuditOutcome(outcome) if outcome else None,
                    since=since,
                    limit=limit,
                )
                return [
                    (
                        f"{r.occurred_at:%Y-%m-%d %H:%M:%S}",
                        r.action,
                        r.outcome,
                        r.actor_name or "—",
                        f"{r.target_type}:{r.target_id}" if r.target_type else "—",
                        r.ip or "—",
                    )
                    for r in rows
                ], total
        finally:
            await dispose_engine()

    rows, total = asyncio.run(_load())
    table = Table(title=f"Journal d'audit ({len(rows)} sur {total})")
    for column in ("Date (UTC)", "Action", "Issue", "Acteur", "Cible", "IP"):
        table.add_column(column)
    for when, act, out, who, target, ip in rows:
        color = _COLORS.get(out, "white")
        table.add_row(when, act, f"[{color}]{out}[/]", who, target, ip)
    console.print(table)
