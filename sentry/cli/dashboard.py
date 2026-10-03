"""CLI `sentry dashboard` — vue console du SOC et exports (RF-23, RF-24).

sentry dashboard show                     # synthèse + activité des 24 dernières heures
sentry dashboard export cves --format csv -o cves.csv
"""

import asyncio
import json
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import click
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.modules.dashboard.service import (
    COLUMNS,
    ActivityItem,
    DashboardSummary,
    Dataset,
    compute_summary,
    csv_lines,
    export_rows,
    recent_activity,
)

console = Console()


def _run[T](work: Callable[[AsyncSession], Awaitable[T]]) -> T:
    from sentry.app.database import dispose_engine, get_session_factory

    async def _main() -> T:
        try:
            async with get_session_factory()() as session:
                return await work(session)
        finally:
            await dispose_engine()

    return asyncio.run(_main())


def _panel(title: str, rows: list[tuple[str, Any]]) -> Panel:
    table = Table.grid(padding=(0, 2))
    for label, value in rows:
        table.add_row(label, f"[bold]{value}[/]")
    return Panel(table, title=title, expand=True)


@click.group()
def dashboard() -> None:
    """Tableau de bord SOC : synthèse en console et exports JSON / CSV."""


@dashboard.command("show")
@click.option("--hours", type=click.IntRange(1, 168), default=24, show_default=True)
def dashboard_show(hours: int) -> None:
    """Vue console de l'état du SOC (RF-23)."""

    async def _load(session: AsyncSession) -> tuple[DashboardSummary, list[ActivityItem]]:
        return await compute_summary(session), await recent_activity(session, hours=hours)

    summary, activity = _run(_load)
    iocs, cves, inc, alerts, feeds = (
        summary.iocs,
        summary.cves,
        summary.incidents,
        summary.alerts,
        summary.feeds,
    )
    prio = cves["by_priority"]
    mttr = inc["mttr_hours_90d"]
    console.print(
        Columns(
            [
                _panel(
                    "IOC",
                    [
                        ("Actifs", iocs["active"]),
                        ("Nouveaux 24 h", iocs["new_24h"]),
                        ("Confirmés ≥ 2 sources", iocs["multi_source"]),
                    ],
                ),
                _panel(
                    "CVE",
                    [
                        ("P0 / P1", f"{prio['P0_CRITIQUE']} / {prio['P1_ELEVE']}"),
                        ("KEV", cves["kev"]),
                        ("Escaladées 24 h", cves["escalated_24h"]),
                    ],
                ),
                _panel(
                    "Incidents",
                    [
                        ("Ouverts", inc["open"]),
                        ("Ouverts 24 h", inc["opened_24h"]),
                        ("MTTR 90 j", "—" if mttr is None else f"{mttr} h"),
                    ],
                ),
                _panel(
                    "Alertes & sources",
                    [
                        ("Alertes non acquittées", alerts["unacknowledged"]),
                        ("Sources actives", f"{feeds['active']} / {feeds['total']}"),
                        ("Sources dégradées", len(feeds["degraded"])),
                    ],
                ),
            ]
        )
    )
    if feeds["degraded"]:
        console.print("[red]Sources dégradées :[/] " + ", ".join(feeds["degraded"]))
    table = Table(title=f"Activité des {hours} dernières heures ({len(activity)})")
    for column in ("Date", "Type", "Niveau", "Élément"):
        table.add_column(column)
    for item in activity[:25]:
        table.add_row(f"{item.at:%m-%d %H:%M}", item.kind, item.level, item.label)
    console.print(table)


@dashboard.command("export")
@click.argument("dataset", type=click.Choice([d.value for d in Dataset]))
@click.option("--format", "fmt", type=click.Choice(["csv", "json"]), default="csv")
@click.option("-o", "--output", type=click.Path(dir_okay=False, path_type=Path), required=True)
def dashboard_export(dataset: str, fmt: str, output: Path) -> None:
    """Exporte un jeu de données (RF-24) : iocs (actifs), cves, incidents, alerts."""
    kind = Dataset(dataset)

    async def _rows(session: AsyncSession) -> list[dict[str, Any]]:
        return [row async for row in export_rows(session, kind)]

    rows = _run(_rows)
    if fmt == "json":
        output.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    else:
        with output.open("w", encoding="utf-8", newline="") as handle:
            handle.writelines(csv_lines(COLUMNS[kind], rows))
    console.print(f"[green]{len(rows)} ligne(s) exportée(s)[/] → {output}")
