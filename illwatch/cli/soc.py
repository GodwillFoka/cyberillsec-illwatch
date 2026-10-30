"""`illwatch soc` : pilotage du SOC et liste d'exclusion (M9, ADR-022).

illwatch soc metrics --days 30          # MTTA, MTTR, délais cibles, niveaux, charge
illwatch soc quality --days 30          # qualité des alertes par règle et par source (ADR-029)
illwatch soc exclude 203.0.113.7 --reason "Résolveur public de l'entreprise"
illwatch soc exclusions                 # liste d'exclusion en vigueur
"""

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

import click
from rich.console import Console
from rich.table import Table

console = Console()


def _run[T](work: Callable[[Any], Awaitable[T]]) -> T:
    from illwatch.app.database import dispose_engine, get_session_factory

    async def _main() -> T:
        try:
            async with get_session_factory()() as session:
                result = await work(session)
                await session.commit()
                return result
        finally:
            await dispose_engine()

    return asyncio.run(_main())


def _hours(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{value:.1f} h".replace(".", ",") if value >= 1 else f"{value * 60:.0f} min"


def _pct(value: float | None) -> str:
    return "-" if value is None else f"{value * 100:.0f} %"


@click.group()
def soc() -> None:
    """Pilotage du SOC (MTTA, MTTR, délais cibles) et faux positifs."""


@soc.command("metrics")
@click.option("--days", type=click.Choice(["7", "30"]), default="7", show_default=True)
def soc_metrics_command(days: str) -> None:
    """Délais de prise en charge et de résolution, dépassements, niveaux, charge."""
    from illwatch.app.models import User
    from illwatch.modules.soc.metrics import soc_metrics
    from illwatch.shared.enums import UserRole

    viewer = User(username="cli", email="cli@localhost", role=UserRole.ADMIN, hashed_password="")
    metrics = _run(lambda session: soc_metrics(session, viewer=viewer, days=int(days)))
    mtta = None if metrics.mtta_minutes is None else metrics.mtta_minutes / 60
    console.print(
        f"[bold]Pilotage SOC: {metrics.window_days} jours[/] · ouverts {metrics.opened} · "
        f"clos {metrics.closed} · en cours {metrics.open_now}"
    )
    console.print(
        f"MTTA {_hours(mtta)} · MTTR {_hours(metrics.mttr_hours)} "
        f"(médiane {_hours(metrics.median_ttr_hours)})"
    )
    table = Table(title="Par sévérité")
    for column in (
        "Sévérité",
        "Ouverts",
        "Clos",
        "MTTA",
        "Cible",
        "Dans le délai",
        "MTTR",
        "Cible",
        "Dans le délai",
    ):
        table.add_column(column)
    for row in metrics.by_severity:
        table.add_row(
            row.severity,
            str(row.opened),
            str(row.closed),
            _hours(None if row.mtta_minutes is None else row.mtta_minutes / 60),
            f"{row.ack_sla_hours} h",
            _pct(row.ack_within_sla),
            _hours(row.mttr_hours),
            f"{row.resolution_sla_hours} h",
            _pct(row.resolved_within_sla),
        )
    console.print(table)
    tiers = " · ".join(f"{k} {v}" for k, v in metrics.open_by_tier.items())
    steps = " · ".join(f"{k} : {v}" for k, v in metrics.escalations.items()) or "aucune"
    console.print(f"En cours par niveau : {tiers}, escalades : {steps}")
    for breach in metrics.breaches:
        console.print(
            f"[red]Dépassement[/] {breach.kind} · {breach.severity} · {breach.tier} · "
            f"{breach.title} ({breach.age_hours:.0f} h / cible {breach.target_hours} h)"
        )


@soc.command("quality")
@click.option("--days", type=click.Choice(["7", "30", "90"]), default="30", show_default=True)
def soc_quality_command(days: str) -> None:
    """Qualité des alertes en situation réelle : issue des signaux par règle et par source."""
    from illwatch.modules.soc.quality import alert_quality

    report = _run(lambda session: alert_quality(session, days=int(days)))
    total = report.total
    console.print(
        f"[bold]Qualité des alertes : {report.window_days} jours[/] · {total.signals} signaux · "
        f"précision {_pct(total.precision)} · bruit {_pct(total.noise)} · "
        f"traitement médian {_hours(total.handling_hours_median)}"
    )
    table = Table(title="Par règle ou déclencheur")
    for column in (
        "Règle",
        "Libellé",
        "Signaux",
        "Confirmés",
        "Faux positifs",
        "Ignorés",
        "Clos (moteur)",
        "En attente",
        "Précision",
        "Bruit",
        "Traitement médian",
    ):
        table.add_column(column)
    for row in report.rules:
        table.add_row(
            row.key,
            row.label,
            str(row.signals),
            str(row.confirmed),
            str(row.false_positive),
            str(row.ignored),
            str(row.auto_closed),
            str(row.pending),
            _pct(row.precision),
            _pct(row.noise),
            _hours(row.handling_hours_median),
        )
    console.print(table)
    sources = Table(title="Par source d'IOC")
    for column in ("Source", "Fiabilité", "IOC déclencheurs", "Confirmés", "Exclus", "Précision"):
        sources.add_column(column)
    for src in report.sources:
        sources.add_row(
            src.name,
            src.reliability or "-",
            str(src.triggered),
            str(src.confirmed),
            str(src.false_positive),
            _pct(src.precision),
        )
    console.print(sources)
    console.print(
        "Précision : confirmés / (confirmés + faux positifs). "
        "Bruit : (faux positifs + ignorés) / signaux traités par un analyste."
    )


@soc.command("exclude")
@click.argument("value")
@click.option("--reason", required=True, help="Pourquoi cette valeur est sûre.")
@click.option("--days", type=int, default=None, help="Réexamen après N jours.")
def soc_exclude(value: str, reason: str, days: int | None) -> None:
    """Met une valeur en liste d'exclusion (faux positif) : l'IOC cesse d'être actif."""
    from illwatch.modules.foundation.audit import cli_actor, record_in_session
    from illwatch.modules.soc.exclusions import ExclusionError, create_exclusion

    async def _work(session: Any) -> str:
        exclusion = await create_exclusion(
            session, value=value, reason=reason, author_id=None, days=days
        )
        await record_in_session(
            session,
            "exclusion.create",
            actor_name=cli_actor(),
            target_type="exclusion",
            target_id=exclusion.id,
            detail={"type": exclusion.indicator_type, "value": exclusion.value[:200]},
        )
        return exclusion.value

    try:
        excluded = _run(_work)
    except ExclusionError as exc:
        raise click.ClickException(str(exc)) from exc
    console.print(f"[green]✔[/] {excluded} exclu : il n'est plus actif.")


@soc.command("exclusions")
def soc_exclusions() -> None:
    """Liste d'exclusion en vigueur."""
    from illwatch.modules.soc.exclusions import list_exclusions

    rows = _run(lambda session: list_exclusions(session))
    if not rows:
        console.print("Liste d'exclusion vide.")
        return
    table = Table(title=f"Liste d'exclusion ({len(rows)})")
    for column in ("Type", "Valeur", "Motif", "Depuis", "Expire"):
        table.add_column(column)
    for e in rows:
        table.add_row(
            e.indicator_type,
            e.value,
            e.reason[:80],
            f"{e.created_at:%d/%m/%Y}",
            f"{e.expires_at:%d/%m/%Y}" if e.expires_at else "jamais",
        )
    console.print(table)
