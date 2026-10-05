"""CLI `sentry cves` — moteur CVE (phase 3, tâche 2.6).

    sentry cves sync [--only kev|nvd|epss]  # synchronisation KEV + NVD + EPSS, recalcul, alertes
    sentry cves list [--priority P0_CRITIQUE] [--kev] [--min-score 60] [--search log4j]
    sentry cves show CVE-2021-44228         # décomposition du score, historique de priorité
    sentry cves alerts [--all]              # alertes non acquittées (toutes avec --all)
    sentry cves import CVE-2024.json.xz --only-known   # NVD 2.0 hors ligne (miroir, archive)

`sync` renvoie 1 si une source a échoué : planifiable par cron, mais `sentry feeds worker`
l'exécute déjà toutes les `CVE_SYNC_INTERVAL_SECONDS` (6 h par défaut).
"""

import asyncio
import gzip
import lzma
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import IO

import click
from rich.console import Console
from rich.table import Table
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app.config import get_settings
from sentry.app.models import CVE, CVEAlert, CVEPriorityChange
from sentry.modules.cve_tracker import queries
from sentry.modules.cve_tracker.alerts import deliver_pending
from sentry.modules.cve_tracker.engine import SyncReport, sync_cves
from sentry.modules.cve_tracker.queries import CVENotFoundError
from sentry.modules.cve_tracker.scoring import compute_risk_breakdown, remediation_sla_hours
from sentry.modules.threat_feeds.fetcher import fetch_feed_content
from sentry.modules.threat_feeds.parsers import FeedParseError
from sentry.shared.enums import RiskPriority
from sentry.shared.logging import configure_logging

console = Console()

_PRIORITY_STYLE = {
    RiskPriority.P0_CRITIQUE: "bold red",
    RiskPriority.P1_ELEVE: "red",
    RiskPriority.P2_MOYEN: "yellow",
    RiskPriority.P3_FAIBLE: "green",
}


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


async def run_cve_sync(session: AsyncSession, steps: tuple[str, ...]) -> SyncReport:
    """Synchronisation + livraison des alertes en attente (partagée avec le worker)."""
    settings = get_settings()
    report = await sync_cves(
        session, settings=settings, fetch=fetch_feed_content, sleep=asyncio.sleep, steps=steps
    )
    await deliver_pending(session, settings=settings)
    return report


@click.group()
def cves() -> None:
    """Vulnérabilités : synchronisation NVD / KEV / EPSS, score de risque, alertes."""
    configure_logging(get_settings().log_level)


@cves.command("sync")
@click.option(
    "--only",
    type=click.Choice(["kev", "nvd", "epss"]),
    multiple=True,
    help="Limiter à certaines sources (répétable). Défaut : les trois.",
)
def cves_sync(only: tuple[str, ...]) -> None:
    """Synchronise KEV, NVD et EPSS, recalcule les scores et émet les alertes."""
    steps = tuple(s for s in ("kev", "nvd", "epss") if not only or s in only)
    console.print(f"Synchronisation : {', '.join(steps)} (NVD sans clé : ≈ 6 s par page)…")

    async def _sync(session: AsyncSession) -> SyncReport:
        return await run_cve_sync(session, steps)

    report = _run(_sync)
    table = Table(title="Synchronisation CVE", show_header=False)
    for label, value in (
        ("Catalogue KEV", report.kev),
        ("CVE reçues du NVD", report.nvd),
        ("Scores EPSS reçus", report.epss),
        ("CVE créées", report.created),
        ("Scores recalculés", report.rescored),
        ("Changements de priorité", report.priority_changes),
        ("Alertes émises", report.alerts),
    ):
        table.add_row(label, str(value))
    console.print(table)
    if report.baseline:
        console.print(
            "[yellow]Première synchronisation (ligne de base) : aucune alerte émise.[/] "
            "Les CVE critiques : `sentry cves list --priority P0_CRITIQUE`."
        )
    for source, error in report.errors.items():
        console.print(f"[red]✗ {source} :[/] {error}")
    if not report.succeeded:
        raise SystemExit(1)


def _open_text(path: Path) -> IO[str]:
    if path.suffix == ".xz":
        return lzma.open(path, "rt", encoding="utf-8")
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8")
    return path.open(encoding="utf-8")


@cves.command("import")
@click.argument(
    "files", nargs=-1, required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path)
)
@click.option(
    "--only-known",
    is_flag=True,
    help="N'importer que les CVE déjà suivies (ex. compléter le CVSS du catalogue KEV).",
)
def cves_import(files: tuple[Path, ...], only_known: bool) -> None:
    """Importe des CVE NVD 2.0 depuis des fichiers (.json, .json.gz, .json.xz).

    Pour un déploiement sans accès à l'API NVD : page de l'API ou flux annuel au format 2.0
    (miroir fkie-cad/nvd-json-data-feeds). Même parseur et même recalcul que `sync`.
    """
    from sentry.modules.cve_tracker.engine import import_nvd_file
    from sentry.modules.cve_tracker.sources import iter_nvd_items

    total = SyncReport()
    for path in files:

        async def _import(session: AsyncSession, path: Path = path) -> SyncReport:
            with _open_text(path) as stream:
                return await import_nvd_file(
                    session,
                    iter_nvd_items(stream),
                    settings=get_settings(),
                    only_known=only_known,
                )

        try:
            report = _run(_import)
        except (FeedParseError, lzma.LZMAError, EOFError, UnicodeDecodeError, OSError) as exc:
            console.print(f"[red]✗ {path.name} :[/] {exc}")
            raise SystemExit(1) from exc
        console.print(
            f"[green]✓[/] {path.name} : {report.nvd} CVE lues, {report.created} créées, "
            f"{report.priority_changes} changement(s) de priorité, {report.alerts} alerte(s)"
        )
        total.nvd += report.nvd
        total.created += report.created
        total.alerts += report.alerts
    console.print(f"Total : {total.nvd} CVE, {total.created} créées, {total.alerts} alerte(s).")


@cves.command("list")
@click.option("--priority", type=click.Choice([p.value for p in RiskPriority]), default=None)
@click.option("--kev", "kev_only", is_flag=True, help="Seulement les CVE du catalogue KEV.")
@click.option("--min-score", type=click.FloatRange(0, 100), default=None)
@click.option("--search", default=None, help="Identifiant ou texte de la description.")
@click.option("--limit", type=click.IntRange(1, 200), default=20, show_default=True)
def cves_list(
    priority: str | None, kev_only: bool, min_score: float | None, search: str | None, limit: int
) -> None:
    """Les CVE les plus risquées d'abord."""

    async def _list(session: AsyncSession) -> queries.Page[CVE]:
        return await queries.list_cves(
            session,
            limit=limit,
            offset=0,
            priority=RiskPriority(priority) if priority else None,
            min_score=min_score,
            is_kev=True if kev_only else None,
            search=search,
        )

    page = _run(_list)
    if not page.items:
        console.print("Aucune CVE. Lancez `sentry cves sync`.")
        return
    table = Table(title=f"CVE ({len(page.items)} sur {page.total})")
    table.add_column("CVE", no_wrap=True)
    for column in ("Score", "Priorité", "CVSS", "EPSS", "KEV", "Exploit", "Ransomware"):
        table.add_column(column)
    for cve in page.items:
        prio = RiskPriority(cve.priority)
        table.add_row(
            cve.id,
            f"{float(cve.composite_risk_score):.1f}",
            f"[{_PRIORITY_STYLE[prio]}]{prio}[/]",
            "—" if cve.cvss_score is None else str(cve.cvss_score),
            "—" if cve.epss_score is None else f"{float(cve.epss_score):.3f}",
            "oui" if cve.is_kev else "",
            "oui" if cve.has_public_exploit else "",
            "oui" if cve.has_ransomware_campaign else "",
        )
    console.print(table)


@cves.command("show")
@click.argument("cve_id")
def cves_show(cve_id: str) -> None:
    """Détail d'une CVE : décomposition du score, délai de remédiation, historique."""

    async def _show(session: AsyncSession) -> tuple[CVE, list[CVEPriorityChange]] | None:
        try:
            cve = await queries.get_cve(session, cve_id)
        except CVENotFoundError:
            return None
        return cve, list(await queries.priority_history(session, cve.id))

    found = _run(_show)
    if found is None:
        console.print(f"[red]{cve_id} introuvable.[/] Lancez `sentry cves sync`.")
        raise SystemExit(1)
    c, history = found  # objets détachés, attributs déjà chargés (expire_on_commit=False)
    prio = RiskPriority(c.priority)
    parts = compute_risk_breakdown(
        cvss=None if c.cvss_score is None else float(c.cvss_score),
        epss=None if c.epss_score is None else float(c.epss_score),
        is_kev=c.is_kev,
        has_public_exploit=c.has_public_exploit,
        has_ransomware_campaign=c.has_ransomware_campaign,
    )
    console.print(
        f"[bold]{c.id}[/] — [{_PRIORITY_STYLE[prio]}]{prio}[/], "
        f"remédiation sous {remediation_sla_hours(prio)} h"
    )
    console.print(c.description)
    table = Table(title="Décomposition du score (ADR-001)", show_header=False)
    for label, value in (
        ("CVSS × 3", parts.cvss_contribution),
        ("EPSS × 25", parts.epss_contribution),
        ("Catalogue KEV", parts.kev_contribution),
        ("Exploit public", parts.exploit_contribution),
        ("Campagne ransomware", parts.attack_contribution),
        ("Total", parts.total),
    ):
        table.add_row(label, f"{value:.2f}")
    console.print(table)
    for h in history:
        console.print(
            f"  {h.changed_at:%Y-%m-%d %H:%M} {h.old_priority or '—'} → "
            f"{h.new_priority} ({h.reason})"
        )


@cves.command("alerts")
@click.option("--all", "show_all", is_flag=True, help="Inclure les alertes acquittées.")
@click.option("--limit", type=click.IntRange(1, 200), default=20, show_default=True)
def cves_alerts(show_all: bool, limit: int) -> None:
    """Alertes de franchissement du seuil de risque."""

    async def _alerts(session: AsyncSession) -> list[CVEAlert]:
        page = await queries.list_alerts(
            session, limit=limit, offset=0, acknowledged=None if show_all else False
        )
        return list(page.items)

    alerts = _run(_alerts)
    if not alerts:
        console.print("Aucune alerte en attente.")
        return
    table = Table(title="Alertes CVE")
    table.add_column("Date")
    table.add_column("CVE", no_wrap=True)
    for column in ("Score", "Priorité", "Déclencheur", "Livrée", "Acquittée"):
        table.add_column(column)
    for a in alerts:
        table.add_row(
            f"{a.created_at:%Y-%m-%d %H:%M}",
            a.cve_id,
            f"{float(a.score):.1f}",
            str(a.priority),
            a.reason,
            "oui" if a.delivered_at else "non",
            "oui" if a.acknowledged_at else "non",
        )
    console.print(table)
