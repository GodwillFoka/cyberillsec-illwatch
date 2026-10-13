"""`illwatch assets` et `illwatch correlate` — inventaire et corrélation (M8, ADR-020).

    illwatch assets add "Pare-feu siège" --product FortiOS --criticality CRITICAL \\
        --address 198.51.100.10 --domain vpn.example.com
    illwatch assets import inventaire.csv   # nom;produit;editeur;version;criticite;...
    illwatch assets list
    illwatch correlate run                  # une passe maintenant (le worker : chaque heure)
    illwatch correlate list
    illwatch correlate evaluate             # mesure sur le jeu figé (rien n'est écrit)
"""

import asyncio
import csv
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.table import Table

from illwatch.shared.enums import Severity

console = Console()
CRITICALITIES = [s.value for s in Severity]
CSV_COLUMNS = ["nom", "produit", "editeur", "version", "criticite", "adresses", "domaines"]


def _split(value: str | None) -> tuple[str, ...]:
    return tuple(v.strip() for v in (value or "").replace(",", " ").split() if v.strip())


async def _with_session(work: Any) -> Any:
    from illwatch.app.database import dispose_engine, get_session_factory

    try:
        async with get_session_factory()() as session:
            result = await work(session)
            await session.commit()
            return result
    finally:
        await dispose_engine()


@click.group()
def assets() -> None:
    """Inventaire d'actifs : produits, adresses et domaines de l'organisation."""


@assets.command("add")
@click.argument("name")
@click.option("--product", required=True, help="Produit tel que nommé dans les avis (FortiOS).")
@click.option("--vendor", default=None, help="Éditeur (Fortinet).")
@click.option("--version", "version_", default=None, help="Version (information).")
@click.option(
    "--criticality", type=click.Choice(CRITICALITIES), default="MEDIUM", show_default=True
)
@click.option("--address", multiple=True, help="Adresse IP publique de l'actif (répétable).")
@click.option("--domain", multiple=True, help="Domaine de l'actif (répétable).")
def assets_add(
    name: str,
    product: str,
    vendor: str | None,
    version_: str | None,
    criticality: str,
    address: tuple[str, ...],
    domain: tuple[str, ...],
) -> None:
    """Déclare un actif."""
    from illwatch.modules.correlation.assets import AssetError, AssetInput, create_asset
    from illwatch.modules.foundation.audit import cli_actor, record_in_session

    async def _work(session: Any) -> str:
        asset = await create_asset(
            session,
            AssetInput(
                name=name,
                product=product,
                vendor=vendor,
                version=version_,
                criticality=Severity(criticality),
                addresses=address,
                domains=domain,
            ),
        )
        await record_in_session(
            session,
            "asset.create",
            actor_name=cli_actor(),
            target_type="asset",
            target_id=asset.id,
            detail={"name": asset.name, "product": asset.product},
        )
        return asset.name

    try:
        created = asyncio.run(_with_session(_work))
    except AssetError as exc:
        raise click.ClickException(str(exc)) from exc
    console.print(f"[green]✔[/] Actif « {created} » déclaré.")


@assets.command("import")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def assets_import(path: Path) -> None:
    """Importe un inventaire CSV (séparateur « ; »), une ligne par actif.

    Colonnes : nom;produit;editeur;version;criticite;adresses;domaines — adresses et domaines
    séparés par des espaces. Un actif déjà présent (même nom) est mis à jour.
    """
    from illwatch.modules.correlation.assets import (
        AssetError,
        AssetInput,
        create_asset,
        find_asset,
        update_asset,
    )
    from illwatch.modules.foundation.audit import cli_actor, record_in_session

    with path.open(encoding="utf-8-sig", newline="") as handle:
        rows = [
            row
            for row in csv.DictReader(handle, delimiter=";")
            if any((v or "").strip() for v in row.values())
        ]
    missing = [c for c in ("nom", "produit") if rows and c not in rows[0]]
    if missing or not rows:
        raise click.ClickException(
            f"En-tête attendu : {';'.join(CSV_COLUMNS)} (au moins nom et produit)."
        )

    async def _work(session: Any) -> tuple[int, int]:
        created = updated = 0
        for number, row in enumerate(rows, start=2):
            level = (row.get("criticite") or "MEDIUM").strip().upper()
            if level not in CRITICALITIES:
                raise click.ClickException(
                    f"Ligne {number} : criticité « {level} » inconnue ({', '.join(CRITICALITIES)})."
                )
            data = AssetInput(
                name=row.get("nom") or "",
                product=row.get("produit") or "",
                vendor=row.get("editeur") or None,
                version=row.get("version") or None,
                criticality=Severity(level),
                addresses=_split(row.get("adresses")),
                domains=_split(row.get("domaines")),
            )
            try:
                existing = await find_asset(session, data.name)
                if existing is None:
                    await create_asset(session, data)
                    created += 1
                else:
                    await update_asset(session, existing.id, data)
                    updated += 1
            except AssetError as exc:
                raise click.ClickException(f"Ligne {number} : {exc}") from exc
        await record_in_session(
            session,
            "asset.import",
            actor_name=cli_actor(),
            detail={"file": path.name, "created": created, "updated": updated},
        )
        return created, updated

    try:
        created, updated = asyncio.run(_with_session(_work))
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    console.print(f"[green]✔[/] {created} actif(s) créé(s), {updated} mis à jour.")


@assets.command("list")
def assets_list() -> None:
    """Inventaire d'actifs."""
    from illwatch.modules.correlation.assets import list_assets

    async def _work(session: Any) -> list[tuple[str, ...]]:
        return [
            (
                a.name,
                a.product,
                a.criticality,
                " ".join(a.addresses or []),
                " ".join(a.domains or []),
                "oui" if a.is_active else "non",
            )
            for a in await list_assets(session)
        ]

    rows = asyncio.run(_with_session(_work))
    if not rows:
        console.print("Inventaire vide : [bold]illwatch assets add[/] ou [bold]import[/].")
        return
    table = Table(title="Inventaire d'actifs")
    for column in ("Actif", "Produit", "Criticité", "Adresses", "Domaines", "Actif ?"):
        table.add_column(column)
    for row in rows:
        table.add_row(*row)
    console.print(table)


@assets.command("remove")
@click.argument("name")
def assets_remove(name: str) -> None:
    """Supprime un actif et ses évènements corrélés."""
    from illwatch.modules.correlation.assets import delete_asset, find_asset
    from illwatch.modules.foundation.audit import cli_actor, record_in_session

    async def _work(session: Any) -> bool:
        asset = await find_asset(session, name)
        if asset is None:
            return False
        await delete_asset(session, asset.id)
        await record_in_session(
            session,
            "asset.delete",
            actor_name=cli_actor(),
            target_type="asset",
            target_id=asset.id,
            detail={"name": asset.name},
        )
        return True

    if not asyncio.run(_with_session(_work)):
        raise click.ClickException(f"Aucun actif nommé « {name} ».")
    console.print(f"[green]✔[/] Actif « {name} » supprimé.")


@click.group()
def correlate() -> None:
    """Corrélation actifs × CVE × IOC (M8, ADR-020)."""


@correlate.command("run")
def correlate_run() -> None:
    """Lance une passe de corrélation maintenant."""
    from datetime import UTC, datetime

    from illwatch.app.config import get_settings
    from illwatch.modules.correlation.engine import mark_correlation, run_correlation
    from illwatch.modules.foundation.audit import cli_actor, record_in_session

    async def _work(session: Any) -> dict[str, Any]:
        now = datetime.now(UTC)
        report = await run_correlation(
            session, now=now, min_confidence=get_settings().correlation_min_confidence
        )
        await mark_correlation(session, now, report.created + report.updated)
        await record_in_session(
            session, "correlation.run", actor_name=cli_actor(), detail=report.as_dict()
        )
        return report.as_dict()

    report = asyncio.run(_with_session(_work))
    rules = ", ".join(f"{k} : {v}" for k, v in sorted(report["by_rule"].items())) or "aucune"
    console.print(
        f"[green]✔[/] {report['assets']} actif(s) · {report['created']} nouveau(x) · "
        f"{report['updated']} mis à jour · {report['reopened']} rouvert(s) · "
        f"{report['resolved']} clos · règles : {rules}"
    )


@correlate.command("list")
@click.option("--all", "show_all", is_flag=True, help="Inclut les évènements acquittés.")
@click.option("--limit", default=30, show_default=True)
def correlate_list(show_all: bool, limit: int) -> None:
    """Évènements corrélés (ouverts par défaut), les plus graves d'abord."""
    from illwatch.modules.correlation.events import list_events

    async def _work(session: Any) -> tuple[list[tuple[str, ...]], int]:
        page = await list_events(session, limit=limit, offset=0, open_only=not show_all)
        return [
            (e.priority[:2], e.rule_id, f"{float(e.score):.1f}".replace(".", ","), name, e.title)
            for e, name in page.items
        ], page.total

    rows, total = asyncio.run(_with_session(_work))
    if not rows:
        console.print(
            "Aucun évènement corrélé."
            if show_all
            else "Aucun évènement corrélé ouvert "
            "(les acquittés et les clos : illwatch correlate list --all)."
        )
        return
    table = Table(title=f"Évènements corrélés ({total})")
    for column in ("Priorité", "Règle", "Score", "Actif", "Évènement"):
        table.add_column(column)
    for row in rows:
        table.add_row(*row)
    console.print(table)


@correlate.command("evaluate")
@click.option(
    "--report",
    "report_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Écrit aussi le résultat en Markdown (ex. Rapport/M8_mesure.md).",
)
def correlate_evaluate(report_path: Path | None) -> None:
    """Mesure la corrélation sur le jeu figé (base en mémoire, aucune écriture)."""
    from illwatch.app.config import get_settings
    from illwatch.modules.correlation.benchmark import evaluate

    result = asyncio.run(evaluate(min_confidence=get_settings().correlation_min_confidence))
    recall = f"{result.recall * 100:.0f} %"
    fp_rate = f"{result.false_positive_rate * 100:.0f} %"
    console.print(
        f"Jeu {result.version} : {result.cases} cas, {result.expected} évènements attendus, "
        f"{result.produced} produits."
    )
    console.print(f"Détection : {recall} · faux positifs : {fp_rate}")
    for label, items in (("Manqués", result.missed), ("Faux positifs", result.false_positives)):
        for item in items:
            console.print(f"  [red]{label} :[/] {item}")
    if report_path is not None:
        lines = [
            f"# Mesure de la corrélation — jeu {result.version}",
            "",
            "| Mesure | Valeur |",
            "|---|---|",
            f"| Cas (CVE et IOC) | {result.cases} |",
            f"| Évènements attendus | {result.expected} |",
            f"| Évènements produits | {result.produced} |",
            f"| Détection (rappel) | {recall} |",
            f"| Taux de faux positifs | {fp_rate} |",
            "",
            "Détectés :",
            "",
            *[f"- {item}" for item in result.true_positives],
            "",
        ]
        report_path.write_text("\n".join(lines), encoding="utf-8")
        console.print(f"Rapport écrit : {report_path}")
    if result.missed or result.false_positives:
        raise SystemExit(1)
