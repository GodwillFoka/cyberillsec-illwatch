"""`illwatch enrich` : enrichissement hors ligne des IP (M8, ADR-017, incrément 2).

- `update` : télécharge et importe les bases DB-IP Lite du mois (pays, système autonome) ;
- `import` : importe un fichier déjà téléchargé (poste sans accès à Internet) ;
- `status` : bases importées ;
- `ip`     : pays et opérateur d'une adresse.

Données DB-IP Lite sous licence CC BY 4.0 : « IP Geolocation by DB-IP » (https://db-ip.com).
"""

import asyncio
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from illwatch.shared.enums import EnrichmentDataset

console = Console()

DATASETS = [d.value for d in EnrichmentDataset]


@click.group()
def enrich() -> None:
    """Pays et opérateur réseau des IP, depuis la base DB-IP Lite importée localement."""


async def _import(dataset: EnrichmentDataset, path: Path, source: str) -> str:
    from illwatch.app.database import dispose_engine, get_session_factory
    from illwatch.modules.enrichment.dbip import import_dataset, open_lines
    from illwatch.modules.foundation.audit import cli_actor, record_in_session

    try:
        async with get_session_factory()() as session:
            with open_lines(path) as lines:
                report = await import_dataset(session, dataset, lines, source=source)
            await record_in_session(
                session,
                "enrichment.import",
                actor_name=cli_actor(),
                detail={"dataset": dataset.value, "source": source, "ranges": report.ranges},
            )
            await session.commit()
    finally:
        await dispose_engine()
    ranges = f"{report.ranges:,}".replace(",", "\u202f")
    invalid = f", {report.invalid} ligne(s) ignorée(s)" if report.invalid else ""
    return f"{dataset.value} : {ranges} plages importées depuis {source}{invalid}"


@enrich.command("import")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--dataset", type=click.Choice(DATASETS), required=True, help="Base contenue.")
def enrich_import(path: Path, dataset: str) -> None:
    """Importe un fichier DB-IP Lite (.csv ou .csv.gz) déjà téléchargé."""
    from illwatch.modules.enrichment.dbip import DatasetImportError

    try:
        message = asyncio.run(_import(EnrichmentDataset(dataset), path, path.name))
    except DatasetImportError as exc:
        raise click.ClickException(str(exc)) from exc
    console.print(f"[green]✔[/] {message}")


@enrich.command("update")
@click.option(
    "--dataset",
    type=click.Choice(DATASETS),
    multiple=True,
    help="Base à mettre à jour (par défaut : toutes).",
)
def enrich_update(dataset: tuple[str, ...]) -> None:
    """Télécharge et importe les bases DB-IP Lite du mois (une fois par mois suffit)."""
    from illwatch.modules.enrichment.dbip import DatasetImportError
    from illwatch.modules.enrichment.download import download_latest
    from illwatch.modules.threat_feeds.fetcher import FetchError

    async def _run(target: EnrichmentDataset) -> str:
        async with download_latest(target) as (name, path):
            console.print(f"Téléchargé : {name} ({path.stat().st_size / 2**20:.1f} Mo)")
            return await _import(target, path, name)

    failed = False
    for name in dataset or DATASETS:
        try:
            console.print(f"[green]✔[/] {asyncio.run(_run(EnrichmentDataset(name)))}")
        except (FetchError, DatasetImportError) as exc:
            failed = True
            console.print(f"[red]✘ {name}[/] : {exc}")
    console.print("Données : IP Geolocation by DB-IP (https://db-ip.com), licence CC BY 4.0.")
    if failed:
        raise SystemExit(1)


@enrich.command("status")
def enrich_status() -> None:
    """Bases d'enrichissement importées."""
    from illwatch.app.database import dispose_engine, get_session_factory
    from illwatch.modules.enrichment.lookup import datasets

    async def _read() -> list[tuple[str, str, int, str]]:
        try:
            async with get_session_factory()() as session:
                return [
                    (d.dataset, d.source, d.ranges, d.imported_at.strftime("%d/%m/%Y %H:%M"))
                    for d in await datasets(session)
                ]
        finally:
            await dispose_engine()

    rows = asyncio.run(_read())
    if not rows:
        console.print("Aucune base importée : lancez [bold]illwatch enrich update[/].")
        return
    table = Table(title="Bases d'enrichissement")
    for column in ("Base", "Source", "Plages", "Importée le"):
        table.add_column(column)
    for name, source, ranges, at in rows:
        table.add_row(name, source, f"{ranges:,}".replace(",", " "), at)
    console.print(table)


@enrich.command("ip")
@click.argument("address")
def enrich_ip_command(address: str) -> None:
    """Pays et système autonome d'une adresse IP."""
    from illwatch.app.database import dispose_engine, get_session_factory
    from illwatch.modules.enrichment.ipkeys import ip_key
    from illwatch.modules.enrichment.lookup import IpEnrichment, enrich_ip

    try:
        ip_key(address)
    except ValueError as exc:
        raise click.ClickException(f"« {address} » n'est pas une adresse IP.") from exc

    async def _read() -> IpEnrichment:
        try:
            async with get_session_factory()() as session:
                return await enrich_ip(session, address)
        finally:
            await dispose_engine()

    found = asyncio.run(_read())
    scope = "" if found.public else " (adresse non routable sur Internet)"
    console.print(f"{address}{scope}")
    console.print(f"  Pays : {found.country or 'inconnu'}")
    asn = f"AS{found.asn} {found.as_org or ''}".strip() if found.asn else "inconnu"
    console.print(f"  Système autonome : {asn}")
