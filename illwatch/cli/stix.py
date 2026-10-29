"""`illwatch stix` : export STIX 2.1 du renseignement (M10, incrément 3, ADR-025).

    illwatch stix export -o illwatch-stix.json   # 1 000 IOC actifs + campagnes
    illwatch stix export --contenu campagnes
    illwatch stix export --contenu indicateurs --limit 20000

Pour un partage continu, le serveur TAXII 2.1 de l'API (`/taxii2/`) est préférable.
"""

import asyncio
import json
from pathlib import Path
from typing import Any

import click
from rich.console import Console

console = Console(stderr=True)


@click.group()
def stix() -> None:
    """Export STIX 2.1 : indicateurs, campagnes, acteurs ATT&CK."""


@stix.command("export")
@click.option(
    "--contenu",
    type=click.Choice(["tout", "indicateurs", "campagnes"]),
    default="tout",
    show_default=True,
)
@click.option("--limit", type=click.IntRange(1, 50_000), default=1000, show_default=True)
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False, writable=True, path_type=Path),
    default=None,
    help="Fichier de sortie (sortie standard par défaut).",
)
def stix_export(contenu: str, limit: int, output: Path | None) -> None:
    """Écrit un bundle STIX 2.1."""
    from illwatch.app.database import dispose_engine, get_session_factory
    from illwatch.modules.foundation.audit import cli_actor, record_in_session
    from illwatch.modules.stix.export import export_bundle

    async def _main() -> dict[str, Any]:
        try:
            async with get_session_factory()() as session:
                document = await export_bundle(session, content=contenu, limit=limit)
                await record_in_session(
                    session,
                    "stix.export",
                    actor_name=cli_actor(),
                    target_type="stix",
                    detail={"contenu": contenu, "objets": len(document["objects"])},
                )
                await session.commit()
                return document
        finally:
            await dispose_engine()

    document = asyncio.run(_main())
    text = json.dumps(document, ensure_ascii=False, indent=2)
    if output is None:
        click.echo(text)
    else:
        output.write_text(text + "\n", encoding="utf-8")
    counts: dict[str, int] = {}
    for obj in document["objects"]:
        counts[obj["type"]] = counts.get(obj["type"], 0) + 1
    detail = ", ".join(f"{n} {kind}" for kind, n in sorted(counts.items()))
    console.print(f"[green]✔[/] Bundle STIX 2.1 : {detail}" + (f" → {output}" if output else ""))
