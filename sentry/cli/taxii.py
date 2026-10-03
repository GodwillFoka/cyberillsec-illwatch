"""CLI `sentry taxii` — découverte de serveurs TAXII 2.1 avant intégration.

    sentry taxii discover https://attack-taxii.mitre.org/taxii2/

Liste les API roots et les collections lisibles, avec l'URL `…/objects/` à enregistrer
(`sentry feeds add --type TAXII --url …`). Les identifiants éventuels viennent de
`TAXII_AUTH` (par hôte). Complément naturel : `sentry feeds probe <url> --type TAXII` pour
vérifier qu'une collection contient des IOC, et pas seulement des objets de contexte.
"""

import asyncio

import click
from rich.console import Console
from rich.table import Table

from sentry.app.config import get_settings
from sentry.modules.threat_feeds.fetcher import FetchError
from sentry.modules.threat_feeds.parsers import FeedParseError
from sentry.modules.threat_feeds.secrets import mask_secrets
from sentry.modules.threat_feeds.taxii import discover

console = Console()


@click.group()
def taxii() -> None:
    """Serveurs TAXII 2.1 : découverte des API roots et des collections."""


@taxii.command("discover")
@click.argument("url")
def taxii_discover(url: str) -> None:
    """Interroge le point de découverte URL (ou une API root) et liste les collections."""
    settings = get_settings()
    try:
        found = asyncio.run(discover(url, settings=settings))
    except (FetchError, FeedParseError) as exc:
        console.print(f"[red]Échec :[/] {mask_secrets(str(exc), settings)}")
        raise SystemExit(1) from exc

    console.print(f"[bold]{found.title or url}[/] — {len(found.api_roots)} API root(s)")
    for root, error in found.errors.items():
        console.print(f"[yellow]! {root} :[/] {mask_secrets(error, settings)}")
    if not found.collections:
        console.print("Aucune collection lisible.")
        raise SystemExit(1 if found.errors else 0)
    table = Table(title="Collections")
    table.add_column("Titre")
    table.add_column("Lecture")
    table.add_column("URL à enregistrer (…/objects/)", overflow="fold")
    for c in found.collections:
        table.add_row(c.title or c.id, "oui" if c.can_read else "non", c.objects_url)
    console.print(table)
