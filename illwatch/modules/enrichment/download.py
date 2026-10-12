"""Téléchargement mensuel des bases DB-IP Lite (`illwatch enrich update`).

Seule requête sortante de l'enrichissement, faite à la demande de l'administrateur (ou par
une tâche planifiée mensuelle), jamais pendant la consultation d'un IOC. Garde-fous repris
du collecteur de flux : hôte fixe, destination publique vérifiée, pas de redirection,
taille plafonnée, écriture dans un fichier temporaire supprimé après import.

DB-IP publie la base du mois en début de mois : si elle n'est pas encore en ligne, celle du
mois précédent est prise.
"""

import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

import httpx

from illwatch import __version__
from illwatch.modules.threat_feeds.fetcher import FetchError, assert_public_destination
from illwatch.shared.enums import EnrichmentDataset

BASE_URL = "https://download.db-ip.com/free"
MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024  # base ASN ≈ 30 Mo compressée, pays ≈ 10 Mo
TIMEOUT_SECONDS = 120.0
USER_AGENT = f"ILLWATCH/{__version__} (CyberillSec Threat Intelligence Platform)"


def _months(now: datetime) -> list[str]:
    previous = (now.year, now.month - 1) if now.month > 1 else (now.year - 1, 12)
    return [f"{now.year}-{now.month:02d}", f"{previous[0]}-{previous[1]:02d}"]


def file_name(dataset: EnrichmentDataset, month: str) -> str:
    return f"dbip-{dataset.value}-lite-{month}.csv.gz"


@asynccontextmanager
async def download_latest(
    dataset: EnrichmentDataset,
    *,
    now: datetime | None = None,
    client: httpx.AsyncClient | None = None,
) -> AsyncIterator[tuple[str, Path]]:
    """Télécharge la base du mois (ou du mois précédent) ; rend (nom du fichier, chemin)."""
    http = client or httpx.AsyncClient(
        timeout=TIMEOUT_SECONDS, follow_redirects=False, headers={"User-Agent": USER_AGENT}
    )
    try:
        with tempfile.TemporaryDirectory(prefix="illwatch-dbip-") as folder:
            last_status = 0
            for month in _months(now or datetime.now(UTC)):
                name = file_name(dataset, month)
                url = f"{BASE_URL}/{name}"
                await assert_public_destination(url)
                async with http.stream("GET", url) as response:
                    last_status = response.status_code
                    if response.status_code == httpx.codes.NOT_FOUND:
                        continue
                    if response.status_code != httpx.codes.OK:
                        raise FetchError(f"{url} : HTTP {response.status_code}.")
                    target = Path(folder) / name
                    size = 0
                    with target.open("wb") as out:
                        async for chunk in response.aiter_bytes():
                            size += len(chunk)
                            if size > MAX_DOWNLOAD_BYTES:
                                raise FetchError(
                                    f"{name} : plus de {MAX_DOWNLOAD_BYTES // 2**20} Mo, "
                                    f"téléchargement arrêté."
                                )
                            out.write(chunk)
                yield name, target
                return
            raise FetchError(
                f"Base DB-IP « {dataset.value} » introuvable pour ce mois et le précédent "
                f"(HTTP {last_status})."
            )
    finally:
        if client is None:
            await http.aclose()
