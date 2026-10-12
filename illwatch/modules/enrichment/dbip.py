"""Import des bases DB-IP Lite (CSV, licence CC BY 4.0 : « IP Geolocation by DB-IP »).

Formats (RFC 4180, UTF-8, sans en-tête) :
- `dbip-country-lite-AAAA-MM.csv.gz` : `début,fin,pays` (ex. `8.8.8.0,8.8.8.255,US`) ;
- `dbip-asn-lite-AAAA-MM.csv.gz` : `début,fin,numéro d'AS,organisation`.

L'import remplace la base entière dans une seule transaction : en cas d'échec, l'ancienne
reste en place. Une ligne invalide est ignorée et comptée ; au-delà de 1 % de lignes
invalides, le fichier est refusé (ce n'est probablement pas le bon fichier).
"""

import csv
import gzip
import io
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

from sqlalchemy import delete, insert
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import EnrichmentDatasetInfo, IpRange
from illwatch.modules.enrichment.ipkeys import ip_key
from illwatch.shared.enums import EnrichmentDataset

BATCH_SIZE = 5000
MAX_INVALID_RATIO = 0.01
MAX_ORG_LENGTH = 255
ATTRIBUTION = "IP Geolocation by DB-IP"
ATTRIBUTION_URL = "https://db-ip.com"


class DatasetImportError(Exception):
    """Fichier refusé : vide, mauvais format ou trop de lignes invalides."""


@dataclass(frozen=True)
class ImportReport:
    dataset: EnrichmentDataset
    source: str
    ranges: int
    invalid: int


def _range(row: list[str], dataset: EnrichmentDataset) -> dict[str, object] | None:
    expected = 3 if dataset is EnrichmentDataset.COUNTRY else 4
    if len(row) != expected:
        return None
    try:
        start, end = ip_key(row[0]), ip_key(row[1])
    except ValueError:
        return None
    if start > end:
        return None
    values: dict[str, object] = {"dataset": dataset.value, "start_key": start, "end_key": end}
    if dataset is EnrichmentDataset.COUNTRY:
        country = row[2].strip().upper()
        if len(country) != 2 or not country.isalpha():
            return None
        values.update(country=country, asn=None, as_org=None)
    else:
        number = row[2].strip()
        if not number.isdigit():
            return None
        org = row[3].strip()[:MAX_ORG_LENGTH] or None
        values.update(country=None, asn=int(number), as_org=org)
    return values


def parse_rows(
    lines: Iterable[str], dataset: EnrichmentDataset, counts: dict[str, int]
) -> Iterator[dict[str, object]]:
    """Plages valides d'un CSV DB-IP ; `counts` reçoit `read` et `invalid`."""
    counts.setdefault("read", 0)
    counts.setdefault("invalid", 0)
    for row in csv.reader(lines):
        if not row:
            continue
        counts["read"] += 1
        values = _range(row, dataset)
        if values is None:
            counts["invalid"] += 1
            continue
        yield values


def open_lines(path: Path) -> TextIO:
    """Lignes d'un fichier CSV, compressé (`.gz`) ou non."""
    if path.suffix == ".gz":
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", newline="")
    return path.open(encoding="utf-8", newline="")


async def import_dataset(
    session: AsyncSession,
    dataset: EnrichmentDataset,
    lines: Iterable[str],
    *,
    source: str,
    now: datetime | None = None,
) -> ImportReport:
    """Remplace la base `dataset` par les plages lues. L'appelant valide la transaction."""
    counts: dict[str, int] = {}
    await session.execute(delete(IpRange).where(IpRange.dataset == dataset.value))
    batch: list[dict[str, object]] = []
    total = 0
    for values in parse_rows(lines, dataset, counts):
        batch.append(values)
        if len(batch) >= BATCH_SIZE:
            await session.execute(insert(IpRange), batch)
            total += len(batch)
            batch = []
    if batch:
        await session.execute(insert(IpRange), batch)
        total += len(batch)
    invalid = counts.get("invalid", 0)
    if total == 0:
        raise DatasetImportError(f"{source} : aucune plage valide ({invalid} lignes refusées).")
    if invalid > MAX_INVALID_RATIO * counts.get("read", 0):
        raise DatasetImportError(
            f"{source} : {invalid} lignes invalides sur {counts['read']} (> 1 %) : "
            f"est-ce bien un fichier DB-IP « {dataset.value} » ?"
        )
    info = await session.get(EnrichmentDatasetInfo, dataset.value)
    stamp = now or datetime.now(UTC)
    if info is None:
        session.add(
            EnrichmentDatasetInfo(
                dataset=dataset.value, source=source, ranges=total, imported_at=stamp
            )
        )
    else:
        info.source, info.ranges, info.imported_at = source, total, stamp
    await session.flush()
    return ImportReport(dataset=dataset, source=source, ranges=total, invalid=invalid)
