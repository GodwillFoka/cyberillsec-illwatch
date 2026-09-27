"""Analyse des formats de flux — RF-06 (JSON, CSV, STIX 2.1), T2.3.

Chaque analyseur transforme un contenu brut en `Observation`. Il ne **valide pas** les
IOC : c'est le rôle de `ingest_indicators`, qui normalise, rejette et compte. Un
analyseur tolérant et une ingestion stricte : une ligne étrange apparaît dans les rejets
au lieu de faire échouer tout le flux.

Formats reconnus :

- **CSV** : en-tête explicite ou commenté (`# id,dateadded,url,…` comme chez abuse.ch).
  La colonne de l'IOC est choisie par son nom (`url`, `dst_ip`, `ioc`, `sha256_hash`…) ;
  sans en-tête exploitable, chaque ligne est un IOC par colonne unique.
- **JSON** : liste de chaînes, liste d'objets, ou objet enveloppant une liste
  (`data`, `indicators`, `iocs`, `items`, `results`, `objects`).
- **STIX 2.1** : objets `indicator` à motif STIX (`[ipv4-addr:value = '…']`, hashs de
  fichiers, URL, domaines, e-mails) et objets observables (`ipv4-addr`, `domain-name`…).
"""

import csv
import json
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sentry.modules.threat_feeds.indicators import Observation
from sentry.shared.enums import FeedType, Severity

MAX_DESCRIPTION_LENGTH = 500

# Ordre de préférence : la première colonne présente est retenue comme IOC.
_VALUE_COLUMNS = (
    "ioc",
    "indicator",
    "ioc_value",
    "value",
    "url",
    "dst_ip",
    "ip_address",
    "ip",
    "domain",
    "hostname",
    "host",
    "sha256_hash",
    "sha256",
    "sha1_hash",
    "sha1",
    "md5_hash",
    "md5",
    "email",
)
_DATE_COLUMNS = ("first_seen_utc", "first_seen", "dateadded", "date_added", "date", "created")
_DESCRIPTION_COLUMNS = ("threat", "malware", "malware_printable", "description", "tags")
_JSON_LIST_KEYS = ("data", "indicators", "iocs", "items", "results", "objects")

_STIX_VALUE_RE = re.compile(
    r"\[\s*(?:ipv4-addr|ipv6-addr|domain-name|url|email-addr):value\s*=\s*'((?:[^'\\]|\\.)*)'\s*\]"
)
_STIX_HASH_RE = re.compile(
    r"\[\s*file:hashes\.(?:'?(?:SHA-256|SHA-1|MD5)'?|\"(?:SHA-256|SHA-1|MD5)\")"
    r"\s*=\s*'([0-9a-fA-F]+)'\s*\]"
)
_STIX_OBSERVABLE_TYPES = {"ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr"}


class FeedParseError(ValueError):
    """Contenu illisible dans le format déclaré du flux."""


@dataclass(slots=True)
class ParseResult:
    observations: list[Observation] = field(default_factory=list)
    skipped: int = 0  # lignes / objets sans IOC exploitable


def _parse_date(raw: object) -> datetime | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip().replace("Z", "+00:00")
    for candidate in (text, text.replace(" ", "T", 1)):
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            continue
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return None


def _severity(raw: object, default: Severity) -> Severity:
    if isinstance(raw, str) and raw.strip().upper() in Severity.__members__:
        return Severity(raw.strip().upper())
    return default


def _description(raw: object) -> str | None:
    if raw is None:
        return None
    text = (
        raw
        if isinstance(raw, str)
        else ", ".join(map(str, raw))
        if isinstance(raw, list)
        else str(raw)
    )
    text = text.strip()
    return text[:MAX_DESCRIPTION_LENGTH] or None


def _decode(content: bytes) -> str:
    return content.decode("utf-8-sig", errors="replace")


# --- CSV -----------------------------------------------------------------------


def _pick(columns: list[str], candidates: Iterable[str]) -> int | None:
    lowered = [c.strip().lower() for c in columns]
    for name in candidates:
        if name in lowered:
            return lowered.index(name)
    return None


def parse_csv(content: bytes, *, default_severity: Severity = Severity.MEDIUM) -> ParseResult:
    result = ParseResult()
    header: list[str] | None = None
    data_lines: list[str] = []

    for line in _decode(content).splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            commented = stripped.lstrip("#").strip()
            # En-tête commenté (abuse.ch) : la dernière ligne de commentaire à plusieurs
            # colonnes dont un nom de colonne IOC connu.
            cells = next(csv.reader([commented]))
            if len(cells) > 1 and _pick(cells, _VALUE_COLUMNS) is not None:
                header = cells
            continue
        data_lines.append(line)

    rows: Iterator[list[str]] = csv.reader(data_lines)
    if header is None:
        first = next(rows, None)
        if first is None:
            return result
        if _pick(first, _VALUE_COLUMNS) is not None:
            header = first
        else:
            rows = iter([first, *rows])

    value_idx = date_idx = desc_idx = sev_idx = None
    if header is not None:
        value_idx = _pick(header, _VALUE_COLUMNS)
        date_idx = _pick(header, _DATE_COLUMNS)
        desc_idx = _pick(header, _DESCRIPTION_COLUMNS)
        sev_idx = _pick(header, ("severity",))

    for row in rows:
        if not row or not any(cell.strip() for cell in row):
            continue
        if value_idx is None:
            if len(row) != 1:
                result.skipped += 1
                continue
            value = row[0]
        elif value_idx < len(row):
            value = row[value_idx]
        else:
            result.skipped += 1
            continue
        if not value.strip():
            result.skipped += 1
            continue

        def cell(idx: int | None, current: list[str] = row) -> str | None:
            return current[idx] if idx is not None and idx < len(current) else None

        result.observations.append(
            Observation(
                value=value.strip(),
                severity=_severity(cell(sev_idx), default_severity),
                description=_description(cell(desc_idx)),
                observed_at=_parse_date(cell(date_idx)),
            )
        )
    return result


# --- JSON ----------------------------------------------------------------------


def _json_items(document: Any) -> list[Any]:
    if isinstance(document, list):
        return document
    if isinstance(document, dict):
        for key in _JSON_LIST_KEYS:
            if isinstance(document.get(key), list):
                return list(document[key])
    raise FeedParseError("JSON : liste d'IOC introuvable (attendu : liste ou clé data/items…).")


def parse_json(content: bytes, *, default_severity: Severity = Severity.MEDIUM) -> ParseResult:
    try:
        document = json.loads(_decode(content))
    except json.JSONDecodeError as exc:
        raise FeedParseError(f"JSON invalide : {exc}") from exc

    result = ParseResult()
    for item in _json_items(document):
        if isinstance(item, str):
            if item.strip():
                result.observations.append(
                    Observation(value=item.strip(), severity=default_severity)
                )
            else:
                result.skipped += 1
            continue
        if not isinstance(item, dict):
            result.skipped += 1
            continue
        lowered = {str(k).lower(): v for k, v in item.items()}
        value = next(
            (lowered[k] for k in _VALUE_COLUMNS if isinstance(lowered.get(k), str) and lowered[k]),
            None,
        )
        if value is None:
            result.skipped += 1
            continue
        result.observations.append(
            Observation(
                value=value.strip(),
                severity=_severity(lowered.get("severity"), default_severity),
                description=_description(
                    next((lowered[k] for k in _DESCRIPTION_COLUMNS if lowered.get(k)), None)
                ),
                observed_at=_parse_date(
                    next((lowered[k] for k in _DATE_COLUMNS if lowered.get(k)), None)
                ),
            )
        )
    return result


# --- STIX 2.1 ------------------------------------------------------------------


def _unescape(value: str) -> str:
    return value.replace("\\'", "'").replace("\\\\", "\\")


def parse_stix(content: bytes, *, default_severity: Severity = Severity.MEDIUM) -> ParseResult:
    try:
        document = json.loads(_decode(content))
    except json.JSONDecodeError as exc:
        raise FeedParseError(f"STIX invalide (JSON) : {exc}") from exc

    if isinstance(document, dict) and document.get("type") == "bundle":
        objects = document.get("objects") or []
    elif isinstance(document, list):
        objects = document
    else:
        raise FeedParseError("STIX : bundle attendu (`type: bundle`).")

    result = ParseResult()
    for obj in objects:
        if not isinstance(obj, dict):
            result.skipped += 1
            continue
        kind = obj.get("type")
        if kind == "indicator":
            if obj.get("revoked") is True or obj.get("pattern_type", "stix") != "stix":
                result.skipped += 1
                continue
            pattern = str(obj.get("pattern", ""))
            values = [_unescape(v) for v in _STIX_VALUE_RE.findall(pattern)]
            values += _STIX_HASH_RE.findall(pattern)
            if not values:
                result.skipped += 1
                continue
            description = _description(obj.get("name") or obj.get("description"))
            seen = _parse_date(obj.get("valid_from") or obj.get("created"))
            result.observations.extend(
                Observation(
                    value=v,
                    severity=default_severity,
                    description=description,
                    observed_at=seen,
                )
                for v in values
            )
        elif kind in _STIX_OBSERVABLE_TYPES and isinstance(obj.get("value"), str):
            result.observations.append(Observation(value=obj["value"], severity=default_severity))
        # Les autres objets (identity, malware, relationship…) ne portent pas d'IOC.
    return result


def parse_feed(
    content: bytes, feed_type: FeedType, *, default_severity: Severity = Severity.MEDIUM
) -> ParseResult:
    """Point d'entrée unique : aiguille selon le format déclaré du flux."""
    parsers = {FeedType.CSV: parse_csv, FeedType.JSON: parse_json, FeedType.STIX: parse_stix}
    return parsers[FeedType(feed_type)](content, default_severity=default_severity)
