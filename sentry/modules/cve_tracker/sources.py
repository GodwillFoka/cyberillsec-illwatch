"""Sources du moteur CVE : NVD 2.0, CISA KEV, FIRST EPSS — tâches 2.1 et 2.2 (phase 3).

Chaque source a un analyseur pur (octets → enregistrements) et une fonction de collecte qui
passe par le fetcher sécurisé du module de flux (DNS vérifié, taille bornée, backoff, 429).

- **NVD 2.0** : pagination `startIndex` / `resultsPerPage`, fenêtres `lastModStartDate` /
  `lastModEndDate` de 120 jours au plus (limite de l'API), filtre `hasKev`. Débit : 5 requêtes
  par 30 s sans clé, 50 avec (`NVD_API_KEY`, en-tête `apiKey`) : on espace les requêtes de 6 s
  ou 0,6 s. CVSS retenu : v3.1 (formule ADR-001), à défaut v3.0, à défaut v4.0 ; la version
  reste visible dans le vecteur. Exploit public = une référence NVD étiquetée « Exploit ».
- **KEV** : catalogue JSON complet ; `knownRansomwareCampaignUse == "Known"` → campagne
  ransomware confirmée.
- **EPSS** : API FIRST par lots de 100 CVE.
"""

import json
from collections.abc import Awaitable, Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any, Protocol
from urllib.parse import urlencode

from sentry.app.config import Settings
from sentry.modules.threat_feeds.parsers import FeedParseError

NVD_MAX_WINDOW = timedelta(days=120)
EPSS_BATCH = 100
MAX_DESCRIPTION = 4000


class HeaderFetcher(Protocol):
    def __call__(
        self, url: str, *, headers: Mapping[str, str] | None = None
    ) -> Awaitable[bytes]: ...


Sleep = Callable[[float], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class NvdRecord:
    id: str
    description: str
    published: datetime
    last_modified: datetime
    cvss_score: float | None
    cvss_vector: str | None
    has_public_exploit: bool
    kev_date_added: date | None = None
    kev_due_date: date | None = None
    kev_required_action: str | None = None


@dataclass(frozen=True, slots=True)
class KevEntry:
    id: str
    description: str
    date_added: date
    due_date: date | None
    required_action: str | None
    ransomware: bool


@dataclass(frozen=True, slots=True)
class EpssEntry:
    score: float
    percentile: float


@dataclass(slots=True)
class NvdPage:
    records: list[NvdRecord] = field(default_factory=list)
    total: int = 0
    rejected: int = 0  # CVE « Rejected » ou sans identifiant exploitable


def _json(content: bytes, source: str) -> Any:
    try:
        return json.loads(content.decode("utf-8-sig", errors="replace"))
    except json.JSONDecodeError as exc:
        raise FeedParseError(f"{source} : JSON invalide : {exc}") from exc


def _dt(raw: object) -> datetime | None:
    if not isinstance(raw, str) or not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _date(raw: object) -> date | None:
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return date.fromisoformat(raw[:10])
    except ValueError:
        return None


# --- NVD -----------------------------------------------------------------------

_CVSS_KEYS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40")


def _cvss(metrics: Mapping[str, Any]) -> tuple[float | None, str | None]:
    for key in _CVSS_KEYS:
        entries = [m for m in metrics.get(key) or [] if isinstance(m, dict)]
        # Évaluation du NVD (« Primary ») d'abord, puis celle du CNA (« Secondary »).
        entries.sort(key=lambda m: m.get("type") != "Primary")
        for entry in entries:
            data = entry.get("cvssData") or {}
            score = data.get("baseScore")
            if isinstance(score, int | float) and 0 <= score <= 10:
                vector = data.get("vectorString")
                return float(score), str(vector)[:120] if vector else None
    return None, None


def parse_nvd_page(content: bytes) -> NvdPage:
    document = _json(content, "NVD")
    if not isinstance(document, dict) or not isinstance(document.get("vulnerabilities"), list):
        raise FeedParseError("NVD : réponse inattendue (clé `vulnerabilities` absente).")
    page = NvdPage(total=int(document.get("totalResults") or 0))
    for item in document["vulnerabilities"]:
        cve = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve, dict):
            page.rejected += 1
            continue
        cve_id = str(cve.get("id") or "")
        published, modified = _dt(cve.get("published")), _dt(cve.get("lastModified"))
        if (
            not cve_id.startswith("CVE-")
            or cve.get("vulnStatus") == "Rejected"
            or published is None
            or modified is None
        ):
            page.rejected += 1
            continue
        descriptions = [d for d in cve.get("descriptions") or [] if isinstance(d, dict)]
        english = next((d.get("value") for d in descriptions if d.get("lang") == "en"), None)
        text = english or next((d.get("value") for d in descriptions), "") or ""
        score, vector = _cvss(cve.get("metrics") or {})
        exploit = any(
            "Exploit" in (ref.get("tags") or [])
            for ref in cve.get("references") or []
            if isinstance(ref, dict)
        )
        page.records.append(
            NvdRecord(
                id=cve_id[:30],
                description=str(text)[:MAX_DESCRIPTION],
                published=published,
                last_modified=modified,
                cvss_score=score,
                cvss_vector=vector,
                has_public_exploit=exploit,
                kev_date_added=_date(cve.get("cisaExploitAdd")),
                kev_due_date=_date(cve.get("cisaActionDue")),
                kev_required_action=cve.get("cisaRequiredAction") or None,
            )
        )
    return page


def nvd_windows(start: datetime, end: datetime) -> Iterator[tuple[datetime, datetime]]:
    """Découpe [start, end] en fenêtres de 120 jours au plus (contrainte de l'API)."""
    cursor = start
    while cursor < end:
        upper = min(cursor + NVD_MAX_WINDOW, end)
        yield cursor, upper
        cursor = upper


def _nvd_date(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


async def fetch_nvd(
    settings: Settings,
    fetch: HeaderFetcher,
    sleep: Sleep,
    *,
    window: tuple[datetime, datetime] | None = None,
    has_kev: bool = False,
    on_page: Callable[[NvdPage], Awaitable[None]],
) -> int:
    """Parcourt toutes les pages d'une requête NVD ; `on_page` traite chaque page.

    Retourne le nombre de CVE reçues. Page par page : la mémoire reste bornée même pour
    une synchronisation initiale de plusieurs dizaines de milliers de CVE.
    """
    headers = {"Accept": "application/json"}
    if settings.nvd_api_key is not None and settings.nvd_api_key.get_secret_value():
        headers["apiKey"] = settings.nvd_api_key.get_secret_value()
    pause = 0.6 if "apiKey" in headers else 6.0

    received = 0
    start_index = 0
    first = True
    while True:
        params: dict[str, str | int] = {
            "resultsPerPage": settings.nvd_results_per_page,
            "startIndex": start_index,
        }
        if window is not None:
            params["lastModStartDate"] = _nvd_date(window[0])
            params["lastModEndDate"] = _nvd_date(window[1])
        query = urlencode(params)
        if has_kev:
            query += "&hasKev"  # paramètre sans valeur dans l'API NVD 2.0
        if not first:
            await sleep(pause)
        first = False
        page = parse_nvd_page(await fetch(f"{settings.nvd_api_url}?{query}", headers=headers))
        received += len(page.records) + page.rejected
        await on_page(page)
        start_index += settings.nvd_results_per_page
        if start_index >= page.total or not (page.records or page.rejected):
            return received


# --- KEV -----------------------------------------------------------------------


def parse_kev(content: bytes) -> dict[str, KevEntry]:
    document = _json(content, "KEV")
    if not isinstance(document, dict) or not isinstance(document.get("vulnerabilities"), list):
        raise FeedParseError("KEV : catalogue inattendu (clé `vulnerabilities` absente).")
    catalog: dict[str, KevEntry] = {}
    for item in document["vulnerabilities"]:
        if not isinstance(item, dict):
            continue
        cve_id = str(item.get("cveID") or "")
        added = _date(item.get("dateAdded"))
        if not cve_id.startswith("CVE-") or added is None:
            continue
        name = item.get("vulnerabilityName") or ""
        summary = item.get("shortDescription") or ""
        catalog[cve_id[:30]] = KevEntry(
            id=cve_id[:30],
            description=f"{name} — {summary}".strip(" —")[:MAX_DESCRIPTION],
            date_added=added,
            due_date=_date(item.get("dueDate")),
            required_action=item.get("requiredAction") or None,
            ransomware=str(item.get("knownRansomwareCampaignUse", "")).lower() == "known",
        )
    if not catalog:
        # Un catalogue vide effacerait le statut KEV de toutes les CVE : on refuse.
        raise FeedParseError("KEV : catalogue vide, import refusé.")
    return catalog


# --- EPSS ----------------------------------------------------------------------


def parse_epss(content: bytes) -> dict[str, EpssEntry]:
    document = _json(content, "EPSS")
    if not isinstance(document, dict) or not isinstance(document.get("data"), list):
        raise FeedParseError("EPSS : réponse inattendue (clé `data` absente).")
    scores: dict[str, EpssEntry] = {}
    for item in document["data"]:
        if not isinstance(item, dict):
            continue
        try:
            score, percentile = float(item["epss"]), float(item["percentile"])
        except (KeyError, TypeError, ValueError):
            continue
        if 0.0 <= score <= 1.0 and 0.0 <= percentile <= 1.0:
            scores[str(item.get("cve"))] = EpssEntry(score, percentile)
    return scores


async def fetch_epss(
    settings: Settings, fetch: HeaderFetcher, sleep: Sleep, cve_ids: Sequence[str]
) -> dict[str, EpssEntry]:
    scores: dict[str, EpssEntry] = {}
    for start in range(0, len(cve_ids), EPSS_BATCH):
        if start:
            await sleep(0.2)
        batch = ",".join(cve_ids[start : start + EPSS_BATCH])
        url = f"{settings.epss_api_url}?{urlencode({'cve': batch, 'limit': EPSS_BATCH})}"
        scores.update(parse_epss(await fetch(url, headers={"Accept": "application/json"})))
    return scores
