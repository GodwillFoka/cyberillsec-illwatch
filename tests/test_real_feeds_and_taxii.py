"""Formats réels des sources publiques semées (M2) et connecteur TAXII 2.1 (tâche 1.8).

Les fixtures `c2intel_*`, `digitalside_*` et `feodo_ipblocklist_2026.csv` sont des extraits
des fichiers publiés par les sources : ils figent leur format réel.
"""

import base64
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app.config import Settings
from sentry.app.models import Indicator, ThreatFeed
from sentry.modules.threat_feeds.collector import collect_feed
from sentry.modules.threat_feeds.fetcher import FetchError
from sentry.modules.threat_feeds.parsers import FeedParseError, parse_csv
from sentry.modules.threat_feeds.secrets import mask_secrets
from sentry.modules.threat_feeds.taxii import (
    TAXII_MEDIA_TYPE,
    TaxiiConfigError,
    fetch_taxii,
    parse_envelope,
    parse_taxii_auth,
)
from sentry.modules.threat_feeds.validators import normalize_indicator
from sentry.shared.enums import FeedStatus, FeedType, IndicatorType

FIXTURES = Path(__file__).parent / "fixtures" / "feeds"
COLLECTION = (
    "https://osint.digitalside.it/taxii2reports/collections/"
    "c1f43330-103b-11ee-9ee3-4b022e286589/objects/"
)
NOW = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)


# --- Formats réels --------------------------------------------------------------


def test_c2intel_la_colonne_ioc_est_un_libelle() -> None:
    """`#ip,ioc` : choisir la colonne par son nom seul prenait le libellé comme IOC."""
    parsed = parse_csv((FIXTURES / "c2intel_ipc2s.csv").read_bytes())
    assert len(parsed.observations) == 20
    first = parsed.observations[0]
    assert (first.value, first.description) == ("1.15.76.39", "Possible Cobaltstrike C2 IP")
    assert all(normalize_indicator(o.value)[0] is IndicatorType.IPV4 for o in parsed.observations)


def test_c2intel_domaines() -> None:
    parsed = parse_csv((FIXTURES / "c2intel_domains.csv").read_bytes())
    values = [o.value for o in parsed.observations]
    assert values[0] == "1309673150-86ymvxmhrm.ap-shanghai.tencentscf.com"
    assert "check1.judicicaß1n" in values  # valeur corrompue : rejetée à l'ingestion


def test_digitalside_liste_texte_avec_cartouche() -> None:
    parsed = parse_csv((FIXTURES / "digitalside_latesturls.txt").read_bytes())
    assert len(parsed.observations) == 23 and parsed.skipped == 0
    assert all(o.value.startswith("http") for o in parsed.observations)


def test_feodo_format_2026_en_tete_entre_guillemets() -> None:
    parsed = parse_csv((FIXTURES / "feodo_ipblocklist_2026.csv").read_bytes())
    assert [o.value for o in parsed.observations] == [
        "162.243.103.246",
        "50.16.16.211",
        "34.204.119.63",
    ]
    assert parsed.observations[1].description == "QakBot"
    assert parsed.observations[1].observed_at == datetime(2025, 12, 30, 13, 56, 31, tzinfo=UTC)


async def test_c2intel_de_bout_en_bout(db_session: AsyncSession) -> None:
    feed = ThreatFeed(name="C2Intel", url="https://c2.example.org/f.csv", feed_type=FeedType.CSV)
    db_session.add(feed)
    await db_session.flush()
    content = (FIXTURES / "c2intel_domains.csv").read_bytes()

    async def fetch(url: str, **_: object) -> bytes:
        return content

    report = await collect_feed(db_session, feed, fetch=fetch, clock=lambda: NOW)
    assert report.succeeded and feed.status == FeedStatus.HEALTHY
    assert (report.inserted, report.rejected) == (12, 1)


# --- TAXII 2.1 -----------------------------------------------------------------


def _settings(auth: str = "osint.digitalside.it=guest:guest", **kw: object) -> Settings:
    return Settings(secret_key="k" * 64, taxii_auth=SecretStr(auth), **kw)  # type: ignore[arg-type]


class _Server:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Mapping[str, str] | None]] = []

    async def __call__(self, url: str, *, headers: Mapping[str, str] | None = None) -> bytes:
        self.calls.append((url, headers))
        page = "taxii_page2.json" if "next=page-2-token" in url else "taxii_page1.json"
        return (FIXTURES / page).read_bytes()


def test_identifiants_par_hote() -> None:
    assert parse_taxii_auth("a.example=u:p;b.example=v:w:x") == {
        "a.example": ("u", "p"),
        "b.example": ("v", "w:x"),
    }
    assert parse_taxii_auth("") == {}
    with pytest.raises(TaxiiConfigError):
        parse_taxii_auth("sans-egal")


def test_enveloppe() -> None:
    objects, token = parse_envelope((FIXTURES / "taxii_page1.json").read_bytes())
    assert (len(objects), token) == (3, "page-2-token")
    assert parse_envelope(b'{"type": "bundle", "objects": []}') == ([], None)
    assert parse_envelope(b'{"more": false}') == ([], None)
    with pytest.raises(FeedParseError):
        parse_envelope(b"[1, 2]")


async def test_pagination_authentification_et_incremental() -> None:
    server = _Server()
    parsed, pages, truncated = await fetch_taxii(
        COLLECTION, settings=_settings(), fetch=server, since=NOW
    )
    assert (pages, truncated) == (2, False)
    assert [o.value for o in parsed.observations] == [
        "198.51.100.23",
        "http://evil-dl.example.net/x86.bin",
        "c2.evil-dl.example.net",
    ]
    assert parsed.skipped == 1  # motif Sigma
    expected = "Basic " + base64.b64encode(b"guest:guest").decode()
    for url, headers in server.calls:
        assert headers is not None
        assert headers["Authorization"] == expected
        assert headers["Accept"] == TAXII_MEDIA_TYPE
        assert "added_after=2026-09-29T11%3A45%3A00.000Z" in url


async def test_pas_d_identifiants_pour_un_autre_hote() -> None:
    server = _Server()
    await fetch_taxii(
        "https://taxii.example.org/api/collections/x/objects/", settings=_settings(), fetch=server
    )
    assert all("Authorization" not in (h or {}) for _, h in server.calls)


async def test_pagination_plafonnee_et_configuration_invalide() -> None:
    _, pages, truncated = await fetch_taxii(
        COLLECTION, settings=_settings(taxii_max_pages=1), fetch=_Server()
    )
    assert (pages, truncated) == (1, True)
    with pytest.raises(FetchError, match="TAXII_AUTH"):
        await fetch_taxii(COLLECTION, settings=_settings("mauvais"), fetch=_Server())


async def test_collecte_taxii_de_bout_en_bout(db_session: AsyncSession) -> None:
    feed = ThreatFeed(name="DigitalSide TAXII", url=COLLECTION, feed_type=FeedType.TAXII)
    db_session.add(feed)
    await db_session.flush()

    report = await collect_feed(db_session, feed, fetch=_Server(), clock=lambda: NOW)

    assert report.succeeded, report.error
    assert feed.status == FeedStatus.HEALTHY
    assert report.inserted == 3
    values = set((await db_session.execute(select(Indicator.value))).scalars())
    assert "c2.evil-dl.example.net" in values


def test_masquage_ignore_les_secrets_courts() -> None:
    settings = _settings("h.example=guest:guest;k.example=u:mot-de-passe-long")
    message = "guest refusé ; mot-de-passe-long refusé"
    assert mask_secrets(message, settings) == "guest refusé ; *** refusé"
