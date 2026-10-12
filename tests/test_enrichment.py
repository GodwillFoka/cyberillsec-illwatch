"""Enrichissement hors ligne des IP (M8, ADR-017, incrément 2) : clés, import DB-IP, lecture."""

import gzip
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import EnrichmentDatasetInfo, IpRange
from illwatch.app.security import create_access_token
from illwatch.modules.enrichment import download
from illwatch.modules.enrichment.dbip import DatasetImportError, import_dataset, open_lines
from illwatch.modules.enrichment.ipkeys import ip_key, is_public
from illwatch.modules.enrichment.lookup import enrich_ip
from illwatch.modules.foundation.users import create_user
from illwatch.modules.threat_feeds.indicators import Observation, ingest_indicators
from illwatch.shared.enums import EnrichmentDataset, UserRole

NOW = datetime(2026, 10, 12, 18, 0, tzinfo=UTC)

COUNTRY_CSV = [
    "1.0.0.0,1.0.0.255,AU",
    "8.8.8.0,8.8.8.255,US",
    "9.0.0.0,9.255.255.255,US",
    "2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,US",
]
ASN_CSV = [
    '8.8.8.0,8.8.8.255,15169,"Google LLC"',
    '2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,15169,"Google LLC"',
]


def test_cles_de_meme_longueur_et_ordonnees() -> None:
    keys = [ip_key(v) for v in ("0.0.0.0", "1.0.0.0", "8.8.8.8", "255.255.255.255", "2001::1")]
    assert all(len(k) == 32 for k in keys)
    assert keys == sorted(keys)
    assert ip_key("8.8.8.8") == ip_key("::ffff:8.8.8.8")
    with pytest.raises(ValueError):
        ip_key("pas une ip")


def test_adresses_publiques() -> None:
    assert is_public("8.8.8.8") and is_public("2001:4860::8888")
    assert not is_public("10.0.0.1") and not is_public("192.0.2.1") and not is_public("x")


async def _load(session: AsyncSession) -> None:
    await import_dataset(session, EnrichmentDataset.COUNTRY, COUNTRY_CSV, source="pays.csv")
    await import_dataset(session, EnrichmentDataset.ASN, ASN_CSV, source="asn.csv", now=NOW)


async def test_import_puis_lecture(db_session: AsyncSession) -> None:
    await _load(db_session)
    google = await enrich_ip(db_session, "8.8.8.8")
    assert (google.country, google.asn, google.as_org, google.public) == (
        "US",
        15169,
        "Google LLC",
        True,
    )
    v6 = await enrich_ip(db_session, "2001:4860:4860::8888")
    assert v6.country == "US" and v6.asn == 15169
    # Dans une plage pays, hors plage AS ; puis entre deux plages : inconnue.
    partial = await enrich_ip(db_session, "9.1.2.3")
    assert partial.country == "US" and partial.asn is None
    gap = await enrich_ip(db_session, "5.5.5.5")
    assert gap.country is None and gap.asn is None
    info = await db_session.get(EnrichmentDatasetInfo, "asn")
    assert info is not None and info.ranges == 2 and info.source == "asn.csv"


async def test_reimport_remplace_la_base(db_session: AsyncSession) -> None:
    await _load(db_session)
    await import_dataset(
        db_session, EnrichmentDataset.COUNTRY, ["8.8.8.0,8.8.8.255,FR"], source="v2.csv"
    )
    count = await db_session.scalar(
        select(func.count()).select_from(IpRange).where(IpRange.dataset == "country")
    )
    assert count == 1
    assert (await enrich_ip(db_session, "8.8.8.8")).country == "FR"
    assert (await enrich_ip(db_session, "8.8.8.8")).asn == 15169  # base AS intacte


async def test_fichier_refuse(db_session: AsyncSession) -> None:
    with pytest.raises(DatasetImportError):
        await import_dataset(
            db_session, EnrichmentDataset.COUNTRY, ["a,b,c", "1.1.1.1"], source="faux.csv"
        )
    # Mauvaise base : un fichier AS importé comme base pays.
    with pytest.raises(DatasetImportError):
        await import_dataset(db_session, EnrichmentDataset.COUNTRY, ASN_CSV, source="asn.csv")


async def test_lignes_invalides_ignorees_sous_le_seuil(db_session: AsyncSession) -> None:
    lines = [f"10.{i // 256}.{i % 256}.0,10.{i // 256}.{i % 256}.255,FR" for i in range(200)]
    lines.append("9.9.9.9,1.1.1.1,FR")  # bornes inversées
    report = await import_dataset(db_session, EnrichmentDataset.COUNTRY, lines, source="x")
    assert report.ranges == 200 and report.invalid == 1


def test_fichier_compresse(tmp_path: Path) -> None:
    path = tmp_path / "dbip-country-lite-2026-10.csv.gz"
    with gzip.open(path, "wt", encoding="utf-8") as out:
        out.write("\n".join(COUNTRY_CSV) + "\n")
    with open_lines(path) as lines:
        assert sum(1 for _ in lines) == len(COUNTRY_CSV)


async def test_detail_d_un_ioc_enrichi(client: AsyncClient, db_session: AsyncSession) -> None:
    await _load(db_session)
    await ingest_indicators(db_session, [Observation("8.8.8.8"), Observation("evil.example")])
    name = f"viewer-{uuid4().hex[:8]}"
    user = await create_user(
        db_session,
        username=name,
        email=f"{name}@cyberill.test",
        password="mot-de-passe-robuste-2026",
        role=UserRole.VIEWER,
    )
    headers = {"Authorization": f"Bearer {create_access_token(user.id, user.role)}"}
    items = (await client.get("/api/v1/indicators", headers=headers)).json()["items"]
    ids = {i["value"]: i["id"] for i in items}
    ip = (await client.get(f"/api/v1/indicators/{ids['8.8.8.8']}", headers=headers)).json()
    assert ip["enrichment"] == {
        "country": "US",
        "asn": 15169,
        "as_org": "Google LLC",
        "public": True,
        "attribution": "IP Geolocation by DB-IP",
    }
    domain = (await client.get(f"/api/v1/indicators/{ids['evil.example']}", headers=headers)).json()
    assert domain["enrichment"] is None


async def test_parametres_listent_les_bases(client: AsyncClient, db_session: AsyncSession) -> None:
    await _load(db_session)
    name = f"admin-{uuid4().hex[:8]}"
    admin = await create_user(
        db_session,
        username=name,
        email=f"{name}@cyberill.test",
        password="mot-de-passe-robuste-2026",
        role=UserRole.ADMIN,
    )
    headers = {"Authorization": f"Bearer {create_access_token(admin.id, admin.role)}"}
    body = (await client.get("/api/v1/settings", headers=headers)).json()
    assert [(d["dataset"], d["ranges"]) for d in body["enrichment"]] == [("asn", 2), ("country", 4)]


async def test_telechargement_mois_precedent_si_absent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    async def _public(url: str) -> None:
        return None

    monkeypatch.setattr(download, "assert_public_destination", _public)
    asked: list[str] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        asked.append(request.url.path)
        if request.url.path.endswith("2026-10.csv.gz"):
            return httpx.Response(404)
        return httpx.Response(200, content=gzip.compress(b"8.8.8.0,8.8.8.255,US\n"))

    async with (
        httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as http,
        download.download_latest(EnrichmentDataset.COUNTRY, now=NOW, client=http) as (name, path),
    ):
        assert name == "dbip-country-lite-2026-09.csv.gz"
        with open_lines(path) as lines:
            assert next(iter(lines)).startswith("8.8.8.0")
    assert asked == [
        "/free/dbip-country-lite-2026-10.csv.gz",
        "/free/dbip-country-lite-2026-09.csv.gz",
    ]
    assert not path.exists()  # fichier temporaire supprimé après usage


async def test_telechargement_plafonne(monkeypatch: pytest.MonkeyPatch) -> None:
    from illwatch.modules.threat_feeds.fetcher import FetchError

    async def _public(url: str) -> None:
        return None

    monkeypatch.setattr(download, "assert_public_destination", _public)
    monkeypatch.setattr(download, "MAX_DOWNLOAD_BYTES", 10)
    transport = httpx.MockTransport(lambda _: httpx.Response(200, content=b"x" * 100))
    async with httpx.AsyncClient(transport=transport) as http:
        with pytest.raises(FetchError):
            async with download.download_latest(EnrichmentDataset.ASN, now=NOW, client=http):
                pass
