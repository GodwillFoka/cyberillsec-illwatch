"""Langue d'affichage du visiteur (ADR-027) : négociation pure et route `GET /api/v1/locale`."""

import json
from collections.abc import AsyncGenerator
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.config import Settings, get_settings
from illwatch.app.database import get_db
from illwatch.app.main import create_app
from illwatch.modules.enrichment.dbip import import_dataset
from illwatch.shared.enums import EnrichmentDataset
from illwatch.shared.i18n import (
    COUNTRY_LANGUAGES,
    SUPPORTED,
    choose_language,
    parse_accept_language,
)

COUNTRY_CSV = [
    "8.8.8.0,8.8.8.255,US",
    "9.9.9.0,9.9.9.255,DE",
    "31.0.0.0,31.0.0.255,CH",
    "41.202.0.0,41.202.0.255,CM",
    "1.1.1.0,1.1.1.255,JP",
]


# --- Négociation (sans base) ------------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("de-AT,de;q=0.9,en;q=0.8", ["de", "en"]),
        ("en;q=0.5, zh-CN;q=0.9, fr", ["fr", "zh", "en"]),
        ("es-419", ["es"]),
        ("ja, ko;q=0.8", []),
        ("de;q=0, fr", ["fr"]),  # q=0 : langue refusée
        ("*", []),
        ("", []),
        (None, []),
    ],
)
def test_accept_language(header: str | None, expected: list[str]) -> None:
    assert parse_accept_language(header) == expected


@pytest.mark.parametrize(
    "header",
    [
        "x" * 600,  # trop long
        "<script>alert(1)</script>",
        "fr;q=abc",
        "fr;q=1.5",
        "fr;q=0.5;q=0.7",
        "fr-" + "a" * 20,
        ",,,;;;",
    ],
)
def test_accept_language_hostile_ignore(header: str) -> None:
    assert parse_accept_language(header) == []


def test_accept_language_borne_le_nombre_d_etiquettes() -> None:
    header = ",".join(["ja"] * 30 + ["fr"])
    assert parse_accept_language(header) == []  # « fr » est au-delà des 20 premières


def test_le_pays_l_emporte_sur_le_navigateur() -> None:
    choice = choose_language(visitor_country="DE", accept_language="en-US,en;q=0.9")
    assert (choice.lang, choice.source) == ("de", "country")
    assert choose_language(visitor_country="fr", accept_language=None).lang == "fr"
    assert choose_language(visitor_country="MX", accept_language="en").lang == "es"
    assert choose_language(visitor_country="CN", accept_language="en").lang == "zh"
    assert choose_language(visitor_country="US", accept_language="de").lang == "en"


def test_pays_bilingue_departage_par_le_navigateur() -> None:
    assert choose_language(visitor_country="CH", accept_language="fr-CH,en").lang == "fr"
    assert choose_language(visitor_country="CH", accept_language="ja").lang == "de"
    assert choose_language(visitor_country="CA", accept_language="fr-CA").lang == "fr"
    assert choose_language(visitor_country="CM", accept_language="en-GB").lang == "en"
    # Langue de l'instance prise en compte si elle est une langue du pays.
    choice = choose_language(visitor_country="CH", accept_language="ja", instance_language="fr")
    assert choice.lang == "fr"


def test_pays_sans_langue_prise_en_charge_puis_navigateur() -> None:
    choice = choose_language(visitor_country="JP", accept_language="es;q=0.4, de;q=0.8")
    assert (choice.lang, choice.source) == ("de", "browser")


def test_adresse_privee_pays_de_l_instance() -> None:
    choice = choose_language(visitor_country=None, accept_language="en", instance_country="DE")
    assert (choice.lang, choice.source) == ("de", "country")


def test_langue_de_l_instance_puis_anglais() -> None:
    choice = choose_language(visitor_country=None, accept_language="ja", instance_language="zh")
    assert (choice.lang, choice.source) == ("zh", "instance")
    choice = choose_language(visitor_country="ZZZ", accept_language=None)
    assert (choice.lang, choice.source) == ("en", "default")


def test_table_des_pays_coherente() -> None:
    for country, langs in COUNTRY_LANGUAGES.items():
        assert len(country) == 2 and country.isupper()
        assert langs and all(lang in SUPPORTED for lang in langs)


# --- Route --------------------------------------------------------------------------------


def _settings(**overrides: object) -> Settings:
    return get_settings().model_copy(update=overrides)


@pytest.fixture
async def load_countries(db_session: AsyncSession) -> None:
    await import_dataset(db_session, EnrichmentDataset.COUNTRY, COUNTRY_CSV, source="pays.csv")


async def _ask(
    db_session: AsyncSession,
    ip: str,
    accept_language: str | None = None,
    settings: Settings | None = None,
) -> tuple[int, dict[str, object], str | None]:
    app = create_app()

    async def _db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    app.dependency_overrides[get_db] = _db
    if settings is not None:
        app.dependency_overrides[get_settings] = lambda: settings
    headers = {"Accept-Language": accept_language} if accept_language else {}
    transport = ASGITransport(app=app, client=(ip, 40000))
    async with AsyncClient(transport=transport, base_url="http://test") as http:
        response = await http.get("/api/v1/locale", headers=headers)
    return response.status_code, response.json(), response.headers.get("vary")


@pytest.mark.usefixtures("load_countries")
async def test_route_pays_du_visiteur(db_session: AsyncSession) -> None:
    status, body, vary = await _ask(db_session, "9.9.9.9", "en-US,en;q=0.9")
    assert status == 200
    assert body["lang"] == "de" and body["source"] == "country"
    assert body["supported"] == list(SUPPORTED)
    assert "country" not in body and "ip" not in body  # minimisation : la langue seulement
    assert vary == "Accept-Language"


@pytest.mark.usefixtures("load_countries")
async def test_route_pays_bilingue(db_session: AsyncSession) -> None:
    _, body, _ = await _ask(db_session, "31.0.0.7", "fr-CH,fr;q=0.9")
    assert body["lang"] == "fr"
    _, body, _ = await _ask(db_session, "41.202.0.9", None)
    assert body["lang"] == "fr"  # Cameroun : français par défaut


@pytest.mark.usefixtures("load_countries")
async def test_route_pays_non_pris_en_charge(db_session: AsyncSession) -> None:
    _, body, _ = await _ask(db_session, "1.1.1.1", "es-ES")
    assert (body["lang"], body["source"]) == ("es", "browser")


@pytest.mark.usefixtures("load_countries")
async def test_route_adresse_privee_pays_de_l_instance(db_session: AsyncSession) -> None:
    _, body, _ = await _ask(db_session, "10.1.2.3", "en", _settings(instance_country="DE"))
    assert (body["lang"], body["source"]) == ("de", "country")
    _, body, _ = await _ask(db_session, "192.168.1.5", None, _settings(default_language="zh"))
    assert (body["lang"], body["source"]) == ("zh", "instance")


async def test_route_sans_base_d_enrichissement(db_session: AsyncSession) -> None:
    _, body, _ = await _ask(db_session, "9.9.9.9", None)
    assert (body["lang"], body["source"]) == ("en", "default")


@pytest.mark.usefixtures("load_countries")
async def test_route_ignore_x_forwarded_for_non_fiable(db_session: AsyncSession) -> None:
    """Sans proxy de confiance, un en-tête forgé ne change pas le pays retenu."""
    app = create_app()

    async def _db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    app.dependency_overrides[get_db] = _db
    transport = ASGITransport(app=app, client=("8.8.8.8", 40000))
    async with AsyncClient(transport=transport, base_url="http://test") as http:
        response = await http.get("/api/v1/locale", headers={"X-Forwarded-For": "9.9.9.9"})
    assert response.json()["lang"] == "en"  # États-Unis, pas l'Allemagne


def test_table_des_pays_identique_sur_le_site() -> None:
    """Le site applique la même table hors ligne (fuseau horaire) : elle ne doit pas diverger."""
    path = (
        Path(__file__).resolve().parents[1] / "Website" / "src" / "data" / "country-languages.json"
    )
    site = json.loads(path.read_text(encoding="utf-8"))["countries"]
    assert site == {country: list(langs) for country, langs in COUNTRY_LANGUAGES.items()}
