"""Textes écrits par le serveur dans la langue de l'instance (ADR-027, décision 12)."""

from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app import config
from illwatch.app.config import Settings
from illwatch.app.models import CVE, Asset, CorrelatedEvent, Incident, IncidentEvent, Indicator
from illwatch.modules.foundation.demo import DEMO_TAG, DEMO_TAG_EN, load_demo_data
from illwatch.modules.threat_hunting.rules import CATALOG
from illwatch.shared.server_text import server_language, tr

NOW = datetime(2026, 10, 11, 9, 0, tzinfo=UTC)


def _use(monkeypatch: pytest.MonkeyPatch, lang: str | None) -> Settings:
    settings = Settings(secret_key="k" * 64, default_language=lang)
    monkeypatch.setattr(config, "get_settings", lambda: settings)
    return settings


@pytest.mark.parametrize(
    ("lang", "expected"), [(None, "fr"), ("fr", "fr"), ("en", "en"), ("de", "en"), ("zh", "en")]
)
def test_langue_du_serveur(
    monkeypatch: pytest.MonkeyPatch, lang: str | None, expected: str
) -> None:
    _use(monkeypatch, lang)
    assert server_language() == expected
    assert tr("bonjour", "hello") == ("bonjour" if expected == "fr" else "hello")


def test_regles_de_chasse_en_anglais(monkeypatch: pytest.MonkeyPatch) -> None:
    _use(monkeypatch, "en")
    assert all(rule.name_en and rule.description_en for rule in CATALOG)
    assert {rule.label() for rule in CATALOG} >= {"Tor exit relay", "Known IOC"}
    _use(monkeypatch, None)
    assert CATALOG[0].label() == "Relais de sortie Tor"


async def test_demonstration_en_anglais(
    monkeypatch: pytest.MonkeyPatch, db_session: AsyncSession
) -> None:
    settings = _use(monkeypatch, "en")
    await load_demo_data(db_session, settings=settings, now=NOW)

    titles = list((await db_session.scalars(select(Incident.title))).all())
    assert "Ransomware: encryption in progress on SRV-FILES-02 [demo]" in titles
    assert all(t.endswith(DEMO_TAG_EN) for t in titles)

    texts = [
        *titles,
        *(await db_session.scalars(select(IncidentEvent.message))).all(),
        *(await db_session.scalars(select(CVE.description))).all(),
        *(d for d in (await db_session.scalars(select(Indicator.description))).all() if d),
        *(await db_session.scalars(select(Asset.name))).all(),
        *(await db_session.scalars(select(CorrelatedEvent.title))).all(),
    ]
    french = ("[démo]", "Incident ouvert", "Indicateur associé", "CVE associée", " touche ")
    leaks = [t for t in texts if any(word in t for word in french)]
    assert not leaks, leaks[:5]


async def test_demonstration_en_francais_par_defaut(
    monkeypatch: pytest.MonkeyPatch, db_session: AsyncSession
) -> None:
    settings = _use(monkeypatch, None)
    await load_demo_data(db_session, settings=settings, now=NOW)
    titles = list((await db_session.scalars(select(Incident.title))).all())
    assert "Ransomware : chiffrement en cours sur SRV-FILES-02 [démo]" in titles
    assert all(t.endswith(DEMO_TAG) for t in titles)
