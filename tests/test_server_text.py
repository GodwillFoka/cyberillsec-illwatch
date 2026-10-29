"""Textes écrits par le serveur dans la langue de l'instance (ADR-027, décision 12)."""

from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app import config
from illwatch.app.config import Settings
from illwatch.app.models import (
    CVE,
    Asset,
    CorrelatedEvent,
    Incident,
    IncidentEvent,
    Indicator,
    ThreatFeed,
)
from illwatch.modules.foundation import demo
from illwatch.modules.foundation.demo import DEMO_TAG, DEMO_TAG_EN, load_demo_data
from illwatch.modules.foundation.seed import REFERENCE_FEEDS, seed_reference_feeds
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


async def _demo(monkeypatch: pytest.MonkeyPatch, session: AsyncSession, lang: str | None) -> None:
    """Charge la démonstration même si des tests précédents ont laissé des données en base."""

    async def always_empty(_: AsyncSession) -> bool:
        return True

    monkeypatch.setattr(demo, "_empty", always_empty)
    await load_demo_data(session, settings=_use(monkeypatch, lang), now=NOW)


async def test_demonstration_en_anglais(
    monkeypatch: pytest.MonkeyPatch, db_session: AsyncSession
) -> None:
    await _demo(monkeypatch, db_session, "en")

    ours = Incident.title.like(f"%{DEMO_TAG_EN}")
    titles = list((await db_session.scalars(select(Incident.title).where(ours))).all())
    assert "Ransomware: encryption in progress on SRV-FILES-02 [demo]" in titles
    assert len(titles) == 5
    demo_assets = select(Asset.id).where(Asset.notes.like(f"%{DEMO_TAG_EN}"))
    texts = [
        *titles,
        *(await db_session.scalars(select(IncidentEvent.message).join(Incident).where(ours))).all(),
        *(
            await db_session.scalars(select(CVE.description).where(CVE.id.like("CVE-2099-9%")))
        ).all(),
        *(
            await db_session.scalars(
                select(Indicator.description).where(Indicator.description.like(f"%{DEMO_TAG_EN}%"))
            )
        ).all(),
        *(await db_session.scalars(select(Asset.name).where(Asset.id.in_(demo_assets)))).all(),
        *(
            await db_session.scalars(
                select(CorrelatedEvent.title).where(CorrelatedEvent.asset_id.in_(demo_assets))
            )
        ).all(),
    ]
    assert len(texts) > 40
    french = ("[démo]", "Incident ouvert", "Indicateur associé", "CVE associée", " touche ")
    leaks = [t for t in texts if t and any(word in t for word in french)]
    assert not leaks, leaks[:5]


async def test_demonstration_en_francais_par_defaut(
    monkeypatch: pytest.MonkeyPatch, db_session: AsyncSession
) -> None:
    await _demo(monkeypatch, db_session, None)
    ours = Incident.title.like(f"%{DEMO_TAG}")
    titles = list((await db_session.scalars(select(Incident.title).where(ours))).all())
    assert "Ransomware : chiffrement en cours sur SRV-FILES-02 [démo]" in titles


async def test_sources_semees_sans_doublon_si_la_langue_change(
    monkeypatch: pytest.MonkeyPatch, db_session: AsyncSession
) -> None:
    known = [f.name for f in REFERENCE_FEEDS] + [f.name_en for f in REFERENCE_FEEDS]
    query = select(ThreatFeed.name).where(ThreatFeed.name.in_(known))
    before = list((await db_session.scalars(query)).all())
    _use(monkeypatch, "en")
    await seed_reference_feeds(db_session)
    _use(monkeypatch, None)
    assert await seed_reference_feeds(db_session) == []
    after = list((await db_session.scalars(query)).all())
    assert len(after) == len(REFERENCE_FEEDS)
    if not before:
        assert "AlienVault OTX: subscribed pulses" in after
