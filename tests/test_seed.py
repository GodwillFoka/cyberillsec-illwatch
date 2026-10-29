"""Tests de l'amorçage des données de référence : `illwatch seed`."""

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import ThreatFeed
from illwatch.modules.foundation.seed import REFERENCE_FEEDS, seed_reference_feeds


async def test_seed_est_idempotent(db_session: AsyncSession) -> None:
    first = await seed_reference_feeds(db_session)
    second = await seed_reference_feeds(db_session)

    assert len(first) == len(REFERENCE_FEEDS)
    assert second == []

    count = await db_session.scalar(select(func.count()).select_from(ThreatFeed))
    assert count == len(REFERENCE_FEEDS)


def test_sources_de_reference_conformes_aux_regles_de_l_api() -> None:
    """Le seed écrit directement en base : ses URL doivent passer les mêmes contrôles
    que celles saisies par un administrateur (SSRF, OTX limité à l'API OTX…)."""
    from illwatch.modules.threat_feeds.secrets import placeholders
    from illwatch.modules.threat_feeds.service import ensure_url_fits_type, validate_feed_url

    for feed in REFERENCE_FEEDS:
        url = feed.url
        for name in placeholders(url):
            url = url.replace("{" + name + "}", "cle")
        assert validate_feed_url(url) == url, feed.name
        ensure_url_fits_type(url, feed.feed_type)
        assert len(feed.name) <= 100
    assert len({f.name.lower() for f in REFERENCE_FEEDS}) == len(REFERENCE_FEEDS)


def test_cotes_de_reference_de_la_migration_conformes_au_seed() -> None:
    """La migration d2f7a9c4e318 cote une fois les sources de référence existantes : mêmes
    noms et mêmes cotes que le seed (qui, lui, ne cote qu'à la création)."""
    import importlib.util
    from pathlib import Path

    path = Path(__file__).parents[1] / "alembic" / "versions" / "d2f7a9c4e318_feed_reliability.py"
    spec = importlib.util.spec_from_file_location("migration_reliability", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # La migration date du 11/10/2026 : elle cite les noms d'alors, au tiret long (renommés le
    # 30/10/2026 par la migration b6e2f4a8c1d3 et par le seed).
    expected = {
        f.legacy_names()[0]: str(f.reliability) for f in REFERENCE_FEEDS if f.reliability != "C"
    }
    assert expected == module.REFERENCE_RATINGS


async def test_ancien_nom_au_tiret_long_renomme_sans_doublon(db_session: AsyncSession) -> None:
    """Nom publié avant le 30/10/2026 : la source est renommée, son historique conservé."""
    otx = next(f for f in REFERENCE_FEEDS if f.name.startswith("AlienVault OTX"))
    old_name = "AlienVault OTX \u2014 pulses abonnés"
    assert old_name in otx.legacy_names()
    legacy = ThreatFeed(name=old_name, url=otx.url, feed_type=otx.feed_type)
    db_session.add(legacy)
    await db_session.flush()

    report = await seed_reference_feeds(db_session)

    assert f"{otx.label()} (renommée)" in report
    assert legacy.name == otx.label()
    count = await db_session.scalar(select(func.count()).select_from(ThreatFeed))
    assert count == len(REFERENCE_FEEDS)
