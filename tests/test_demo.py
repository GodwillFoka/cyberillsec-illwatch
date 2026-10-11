"""Jeu de démonstration : complet, fictif, jamais chargé sur une base réelle."""

from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.config import Settings
from illwatch.app.models import CVE, CVEAlert, HuntingSession, Incident, Indicator
from illwatch.modules.foundation.demo import DEMO_TAG, DemoRefusedError, load_demo_data
from illwatch.modules.threat_feeds.indicators import Observation, ingest_indicators

SETTINGS = Settings(secret_key="k" * 64)
NOW = datetime(2026, 10, 11, 9, 0, tzinfo=UTC)


async def _count(session: AsyncSession, model: type) -> int:
    return int(await session.scalar(select(func.count()).select_from(model)) or 0)


async def test_chargement_complet_et_fictif(db_session: AsyncSession) -> None:
    report = await load_demo_data(db_session, settings=SETTINGS, now=NOW)
    assert report.indicators >= 500 and report.cves == 48 and report.alerts > 0
    assert report.incidents == 5 and report.hunts == 1 and report.runs > 0
    assert await _count(db_session, Indicator) == report.indicators
    assert await _count(db_session, CVE) == 48
    assert await _count(db_session, CVEAlert) == report.alerts
    assert await _count(db_session, Incident) == 5
    hunt = await db_session.scalar(select(HuntingSession))
    assert hunt is not None and hunt.matches_count > 0
    # Fictif : CVE de l'année 2099 étiquetées, adresses des plages de documentation.
    ids = (await db_session.scalars(select(CVE.id))).all()
    assert all(i.startswith("CVE-2099-9") for i in ids)
    descriptions = (await db_session.scalars(select(CVE.description))).all()
    assert all(d.startswith(DEMO_TAG) for d in descriptions)
    ipv4 = (await db_session.scalars(select(Indicator.value).where(Indicator.type == "IPV4"))).all()
    assert ipv4 and all(v.startswith(("192.0.2.", "198.51.100.", "203.0.113.")) for v in ipv4)


async def test_refus_sur_une_base_reelle(db_session: AsyncSession) -> None:
    await ingest_indicators(db_session, [Observation("evil.example.com")])
    with pytest.raises(DemoRefusedError):
        await load_demo_data(db_session, settings=SETTINGS, now=NOW)
    assert await _count(db_session, CVE) == 0
