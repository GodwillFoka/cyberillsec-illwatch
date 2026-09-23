"""Tests de l'amorçage des données de référence — `sentry seed`."""

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app.models import ThreatFeed
from sentry.modules.foundation.seed import REFERENCE_FEEDS, seed_reference_feeds


async def test_seed_est_idempotent(db_session: AsyncSession) -> None:
    first = await seed_reference_feeds(db_session)
    second = await seed_reference_feeds(db_session)

    assert len(first) == len(REFERENCE_FEEDS)
    assert second == []

    count = await db_session.scalar(select(func.count()).select_from(ThreatFeed))
    assert count == len(REFERENCE_FEEDS)
