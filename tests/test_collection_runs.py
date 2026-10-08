"""Journal des collectes et santé des sources — ADR-016, écran « Sources CTI »."""

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import CollectionRun, ThreatFeed
from illwatch.app.security import create_access_token
from illwatch.modules.foundation.users import create_user
from illwatch.modules.threat_feeds.collector import collect_feed
from illwatch.modules.threat_feeds.fetcher import FetchError
from illwatch.modules.threat_feeds.runs import feeds_health, list_runs, purge_runs
from illwatch.shared.enums import FeedStatus, FeedType, UserRole

FIXTURES = Path(__file__).parent / "fixtures" / "feeds"
NOW = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)
FEEDS = "/api/v1/feeds"

Headers = dict[str, str]


def _clock() -> datetime:
    return NOW


def _serving(outcome: bytes | Exception) -> Callable[[str], Awaitable[bytes]]:
    async def fetch(url: str) -> bytes:
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    return fetch


async def _feed(session: AsyncSession, name: str) -> ThreatFeed:
    feed = ThreatFeed(
        name=name, url=f"https://{name.lower()}.example.org/f", feed_type=FeedType.CSV
    )
    session.add(feed)
    await session.flush()
    return feed


def _run(feed: ThreatFeed, started_at: datetime, *, ok: bool = True, **kw: object) -> CollectionRun:
    return CollectionRun(
        feed_id=feed.id,
        started_at=started_at,
        duration_ms=kw.pop("duration_ms", 100),
        succeeded=ok,
        status=FeedStatus.HEALTHY if ok else FeedStatus.DEGRADED,
        error=None if ok else "HTTP 502 depuis 10.0.0.5",
        **kw,
    )


async def _headers(session: AsyncSession, role: UserRole) -> Headers:
    name = f"{role.value.lower()}-{uuid4().hex[:8]}"
    user = await create_user(
        session,
        username=name,
        email=f"{name}@cyberill.test",
        password="mot-de-passe-2026!",
        role=role,
    )
    return {"Authorization": f"Bearer {create_access_token(user.id, user.role)}"}


# --- Enregistrement par le collecteur -------------------------------------------------------


async def test_une_collecte_reussie_laisse_une_ligne(db_session: AsyncSession) -> None:
    feed = await _feed(db_session, "URLhaus")
    fetch = _serving((FIXTURES / "urlhaus_recent.csv").read_bytes())

    report = await collect_feed(db_session, feed, fetch=fetch, clock=_clock)  # type: ignore[arg-type]

    runs = await list_runs(db_session, feed.id)
    assert len(runs) == 1
    run = runs[0]
    assert run.succeeded and run.status == FeedStatus.HEALTHY
    assert (run.inserted, run.updated, run.rejected) == (report.inserted, report.updated, 1)
    assert run.error is None
    assert run.duration_ms >= 0


async def test_une_collecte_en_echec_est_journalisee(db_session: AsyncSession) -> None:
    feed = await _feed(db_session, "Panne")
    fetch = _serving(FetchError("HTTP 502 renvoyé par la source."))

    await collect_feed(db_session, feed, fetch=fetch, clock=_clock)  # type: ignore[arg-type]

    [run] = await list_runs(db_session, feed.id)
    assert not run.succeeded
    assert run.status == FeedStatus.DEGRADED
    assert run.error is not None and "502" in run.error
    assert run.inserted == 0


# --- Lecture ----------------------------------------------------------------------------------


async def test_historique_du_plus_recent_au_plus_ancien_et_borne(db_session: AsyncSession) -> None:
    feed = await _feed(db_session, "Historique")
    for hours in range(5):
        db_session.add(_run(feed, NOW - timedelta(hours=hours)))
    await db_session.flush()

    runs = await list_runs(db_session, feed.id, limit=3)
    assert [r.started_at.replace(tzinfo=UTC) for r in runs] == [
        NOW - timedelta(hours=h) for h in range(3)
    ]
    assert len(await list_runs(db_session, feed.id, limit=10_000)) == 5


async def test_sante_agrege_sur_sept_jours(db_session: AsyncSession) -> None:
    sain = await _feed(db_session, "Sain")
    instable = await _feed(db_session, "Instable")
    jamais = await _feed(db_session, "Jamais")
    db_session.add_all(
        [
            _run(sain, NOW - timedelta(hours=2), inserted=3),
            _run(sain, NOW - timedelta(hours=1), inserted=7, updated=2, duration_ms=850),
            _run(instable, NOW - timedelta(days=10), ok=False),  # hors fenêtre
            _run(instable, NOW - timedelta(days=2), ok=False),
            _run(instable, NOW - timedelta(days=1)),
        ]
    )
    await db_session.flush()

    health = {h.name: h for h in await feeds_health(db_session, now=NOW)}

    assert list(health) == ["Instable", "Jamais", "Sain"]
    assert health["Sain"].runs_7d == 2 and health["Sain"].errors_7d == 0
    assert health["Sain"].last_attempt_at == NOW - timedelta(hours=1)
    assert (health["Sain"].last_inserted, health["Sain"].last_updated) == (7, 2)
    assert health["Sain"].last_duration_ms == 850
    assert health["Instable"].runs_7d == 2 and health["Instable"].errors_7d == 1
    assert health["Jamais"].runs_7d == 0 and health["Jamais"].last_attempt_at is None
    assert health["Jamais"].feed_id == jamais.id


async def test_purge_au_dela_de_la_retention(db_session: AsyncSession) -> None:
    feed = await _feed(db_session, "Ancien")
    db_session.add_all([_run(feed, NOW - timedelta(days=91)), _run(feed, NOW - timedelta(days=89))])
    await db_session.flush()

    assert await purge_runs(db_session, now=NOW) == 1
    remaining = await db_session.scalar(select(func.count()).select_from(CollectionRun))
    assert remaining == 1


@pytest.mark.postgres
async def test_suppression_d_un_flux_supprime_son_journal(db_session: AsyncSession) -> None:
    """ON DELETE CASCADE appliqué par PostgreSQL lui-même."""
    feed = await _feed(db_session, "Retire")
    db_session.add(_run(feed, NOW))
    await db_session.flush()
    await db_session.execute(delete(ThreatFeed).where(ThreatFeed.id == feed.id))
    db_session.expire_all()

    remaining = await db_session.scalar(select(func.count()).select_from(CollectionRun))
    assert remaining == 0


# --- API --------------------------------------------------------------------------------------


@pytest.mark.parametrize("role", [UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER])
async def test_api_sante_et_journal_lisibles_par_tous(
    client: AsyncClient, db_session: AsyncSession, role: UserRole
) -> None:
    now = datetime.now(UTC)
    feed = await _feed(db_session, "Source")
    db_session.add_all([_run(feed, now - timedelta(hours=1)), _run(feed, now, ok=False)])
    feed.last_error = "HTTP 502 depuis 10.0.0.5"
    await db_session.flush()
    headers = await _headers(db_session, role)

    health = await client.get(f"{FEEDS}/health", headers=headers)
    assert health.status_code == 200
    [item] = health.json()
    assert item["name"] == "Source" and item["runs_7d"] == 2
    assert item["errors_7d"] == 1 and item["last_rejected"] == 0

    runs = await client.get(f"{FEEDS}/{feed.id}/runs", params={"limit": 1}, headers=headers)
    assert runs.status_code == 200
    [last] = runs.json()
    assert last["succeeded"] is False

    # Le détail d'erreur peut citer une adresse interne (SSRF) : réservé aux administrateurs.
    if role == UserRole.ADMIN:
        assert "10.0.0.5" in last["error"] and "10.0.0.5" in item["last_error"]
    else:
        assert "10.0.0.5" not in last["error"] and "10.0.0.5" not in item["last_error"]


async def test_api_journal_flux_inconnu_et_limite(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session, UserRole.VIEWER)
    assert (await client.get(f"{FEEDS}/{uuid4()}/runs", headers=headers)).status_code == 404
    feed = await _feed(db_session, "Borne")
    response = await client.get(f"{FEEDS}/{feed.id}/runs", params={"limit": 101}, headers=headers)
    assert response.status_code == 422


async def test_api_sante_anonyme_refuse(client: AsyncClient) -> None:
    assert (await client.get(f"{FEEDS}/health")).status_code == 401
