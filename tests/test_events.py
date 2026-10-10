"""Bus d'événements et flux SSE — ADR-016 (interface temps réel)."""

import asyncio
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.api.v1.stream import event_stream, format_event
from illwatch.app.main import create_app
from illwatch.app.models import CVE, CVEAlert, ThreatFeed
from illwatch.modules.cve_tracker.alerts import acknowledge
from illwatch.modules.events import RESYNC, Event, LocalEventBus, Subscription, can_see, emit
from illwatch.modules.foundation.users import create_user
from illwatch.modules.incidents.service import create_incident
from illwatch.modules.threat_feeds.collector import collect_feed
from illwatch.modules.threat_feeds.fetcher import FetchError
from illwatch.shared.enums import FeedType, RiskPriority, Severity, UserRole

NOW = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)


async def _received(sub: Subscription, wait: float = 1.0) -> list[Event]:
    """Tous les événements arrivés jusqu'à un silence de `wait` secondes (borné)."""
    events: list[Event] = []
    while (item := await sub.next(wait)) is not None:
        events.append(item)
        wait = 0.2
    return events


# --- Rôles -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("role", "min_role", "visible"),
    [
        (UserRole.VIEWER, UserRole.VIEWER, True),
        (UserRole.VIEWER, UserRole.ANALYST, False),
        (UserRole.VIEWER, UserRole.ADMIN, False),
        (UserRole.ANALYST, UserRole.ANALYST, True),
        (UserRole.ANALYST, UserRole.ADMIN, False),
        (UserRole.ADMIN, UserRole.ADMIN, True),
        ("INCONNU", UserRole.VIEWER, False),
    ],
)
def test_filtrage_par_role(role: str, min_role: UserRole, visible: bool) -> None:
    assert can_see(role, Event("x", min_role=min_role)) is visible


def test_serialisation_aller_retour() -> None:
    event = Event("alert.created", {"id": "a1"}, min_role=UserRole.ANALYST)
    assert Event.from_json(event.to_json()) == event
    frame = format_event(event)
    assert frame.startswith(f"id: {event.id}\nevent: alert.created\ndata: {{")
    assert frame.endswith("\n\n") and frame.count("\n") == 4  # une seule ligne `data`


# --- Bus local -------------------------------------------------------------------------------


async def test_bus_local_diffuse_a_tous_les_abonnes() -> None:
    bus = LocalEventBus()
    async with bus.subscribe() as a, bus.subscribe() as b:
        assert bus.subscribers == 2
        await bus.publish(Event("x"))
        assert [e.kind for e in await _received(a, 0.1)] == ["x"]
        assert [e.kind for e in await _received(b, 0.1)] == ["x"]
    assert bus.subscribers == 0


async def test_abonne_trop_lent_recoit_resync() -> None:
    bus = LocalEventBus(queue_size=3)
    async with bus.subscribe() as sub:
        for i in range(5):
            await bus.publish(Event(f"e{i}"))
        kinds = [e.kind for e in await _received(sub, 0.1)]
    assert kinds[0] == RESYNC  # la file a été vidée : l'interface doit tout relire
    assert len(kinds) <= 3


# --- Générateur SSE --------------------------------------------------------------------------


async def test_flux_sse_filtre_et_battement() -> None:
    bus = LocalEventBus()
    stream = event_stream(bus, UserRole.VIEWER, max_seconds=30, heartbeat=0.05)
    first = await anext(stream)
    assert first.startswith("retry: ")

    await bus.publish(Event("admin.only", min_role=UserRole.ADMIN))
    await bus.publish(Event("incident.updated", {"id": "i1"}))
    frame = await anext(stream)
    assert "event: incident.updated" in frame  # l'événement ADMIN n'est jamais transmis
    assert await anext(stream) == ": ping\n\n"
    await stream.aclose()
    assert bus.subscribers == 0  # désabonné à la fermeture de la connexion


async def test_flux_sse_se_ferme_a_l_expiration_du_jeton() -> None:
    bus = LocalEventBus()
    ticks = iter([0.0, 0.0, 100.0, 100.0])
    stream = event_stream(
        bus, UserRole.ADMIN, max_seconds=60, heartbeat=0.01, clock=lambda: next(ticks)
    )
    frames = [frame async for frame in stream]
    assert frames[0].startswith("retry: ")
    assert frames[-1].startswith("event: expired")


# --- Publication après commit ----------------------------------------------------------------


async def test_publie_apres_commit_seulement(
    db_session: AsyncSession, event_bus: LocalEventBus
) -> None:
    async with event_bus.subscribe() as sub:
        emit(db_session, Event("annule"))
        await db_session.rollback()
        emit(db_session, Event("valide"))
        assert await sub.next(0.05) is None  # rien avant le commit
        await db_session.commit()
        assert [e.kind for e in await _received(sub)] == ["valide"]


async def test_alerte_creee_puis_acquittee(
    db_session: AsyncSession, event_bus: LocalEventBus
) -> None:
    db_session.add(
        CVE(
            id="CVE-2026-2000",
            description="x",
            published_date=NOW,
            last_modified_date=NOW,
            composite_risk_score=95,
            priority=RiskPriority.P0_CRITIQUE,
        )
    )
    alert = CVEAlert(
        cve_id="CVE-2026-2000", score=95, priority="P0_CRITIQUE", reason="kev", delivery_attempts=0
    )
    db_session.add(alert)
    async with event_bus.subscribe() as sub:
        await db_session.flush()
        await db_session.commit()
        created = await _received(sub)
        assert [(e.kind, e.data["cve_id"]) for e in created] == [("alert.created", "CVE-2026-2000")]
        assert created[0].data["priority"] == "P0_CRITIQUE"

        user = await create_user(
            db_session,
            username="analyste-ev",
            email="analyste-ev@cyberill.test",
            password="mot-de-passe-2026!",
            role=UserRole.ANALYST,
        )
        await acknowledge(db_session, alert.id, user.id)
        await db_session.commit()
        assert [e.kind for e in await _received(sub)] == ["alert.acknowledged"]


async def test_incident_cree(db_session: AsyncSession, event_bus: LocalEventBus) -> None:
    async with event_bus.subscribe() as sub:
        incident = await create_incident(
            db_session, title="Phishing", description="x", severity=Severity.HIGH, author_id=None
        )
        await db_session.commit()
        events = await _received(sub)
    assert {(e.kind, e.data["id"]) for e in events} == {
        ("incident.created", str(incident.id)),
        ("incident.updated", str(incident.id)),
    }


async def test_collecte_annoncee(db_session: AsyncSession, event_bus: LocalEventBus) -> None:
    feed = ThreatFeed(name="Panne", url="https://panne.example.org/f", feed_type=FeedType.CSV)
    db_session.add(feed)
    await db_session.flush()

    async def fetch(url: str) -> bytes:
        raise FetchError("HTTP 503")

    async with event_bus.subscribe() as sub:
        await collect_feed(db_session, feed, fetch=fetch, clock=lambda: NOW)  # type: ignore[arg-type]
        await db_session.commit()
        [event] = await _received(sub)
    assert event.kind == "feed.collected"
    assert event.data == {"feed_id": str(feed.id), "succeeded": False, "inserted": 0}


# --- Route -----------------------------------------------------------------------------------


async def test_route_stream_protegee_et_documentee(client: AsyncClient) -> None:
    assert (await client.get("/api/v1/stream")).status_code == 401
    operation = create_app().openapi()["paths"]["/api/v1/stream"]["get"]
    assert "text/event-stream" in operation["responses"]["200"]["content"]


def test_pas_de_boucle_pas_d_erreur() -> None:
    """Un commit hors boucle asyncio (outil synchrone) ne lève pas."""
    from illwatch.modules.events.bus import _schedule

    _schedule(lambda: asyncio.sleep(0))


# --- Bus Redis : panne et retour ---------------------------------------------------------------


class _FakeRedis:
    """Redis simulé : `down` coupe publish et subscribe ; les messages publiés sont relayés."""

    def __init__(self) -> None:
        self.down = False
        self.queue: list[str] = []

    async def publish(self, channel: str, data: str) -> None:
        from redis.exceptions import ConnectionError as RedisConnectionError

        if self.down:
            raise RedisConnectionError("panne simulée")
        self.queue.append(data)

    def pubsub(self) -> "_FakePubSub":
        return _FakePubSub(self)

    async def aclose(self) -> None:
        return None


class _FakePubSub:
    def __init__(self, redis: _FakeRedis) -> None:
        self.redis = redis

    async def subscribe(self, channel: str) -> None:
        from redis.exceptions import ConnectionError as RedisConnectionError

        if self.redis.down:
            raise RedisConnectionError("panne simulée")

    async def get_message(self, **_: object) -> dict[str, object] | None:
        from redis.exceptions import ConnectionError as RedisConnectionError

        if self.redis.down:
            raise RedisConnectionError("panne simulée")
        if self.redis.queue:
            return {"type": "message", "data": self.redis.queue.pop(0)}
        await asyncio.sleep(0.01)
        return None

    async def aclose(self) -> None:
        return None


async def test_bus_redis_publie_localement_pendant_une_panne() -> None:
    from illwatch.modules.events.bus import RedisEventBus

    redis = _FakeRedis()
    bus = RedisEventBus(redis)
    bus.RETRY_FIRST_SECONDS = 0.01
    async with bus.subscribe() as sub:
        redis.down = True
        await bus.publish(Event("incident.updated"))
        kinds = [e.kind for e in await _received(sub, 0.5)]
    await bus.close()
    assert "incident.updated" in kinds  # livré aux abonnés du processus malgré la panne


async def test_bus_redis_se_reconnecte_et_demande_une_relecture() -> None:
    from illwatch.modules.events.bus import RedisEventBus

    redis = _FakeRedis()
    bus = RedisEventBus(redis)
    bus.RETRY_FIRST_SECONDS = 0.01
    redis.down = True
    async with bus.subscribe() as sub:
        assert (await sub.next(1.0)).kind == RESYNC  # écoute perdue : tout relire
        redis.down = False
        assert (await sub.next(1.0)).kind == RESYNC  # écoute rétablie : tout relire
        await bus.publish(Event("alert.created"))
        assert (await sub.next(1.0)).kind == "alert.created"
    await bus.close()
