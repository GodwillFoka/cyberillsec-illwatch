"""Bus d'événements temps réel — ADR-016.

Un événement dit à l'interface « telle donnée a changé » : nouvelle alerte, incident modifié,
collecte terminée… L'interface relit alors la donnée par l'API REST, avec les droits de
l'utilisateur. L'événement ne transporte donc que des identifiants et des libellés courts,
jamais le détail d'une donnée.

- `emit(session, event)` : rattache l'événement à la transaction en cours. Il n'est publié
  qu'**après le commit** (et oublié en cas d'annulation) : l'interface ne relit jamais une donnée
  pas encore écrite, et n'annonce jamais une modification annulée.
- `RedisEventBus` : publication sur le canal Redis `illwatch:events`, partagée entre l'API et le
  worker de collecte (processus distincts).
- `LocalEventBus` : même contrat dans un seul processus ; utilisé si Redis est injoignable
  (avertissement journalisé) et en test.

Chaque événement porte le rôle minimal requis pour le recevoir (`min_role`) : le flux SSE ne
transmet à un utilisateur que ce que son rôle lui permet de lire.

Un abonné trop lent ne bloque jamais la publication : sa file est vidée et il reçoit un
événement `resync`, qui demande à l'interface de tout relire.
"""

import asyncio
import contextlib
import json
import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import uuid4

from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy import event as sa_event
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from illwatch.shared.enums import UserRole

log = logging.getLogger("illwatch.events")

CHANNEL = "illwatch:events"
QUEUE_SIZE = 1000
_PENDING_KEY = "illwatch_pending_events"
_ROLE_RANK = {UserRole.VIEWER: 0, UserRole.ANALYST: 1, UserRole.ADMIN: 2}


@dataclass(frozen=True, slots=True)
class Event:
    kind: str  # ex. « alert.created », « incident.updated », « feed.collected »
    data: dict[str, Any] = field(default_factory=dict)
    min_role: UserRole = UserRole.VIEWER
    at: datetime = field(default_factory=lambda: datetime.now(UTC))
    id: str = field(default_factory=lambda: uuid4().hex)

    def to_json(self) -> str:
        return json.dumps(
            {
                "id": self.id,
                "kind": self.kind,
                "data": self.data,
                "min_role": str(self.min_role),
                "at": self.at.isoformat(),
            },
            default=str,
        )

    @classmethod
    def from_json(cls, raw: str | bytes) -> "Event":
        body = json.loads(raw)
        return cls(
            kind=str(body["kind"]),
            data=dict(body.get("data") or {}),
            min_role=UserRole(body.get("min_role", UserRole.ADMIN)),
            at=datetime.fromisoformat(body["at"]),
            id=str(body["id"]),
        )


RESYNC = "resync"


def can_see(role: str, event: Event) -> bool:
    """Un rôle inconnu ne voit rien (refus par défaut)."""
    try:
        rank = _ROLE_RANK[UserRole(role)]
    except ValueError:
        return False
    return rank >= _ROLE_RANK[event.min_role]


class EventBus(Protocol):
    async def publish(self, event: Event) -> None: ...

    def subscribe(self) -> Any:
        """Gestionnaire de contexte asynchrone qui produit une `Subscription`."""
        ...

    async def close(self) -> None: ...


class Subscription:
    """File d'un abonné. `next(wait)` renvoie `None` si rien n'arrive à temps : l'attente
    peut être interrompue sans perdre d'événement (contrairement à un générateur annulé)."""

    def __init__(self, queue: "asyncio.Queue[Event]") -> None:
        self._queue = queue

    async def next(self, wait: float) -> Event | None:
        try:
            return await asyncio.wait_for(self._queue.get(), timeout=wait)
        except TimeoutError:
            return None


class LocalEventBus:
    """Bus en mémoire, limité au processus courant."""

    def __init__(self, queue_size: int = QUEUE_SIZE) -> None:
        self._queues: set[asyncio.Queue[Event]] = set()
        self._queue_size = queue_size

    @property
    def subscribers(self) -> int:
        return len(self._queues)

    async def publish(self, event: Event) -> None:
        for queue in list(self._queues):
            _offer(queue, event)

    @asynccontextmanager
    async def subscribe(self) -> AsyncIterator[Subscription]:
        queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=self._queue_size)
        self._queues.add(queue)
        try:
            yield Subscription(queue)
        finally:
            self._queues.discard(queue)

    async def close(self) -> None:
        self._queues.clear()


def _offer(queue: "asyncio.Queue[Event]", event: Event) -> None:
    try:
        queue.put_nowait(event)
    except asyncio.QueueFull:
        while not queue.empty():
            queue.get_nowait()
        queue.put_nowait(Event(kind=RESYNC))


class RedisEventBus:
    """Bus Redis pub/sub : un message par événement sur `illwatch:events`.

    Chaque abonné (une connexion SSE) écoute le canal via une file locale alimentée par une
    seule souscription Redis par processus.
    """

    def __init__(self, client: Any) -> None:
        self._client = client
        self._local = LocalEventBus()
        self._listener: asyncio.Task[None] | None = None

    async def publish(self, event: Event) -> None:
        await self._client.publish(CHANNEL, event.to_json())

    @asynccontextmanager
    async def subscribe(self) -> AsyncIterator[Subscription]:
        self._ensure_listener()
        async with self._local.subscribe() as subscription:
            yield subscription

    def _ensure_listener(self) -> None:
        if self._listener is None or self._listener.done():
            self._listener = asyncio.create_task(self._listen(), name="illwatch-events")

    async def _listen(self) -> None:
        pubsub = self._client.pubsub()
        try:
            await pubsub.subscribe(CHANNEL)
            while True:
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=5.0)
                if message is None or message.get("type") != "message":
                    continue
                try:
                    event = Event.from_json(message["data"])
                except (ValueError, KeyError, TypeError):
                    log.warning("events.invalid_message")
                    continue
                await self._local.publish(event)
        except (RedisError, OSError) as exc:
            log.warning("events.redis_lost", extra={"fields": {"error": f"{type(exc).__name__}"}})
            # Les abonnés relisent tout : des événements ont pu être perdus.
            await self._local.publish(Event(kind=RESYNC))
        finally:
            with contextlib.suppress(RedisError, OSError, AttributeError):
                await pubsub.aclose()

    async def close(self) -> None:
        if self._listener is not None:
            self._listener.cancel()
        await self._local.close()
        await self._client.aclose()


# --- Instance du processus ---------------------------------------------------------------------

_bus: EventBus | None = None
_bus_lock = asyncio.Lock()


async def open_event_bus(redis_url: str) -> EventBus:
    """Bus Redis si le serveur répond, sinon bus local (avec avertissement)."""
    client: Any = Redis.from_url(redis_url, socket_connect_timeout=2, socket_timeout=None)
    try:
        await client.ping()
    except (RedisError, OSError) as exc:
        await client.aclose()
        log.warning(
            "events.redis_unavailable",
            extra={
                "fields": {
                    "error": f"{type(exc).__name__}: {exc}",
                    "fallback": "bus local : pas d'événements entre processus",
                }
            },
        )
        return LocalEventBus()
    return RedisEventBus(client)


async def get_event_bus() -> EventBus:
    global _bus
    if _bus is None:
        async with _bus_lock:
            if _bus is None:
                from illwatch.app.config import get_settings

                _bus = await open_event_bus(get_settings().redis_url)
    return _bus


def set_event_bus(bus: EventBus | None) -> None:
    """Remplace le bus du processus (tests)."""
    global _bus
    _bus = bus


async def close_event_bus() -> None:
    global _bus
    if _bus is not None:
        await _bus.close()
        _bus = None


# --- Publication après commit ------------------------------------------------------------------

_tasks: set[asyncio.Task[None]] = set()


def emit(session: AsyncSession | Session, event: Event) -> None:
    """Publie `event` après le commit de la transaction de `session` (jamais avant)."""
    target = session.sync_session if isinstance(session, AsyncSession) else session
    target.info.setdefault(_PENDING_KEY, []).append(event)


async def _publish_all(events: list[Event]) -> None:
    try:
        bus = await get_event_bus()
        for item in events:
            await bus.publish(item)
    except Exception as exc:  # noqa: BLE001 - un événement perdu ne doit jamais casser l'appelant
        log.warning("events.publish_failed", extra={"fields": {"error": type(exc).__name__}})


def _schedule(coro_factory: Callable[[], Any]) -> None:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:  # pas de boucle (outil synchrone) : rien à notifier
        return
    task = loop.create_task(coro_factory())
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)


@sa_event.listens_for(Session, "after_commit")
def _after_commit(session: Session) -> None:
    events = session.info.pop(_PENDING_KEY, None)
    if events:
        _schedule(lambda: _publish_all(events))


@sa_event.listens_for(Session, "after_soft_rollback")
def _after_rollback(session: Session, previous_transaction: Any) -> None:
    # L'annulation d'un point de sauvegarde (`begin_nested`) ne touche pas aux événements de la
    # transaction englobante : seule l'annulation de la transaction racine les oublie.
    if previous_transaction.parent is None:
        session.info.pop(_PENDING_KEY, None)
