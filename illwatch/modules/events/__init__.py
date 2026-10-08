"""Bus d'événements temps réel — ADR-016 (flux SSE `GET /api/v1/stream`)."""

from illwatch.modules.events import derive as _derive  # noqa: F401 - enregistre les écouteurs
from illwatch.modules.events.bus import (
    CHANNEL,
    RESYNC,
    Event,
    EventBus,
    LocalEventBus,
    RedisEventBus,
    Subscription,
    can_see,
    close_event_bus,
    emit,
    get_event_bus,
    set_event_bus,
)

__all__ = [
    "CHANNEL",
    "Event",
    "RESYNC",
    "EventBus",
    "LocalEventBus",
    "RedisEventBus",
    "Subscription",
    "can_see",
    "close_event_bus",
    "emit",
    "get_event_bus",
    "set_event_bus",
]
