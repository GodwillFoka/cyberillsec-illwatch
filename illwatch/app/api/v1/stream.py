"""Flux temps réel de l'interface — `GET /api/v1/stream` (ADR-016, Server-Sent Events).

Le navigateur garde cette connexion ouverte et reçoit, au fil de l'eau, les événements que son
rôle lui permet de voir (`Event.min_role`). Chaque événement dit seulement « telle donnée a
changé » ; l'interface relit la donnée par l'API REST.

- Battement toutes les 15 s (commentaire SSE) : les proxys ne coupent pas une connexion muette,
  et le navigateur détecte une coupure.
- Durée bornée à celle du jeton d'accès : à l'expiration, le serveur ferme le flux et le client
  se reconnecte avec un jeton rafraîchi. Un compte désactivé ou rétrogradé perd donc le flux
  au plus tard à l'expiration de son jeton.
- La session de base de données est libérée avant l'ouverture du flux : une connexion SSE ne
  monopolise pas une connexion PostgreSQL.
"""

import time
from collections.abc import AsyncIterator, Callable
from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse

from illwatch.app.api.deps import CurrentUser, DbSession
from illwatch.app.config import get_settings
from illwatch.modules.events import Event, EventBus, can_see, get_event_bus

router = APIRouter(tags=["temps réel"])

HEARTBEAT_SECONDS = 15.0
RETRY_MS = 5000


def format_event(event: Event) -> str:
    """Trame SSE : `id`, `event` (le type), `data` (JSON sur une ligne)."""
    return f"id: {event.id}\nevent: {event.kind}\ndata: {event.to_json()}\n\n"


async def event_stream(
    bus: EventBus,
    role: str,
    *,
    max_seconds: float,
    heartbeat: float = HEARTBEAT_SECONDS,
    clock: Callable[[], float] | None = None,
) -> AsyncIterator[str]:
    """Générateur SSE ; testé directement (le client de test met les réponses en tampon)."""
    now = clock or time.monotonic
    deadline = now() + max_seconds
    async with bus.subscribe() as subscription:
        yield f"retry: {RETRY_MS}\n: illwatch\n\n"
        while (remaining := deadline - now()) > 0:
            event = await subscription.next(min(heartbeat, remaining))
            if event is None:
                yield ": ping\n\n"
            elif can_see(role, event):
                yield format_event(event)
        yield "event: expired\ndata: {}\n\n"


@router.get(
    "/stream",
    summary="Flux d'événements temps réel (Server-Sent Events)",
    description=(
        "Connexion longue `text/event-stream`. Types d'événements : `alert.created`, "
        "`alert.acknowledged`, `incident.created`, `incident.updated`, `feed.collected`, "
        "`hunt.completed`, `resync` (tout relire), `expired` (se reconnecter avec un jeton "
        "rafraîchi). Seuls les événements autorisés au rôle de l'utilisateur sont transmis."
    ),
    response_class=StreamingResponse,
    responses={200: {"content": {"text/event-stream": {}}}},
)
async def stream(
    user: CurrentUser,
    session: DbSession,
    bus: Annotated[EventBus, Depends(get_event_bus)],
) -> StreamingResponse:
    role = str(user.role)
    await session.close()  # libère la connexion avant un flux de plusieurs minutes
    max_seconds = get_settings().access_token_expire_minutes * 60
    return StreamingResponse(
        event_stream(bus, role, max_seconds=max_seconds),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
