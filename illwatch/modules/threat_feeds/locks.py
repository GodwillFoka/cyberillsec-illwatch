"""Verrous de collecte — T2.6 : deux instances ne collectent jamais le même flux ensemble.

Plusieurs collecteurs peuvent tourner en même temps : un `illwatch feeds worker` et un
`fetch-all` lancé à la main, deux conteneurs derrière un orchestrateur… Sans verrou, un
flux serait téléchargé deux fois (quota de la source consommé, `hit_count` doublé).

- `RedisFeedLock` : verrou partagé entre processus et machines. `SET clé jeton NX EX ttl`
  pour prendre, script Lua « supprimer seulement si le jeton est le mien » pour rendre :
  un collecteur ne libère jamais le verrou d'un autre, même après expiration du sien.
- `LocalFeedLock` : même contrat dans un seul processus. Utilisé si Redis est
  injoignable (le collecteur continue, avec un avertissement journalisé) et en test.

Le TTL borne la durée d'un verrou orphelin (processus tué) : il doit dépasser la durée
maximale d'une collecte (`COLLECT_LOCK_TTL_SECONDS`, 15 min par défaut).
"""

import logging
import secrets
import time
from typing import Any, Protocol

from redis.asyncio import Redis
from redis.exceptions import RedisError

log = logging.getLogger("illwatch.collector")

KEY_PREFIX = "illwatch:lock:feed:"

_RELEASE_SCRIPT = """
if redis.call('get', KEYS[1]) == ARGV[1] then
    return redis.call('del', KEYS[1])
end
return 0
"""


class FeedLock(Protocol):
    async def acquire(self, name: str, ttl_seconds: int) -> str | None:
        """Retourne un jeton si le verrou est pris, `None` s'il est déjà tenu."""
        ...

    async def release(self, name: str, token: str) -> None: ...

    async def close(self) -> None: ...


class LocalFeedLock:
    """Verrou en mémoire, limité au processus courant."""

    def __init__(self) -> None:
        self._held: dict[str, tuple[str, float]] = {}

    async def acquire(self, name: str, ttl_seconds: int) -> str | None:
        now = time.monotonic()
        current = self._held.get(name)
        if current is not None and current[1] > now:
            return None
        token = secrets.token_hex(16)
        self._held[name] = (token, now + ttl_seconds)
        return token

    async def release(self, name: str, token: str) -> None:
        current = self._held.get(name)
        if current is not None and current[0] == token:
            del self._held[name]

    async def close(self) -> None:
        self._held.clear()


class RedisFeedLock:
    """Verrou distribué Redis (un seul nœud : suffisant pour éviter les doublons de
    collecte ; ce n'est pas un verrou d'exclusion mutuelle garanti type Redlock)."""

    def __init__(self, client: Any) -> None:
        # `Any` : les annotations de redis-py diffèrent selon la présence du paquet
        # `types-redis` (obsolète depuis redis 5) ; ce code reste identique dans les deux cas.
        self._client = client

    async def acquire(self, name: str, ttl_seconds: int) -> str | None:
        token = secrets.token_hex(16)
        taken = await self._client.set(KEY_PREFIX + name, token, nx=True, ex=ttl_seconds)
        return token if taken else None

    async def release(self, name: str, token: str) -> None:
        await self._client.eval(_RELEASE_SCRIPT, 1, KEY_PREFIX + name, token)

    async def close(self) -> None:
        await self._client.aclose()


async def open_feed_lock(redis_url: str) -> FeedLock:
    """Verrou Redis si le serveur répond, sinon verrou local (avec avertissement)."""
    client: Any = Redis.from_url(redis_url, socket_connect_timeout=2, socket_timeout=5)
    try:
        await client.ping()
    except (RedisError, OSError) as exc:
        await client.aclose()
        log.warning(
            "lock.redis_unavailable",
            extra={
                "fields": {
                    "error": f"{type(exc).__name__}: {exc}",
                    "fallback": "verrou local : pas de protection entre instances",
                }
            },
        )
        return LocalFeedLock()
    return RedisFeedLock(client)
