"""Limitation des tentatives de connexion — protection contre la force brute (RNF-SEC).

Deux compteurs par fenêtre glissante simple (`LOGIN_WINDOW_SECONDS`, 15 min par défaut) :

- **par identifiant** : `LOGIN_MAX_FAILURES` échecs (5) bloquent le compte visé, quelle que
  soit l'adresse d'origine (attaque distribuée sur un compte) ;
- **par adresse IP** : 4 × ce seuil bloquent l'adresse, quel que soit le compte visé
  (pulvérisation de mots de passe sur de nombreux comptes).

Un blocage renvoie HTTP 429 avec `Retry-After`. Une connexion réussie remet à zéro le
compteur de l'identifiant. Le stockage est Redis (partagé entre instances de l'API) ; si
Redis est injoignable, un compteur en mémoire prend le relais (protection par instance) et
l'incident est journalisé.
"""

import logging
import time
from typing import Any, Protocol

from redis.asyncio import Redis
from redis.exceptions import RedisError

from sentry.app.config import get_settings

log = logging.getLogger("sentry.security")

IP_FACTOR = 4
_PREFIX = "sentry:login:"


class FailureCounter(Protocol):
    async def failures(self, key: str) -> int: ...

    async def record(self, key: str, window: int) -> int: ...

    async def reset(self, key: str) -> None: ...


class LocalCounter:
    def __init__(self, clock: Any = time.monotonic) -> None:
        self._clock = clock
        self._data: dict[str, tuple[int, float]] = {}

    async def failures(self, key: str) -> int:
        count, expires = self._data.get(key, (0, 0.0))
        return count if expires > self._clock() else 0

    async def record(self, key: str, window: int) -> int:
        count = await self.failures(key)
        expires = self._data[key][1] if count else self._clock() + window
        self._data[key] = (count + 1, expires)
        return count + 1

    async def reset(self, key: str) -> None:
        self._data.pop(key, None)


class RedisCounter:
    def __init__(self, client: Any) -> None:
        self._client = client

    async def failures(self, key: str) -> int:
        value = await self._client.get(_PREFIX + key)
        return int(value or 0)

    async def record(self, key: str, window: int) -> int:
        async with self._client.pipeline(transaction=True) as pipe:
            pipe.incr(_PREFIX + key)
            pipe.expire(_PREFIX + key, window, nx=True)
            count, _ = await pipe.execute()
        return int(count)

    async def reset(self, key: str) -> None:
        await self._client.delete(_PREFIX + key)


class LoginThrottle:
    def __init__(self, counter: FailureCounter, *, max_failures: int, window: int) -> None:
        self.counter = counter
        self.max_failures = max_failures
        self.window = window

    @staticmethod
    def _keys(username: str, ip: str) -> tuple[str, str]:
        return f"user:{username.strip().lower()}", f"ip:{ip}"

    async def blocked(self, username: str, ip: str) -> bool:
        user_key, ip_key = self._keys(username, ip)
        return (
            await self.counter.failures(user_key) >= self.max_failures
            or await self.counter.failures(ip_key) >= self.max_failures * IP_FACTOR
        )

    async def failure(self, username: str, ip: str) -> None:
        user_key, ip_key = self._keys(username, ip)
        count = await self.counter.record(user_key, self.window)
        await self.counter.record(ip_key, self.window)
        if count == self.max_failures:
            log.warning(
                "auth.account_throttled",
                extra={"fields": {"username": username.strip().lower(), "ip": ip}},
            )

    async def success(self, username: str) -> None:
        await self.counter.reset(self._keys(username, "")[0])


_throttle: LoginThrottle | None = None


async def get_login_throttle() -> LoginThrottle:
    """Dépendance FastAPI : limiteur partagé (Redis si joignable, sinon en mémoire)."""
    global _throttle
    if _throttle is None:
        settings = get_settings()
        counter: FailureCounter
        client: Any = Redis.from_url(settings.redis_url, socket_connect_timeout=2)
        try:
            await client.ping()
            counter = RedisCounter(client)
        except (RedisError, OSError) as exc:
            await client.aclose()
            log.warning(
                "auth.throttle_local_fallback",
                extra={"fields": {"error": f"{type(exc).__name__}: {exc}"}},
            )
            counter = LocalCounter()
        _throttle = LoginThrottle(
            counter, max_failures=settings.login_max_failures, window=settings.login_window_seconds
        )
    return _throttle
