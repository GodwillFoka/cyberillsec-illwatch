"""Limitation des tentatives de connexion (force brute)."""

import os
from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.throttle import LocalCounter, LoginThrottle, RedisCounter
from illwatch.modules.foundation.users import create_user

PASSWORD = "mot-de-passe-robuste-2026"


async def _login(client: AsyncClient, username: str, password: str) -> int:
    response = await client.post(
        "/api/v1/auth/token", data={"username": username, "password": password}
    )
    return response.status_code


async def test_compte_bloque_apres_cinq_echecs(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    name = f"cible-{uuid4().hex[:6]}"
    await create_user(db_session, username=name, email=f"{name}@cyberill.test", password=PASSWORD)

    assert [await _login(client, name, "mauvais") for _ in range(5)] == [401] * 5
    # Même le bon mot de passe est refusé : l'attaquant n'apprend plus rien.
    assert await _login(client, name, PASSWORD) == 429
    assert await _login(client, name.upper(), PASSWORD) == 429  # insensible à la casse


async def test_succes_remet_le_compteur_a_zero(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    name = f"distrait-{uuid4().hex[:6]}"
    await create_user(db_session, username=name, email=f"{name}@cyberill.test", password=PASSWORD)
    for _ in range(4):
        assert await _login(client, name, "mauvais") == 401
    assert await _login(client, name, PASSWORD) == 200
    for _ in range(4):
        assert await _login(client, name, "mauvais") == 401
    assert await _login(client, name, PASSWORD) == 200


async def test_pulverisation_depuis_une_adresse() -> None:
    throttle = LoginThrottle(LocalCounter(), max_failures=2, window=60)
    for n in range(8):  # 8 comptes différents, 1 échec chacun, même IP
        assert not await throttle.blocked(f"compte{n}", "203.0.113.9")
        await throttle.failure(f"compte{n}", "203.0.113.9")
    assert await throttle.blocked("compte-neuf", "203.0.113.9")
    assert not await throttle.blocked("compte-neuf", "198.51.100.1")


async def test_fenetre_expire() -> None:
    now = [0.0]
    counter = LocalCounter(clock=lambda: now[0])
    await counter.record("k", 10)
    await counter.record("k", 10)
    assert await counter.failures("k") == 2
    now[0] = 11.0
    assert await counter.failures("k") == 0


async def test_compteur_redis_partage() -> None:
    from redis.asyncio import Redis

    client = Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
    try:
        await client.ping()
    except OSError:
        await client.aclose()
        pytest.skip("Redis injoignable")
    except Exception:  # noqa: BLE001 - toute erreur Redis : test non applicable
        await client.aclose()
        pytest.skip("Redis injoignable")
    key = f"test-{uuid4().hex}"
    counter = RedisCounter(client)
    try:
        assert await counter.record(key, 30) == 1
        assert await counter.record(key, 30) == 2
        assert await counter.failures(key) == 2
        assert 0 < await client.ttl("illwatch:login:" + key) <= 30
        await counter.reset(key)
        assert await counter.failures(key) == 0
    finally:
        await client.delete("illwatch:login:" + key)
        await client.aclose()
