"""Sondes d'exploitation — `GET /health` (vivacité) et `GET /ready` (disponibilité).

- **/health** : le processus répond et la base est joignable (critère M1, `HEALTHCHECK` Docker).
  Répond toujours 200 : un orchestrateur ne doit pas redémarrer l'API pour une panne de base.
- **/ready** (M7) : l'instance peut recevoir du trafic. 503 si la base est injoignable ou si
  son schéma n'est pas à la révision attendue (migration oubliée après un déploiement). Redis
  est signalé mais non bloquant : la limitation de débit bascule alors en mémoire locale.

Les deux acceptent `HEAD`, utilisé par certains répartiteurs de charge.
"""

from collections.abc import Awaitable, Callable
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Response, status
from pydantic import BaseModel
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.config import Settings, get_settings
from illwatch.app.database import get_db
from illwatch.app.migrations import head_revision

router = APIRouter(tags=["diagnostic"])

Check = Literal["ok", "fail", "degraded"]
RedisProbe = Callable[[str], Awaitable[bool]]


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    version: str
    environment: str
    database: Literal["connected", "unreachable"]


class ReadinessResponse(BaseModel):
    status: Literal["ready", "not_ready"]
    version: str
    checks: dict[str, Check]
    schema_revision: str | None
    expected_revision: str | None


async def _database_ok(session: AsyncSession) -> bool:
    try:
        await session.execute(text("SELECT 1"))
    except Exception:  # noqa: BLE001 - l'état dégradé est une réponse métier, pas une erreur HTTP
        return False
    return True


@router.head("/health", include_in_schema=False)
@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Vivacité et connexion base",
)
async def health(
    session: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> HealthResponse:
    """Vérifie que le process répond et que la base de données est joignable."""
    database: Literal["connected", "unreachable"] = (
        "connected" if await _database_ok(session) else "unreachable"
    )
    return HealthResponse(
        status="ok" if database == "connected" else "degraded",
        version=settings.app_version,
        environment=settings.environment,
        database=database,
    )


async def _schema_revision(session: AsyncSession) -> str | None:
    try:
        async with session.begin_nested():
            value = await session.scalar(text("SELECT version_num FROM alembic_version"))
    except Exception:  # noqa: BLE001 - table absente : base non migrée
        return None
    return None if value is None else str(value)


async def redis_ok(url: str) -> bool:
    # `Any` : les stubs `types-redis` ignorent `aclose()` (redis ≥ 5), comme dans throttle.py.
    client: Any = Redis.from_url(url, socket_connect_timeout=1, socket_timeout=1)
    try:
        return bool(await client.ping())
    except Exception:  # noqa: BLE001 - toute erreur Redis rend la vérification négative
        return False
    finally:
        await client.aclose()


def get_redis_probe() -> RedisProbe:
    """Dépendance remplaçable dans les tests (sonde Redis)."""
    return redis_ok


@router.head("/ready", include_in_schema=False)
@router.get(
    "/ready",
    response_model=ReadinessResponse,
    summary="Disponibilité : base joignable, schéma à jour, Redis",
    responses={503: {"model": ReadinessResponse}},
)
async def ready(
    response: Response,
    session: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
    probe: Annotated[RedisProbe, Depends(get_redis_probe)],
) -> ReadinessResponse:
    checks: dict[str, Check] = {}
    database = await _database_ok(session)
    checks["database"] = "ok" if database else "fail"
    current = await _schema_revision(session) if database else None
    try:
        expected = head_revision()
    except FileNotFoundError:  # image sans scripts Alembic : contrôle impossible, non bloquant
        expected = None
    if expected is None:
        checks["schema"] = "degraded" if current is not None else "fail"
    else:
        checks["schema"] = "ok" if current == expected else "fail"
    checks["redis"] = "ok" if await probe(settings.redis_url) else "degraded"
    is_ready = all(value != "fail" for value in checks.values())
    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return ReadinessResponse(
        status="ready" if is_ready else "not_ready",
        version=settings.app_version,
        checks=checks,
        schema_revision=current,
        expected_revision=expected,
    )
