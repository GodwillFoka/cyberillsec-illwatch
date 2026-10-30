"""`GET /metrics`: exposition Prometheus (M11, ADR-026).

Accès : jeton `METRICS_TOKEN` (en-tête `Authorization: Bearer …`) s'il est défini ; sinon,
adresses locales ou privées seulement (Prometheus dans le réseau Docker). Caddy ne relaie pas
`/metrics` vers Internet (`deploy/Caddyfile`) : double barrière.
"""

import hmac
import ipaddress
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import PlainTextResponse

from illwatch.app.api.deps import DbSession
from illwatch.app.api.health import RedisProbe, get_redis_probe
from illwatch.app.config import Settings, get_settings
from illwatch.modules.observability.metrics import CONTENT_TYPE, business_gauges, exposition

router = APIRouter(include_in_schema=False)


def _private(host: str | None) -> bool:
    if not host:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host in {"localhost", "testclient"}
    return address.is_private or address.is_loopback


def check_metrics_access(request: Request, settings: Settings) -> None:
    token = settings.metrics_token.get_secret_value() if settings.metrics_token else None
    if token:
        scheme, _, given = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(given.strip(), token):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Jeton de métriques requis.")
        return
    if not _private(request.client.host if request.client else None):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, detail="Métriques réservées au réseau interne."
        )


@router.get("/metrics")
async def metrics(
    request: Request,
    session: DbSession,
    settings: Annotated[Settings, Depends(get_settings)],
    probe: Annotated[RedisProbe, Depends(get_redis_probe)],
) -> PlainTextResponse:
    check_metrics_access(request, settings)
    gauges = await business_gauges(session, redis_up=await probe(settings.redis_url))
    return PlainTextResponse(
        exposition(settings.app_version, settings.environment, gauges), media_type=CONTENT_TYPE
    )
