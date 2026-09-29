"""Livraison et acquittement des alertes CVE — tâche 2.5 (RF-15).

Une alerte est d'abord **enregistrée** (`cve_alerts`, ligne de journal `cve.alert`), puis
livrée au webhook configuré (`ALERT_WEBHOOK_URL`). Une livraison échouée est retentée aux
cycles suivants, 5 fois au plus : une panne du webhook ne perd aucune alerte, elles restent
consultables par `GET /api/v1/alerts` et `sentry cves alerts`.

Charge utile : JSON avec un champ `text` (compatible Slack, Mattermost, Rocket.Chat) et les
champs structurés (`cve`, `score`, `priority`, `sla_hours`, `reason`).
"""

import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentry import __version__
from sentry.app.config import Settings
from sentry.app.models import CVEAlert
from sentry.modules.cve_tracker.scoring import remediation_sla_hours
from sentry.modules.threat_feeds.secrets import mask_secrets
from sentry.shared.enums import RiskPriority

log = logging.getLogger("sentry.cve")

MAX_DELIVERY_ATTEMPTS = 5

Poster = Callable[[str, dict[str, Any]], Awaitable[None]]


class AlertNotFoundError(LookupError):
    """Aucune alerte ne porte cet identifiant."""


async def post_json(url: str, payload: dict[str, Any]) -> None:
    """POST JSON sans suivre les redirections ; toute réponse hors 2xx est un échec."""
    async with httpx.AsyncClient(
        timeout=10.0,
        follow_redirects=False,
        headers={"User-Agent": f"SENTRY/{__version__}"},
    ) as client:
        response = await client.post(url, json=payload)
        if not response.is_success:
            raise RuntimeError(f"webhook : HTTP {response.status_code}")


def alert_payload(alert: CVEAlert) -> dict[str, Any]:
    priority = RiskPriority(alert.priority)
    sla = remediation_sla_hours(priority)
    score = float(alert.score)
    return {
        "text": (
            f"[SENTRY] {alert.cve_id} — score {score:.1f}/100 ({priority}), "
            f"remédiation sous {sla} h. Déclencheur : {alert.reason}."
        ),
        "cve": alert.cve_id,
        "score": score,
        "previous_score": None if alert.previous_score is None else float(alert.previous_score),
        "priority": str(priority),
        "sla_hours": sla,
        "reason": alert.reason,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
    }


async def deliver_pending(
    session: AsyncSession,
    *,
    settings: Settings,
    post: Poster = post_json,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> tuple[int, int]:
    """Livre les alertes en attente. Retourne (livrées, échecs). Sans webhook : (0, 0)."""
    if settings.alert_webhook_url is None or not settings.alert_webhook_url.get_secret_value():
        return 0, 0
    url = settings.alert_webhook_url.get_secret_value()
    pending = (
        (
            await session.execute(
                select(CVEAlert)
                .where(
                    CVEAlert.delivered_at.is_(None),
                    CVEAlert.delivery_attempts < MAX_DELIVERY_ATTEMPTS,
                )
                .order_by(CVEAlert.created_at)
            )
        )
        .scalars()
        .all()
    )
    delivered = failed = 0
    for alert in pending:
        alert.delivery_attempts += 1
        try:
            await post(url, alert_payload(alert))
        except Exception as exc:  # noqa: BLE001 - l'alerte reste en base et sera retentée
            failed += 1
            alert.last_delivery_error = mask_secrets(f"{type(exc).__name__} : {exc}", settings)[
                :1000
            ]
            log.error(
                "alert.delivery_failed",
                extra={"fields": {"cve": alert.cve_id, "attempt": alert.delivery_attempts}},
            )
            continue
        delivered += 1
        alert.delivered_at = clock()
        alert.last_delivery_error = None
    await session.flush()
    return delivered, failed


async def acknowledge(
    session: AsyncSession,
    alert_id: UUID,
    user_id: UUID,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> CVEAlert:
    """Acquitte une alerte (idempotent : le premier acquittement fait foi)."""
    alert = await session.get(CVEAlert, alert_id, populate_existing=True)
    if alert is None:
        raise AlertNotFoundError(str(alert_id))
    if alert.acknowledged_at is None:
        alert.acknowledged_at = clock()
        alert.acknowledged_by = user_id
        await session.flush()
    return alert
