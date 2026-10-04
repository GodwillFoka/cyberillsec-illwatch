"""Journal d'audit de sécurité — M7 Production Hardening (ADR-011).

Chaque action sensible produit **une ligne en base** (`audit_events`, en ajout seul) et **une
ligne JSON** dans le journal applicatif (`sentry.audit`), que collecte n'importe quel SIEM.

Écriture **hors transaction de la requête** : une connexion refusée lève une erreur HTTP, la
session de la requête est alors annulée ; l'audit, lui, doit survivre. L'enregistreur ouvre
donc sa propre session et valide immédiatement.

Politique en cas d'échec d'écriture : **ouverture** (la requête aboutit, l'échec est journalisé
en ERROR). Un journal d'audit indisponible ne doit pas rendre la plateforme indisponible ; la
ligne JSON reste émise et sert de trace de secours.
"""

import getpass
import logging
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app.config import get_settings
from sentry.app.database import get_session_factory
from sentry.app.models import AuditEvent, User
from sentry.modules.threat_feeds.secrets import mask_secrets
from sentry.shared.enums import AuditOutcome

log = logging.getLogger("sentry.audit")

MAX_DETAIL_VALUE = 500


@dataclass(frozen=True, slots=True)
class AuditContext:
    """Origine d'une action : adresse IP du client et identifiant de requête."""

    ip: str | None = None
    request_id: str | None = None

    @classmethod
    def from_request(cls, request: Request) -> "AuditContext":
        return cls(
            ip=request.client.host if request.client else None,
            request_id=getattr(request.state, "request_id", None),
        )


Writer = Callable[[AuditEvent], Awaitable[None]]


async def write_independently(event: AuditEvent) -> None:
    """Écrit la ligne dans sa propre transaction, indépendante de celle de la requête."""
    async with get_session_factory()() as session:
        session.add(event)
        await session.commit()


def _clean(detail: dict[str, Any] | None) -> dict[str, Any] | None:
    """Tronque les valeurs et masque tout secret configuré (clés d'API, mots de passe)."""
    if not detail:
        return None
    settings = get_settings()
    cleaned: dict[str, Any] = {}
    for key, value in detail.items():
        if isinstance(value, str):
            cleaned[key] = mask_secrets(value, settings)[:MAX_DETAIL_VALUE]
        elif isinstance(value, bool | int | float) or value is None:
            cleaned[key] = value
        else:
            cleaned[key] = mask_secrets(str(value), settings)[:MAX_DETAIL_VALUE]
    return cleaned


class AuditRecorder:
    """Point d'entrée unique de l'audit, injecté dans les routes (`Depends`)."""

    def __init__(self, writer: Writer = write_independently) -> None:
        self._write = writer

    async def record(
        self,
        action: str,
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
        *,
        actor: User | None = None,
        actor_id: UUID | None = None,
        actor_name: str | None = None,
        target_type: str | None = None,
        target_id: str | UUID | None = None,
        detail: dict[str, Any] | None = None,
        context: AuditContext | None = None,
    ) -> None:
        ctx = context or AuditContext()
        event = AuditEvent(
            action=action,
            outcome=outcome,
            actor_id=actor.id if actor is not None else actor_id,
            actor_name=(actor.username if actor is not None else actor_name or None),
            target_type=target_type,
            target_id=None if target_id is None else str(target_id)[:255],
            ip=(ctx.ip or None) and ctx.ip[:45],
            request_id=ctx.request_id,
            detail=_clean(detail),
        )
        log.info(
            "audit",
            extra={
                "fields": {
                    "action": action,
                    "outcome": str(outcome),
                    "actor": event.actor_name,
                    "target_type": target_type,
                    "target_id": event.target_id,
                    "ip": event.ip,
                    "request_id": event.request_id,
                }
            },
        )
        try:
            await self._write(event)
        except Exception as exc:  # noqa: BLE001 - politique d'ouverture, voir l'en-tête
            log.error(
                "audit.write_failed",
                extra={"fields": {"action": action, "error": f"{type(exc).__name__}: {exc}"}},
            )


_recorder = AuditRecorder()


def get_audit_recorder() -> AuditRecorder:
    """Dépendance FastAPI ; remplacée dans les tests par un enregistreur transactionnel."""
    return _recorder


def cli_actor() -> str:
    """Acteur d'une commande CLI : compte système qui l'exécute (`cli:kali`)."""
    try:
        return f"cli:{getpass.getuser()}"[:150]
    except (KeyError, OSError):  # conteneur sans entrée passwd pour l'UID courant
        return "cli:inconnu"


async def record_in_session(
    session: AsyncSession,
    action: str,
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
    **kwargs: Any,
) -> None:
    """Variante pour la CLI : la ligne suit la transaction de la commande."""

    async def _write(event: AuditEvent) -> None:
        session.add(event)
        await session.flush()

    await AuditRecorder(_write).record(action, outcome, **kwargs)


async def list_audit_events(
    session: AsyncSession,
    *,
    action: str | None = None,
    actor: str | None = None,
    outcome: AuditOutcome | None = None,
    since: datetime | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[Sequence[AuditEvent], int]:
    """Lignes d'audit, les plus récentes d'abord. `action` accepte un préfixe (`feed.`)."""
    conditions = []
    if action:
        conditions.append(AuditEvent.action.startswith(action))
    if actor:
        conditions.append(func.lower(AuditEvent.actor_name) == actor.strip().lower())
    if outcome is not None:
        conditions.append(AuditEvent.outcome == outcome)
    if since is not None:
        conditions.append(AuditEvent.occurred_at >= since)
    total = int(
        await session.scalar(select(func.count()).select_from(AuditEvent).where(*conditions)) or 0
    )
    rows = await session.execute(
        select(AuditEvent)
        .where(*conditions)
        .order_by(AuditEvent.occurred_at.desc(), AuditEvent.id)
        .limit(limit)
        .offset(offset)
    )
    return rows.scalars().all(), total
