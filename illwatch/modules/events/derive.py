"""Événements déduits des écritures en base — ADR-016.

Plutôt que d'appeler `emit` dans chaque service (et d'en oublier un), les événements sont
déduits de ce que la transaction écrit, au moment du `flush` : une alerte CVE insérée donne
`alert.created`, un événement de chronologie d'incident donne `incident.updated`, etc. L'API
comme le worker de collecte sont donc couverts, quel que soit le chemin de code.

Les événements restent en attente jusqu'au commit (voir `bus.emit`).
"""

from typing import Any

from sqlalchemy import event as sa_event
from sqlalchemy import inspect
from sqlalchemy.orm import Session

from illwatch.app.models import CollectionRun, CVEAlert, HuntingSession, Incident, IncidentEvent
from illwatch.modules.events.bus import Event, emit

_SEEN_KEY = "illwatch_emitted_keys"


def _added(obj: Any, attribute: str) -> bool:
    """Vrai si l'attribut a reçu une valeur non nulle dans ce flush."""
    history = inspect(obj).attrs[attribute].history
    return any(value is not None for value in history.added or ())


def _events_for(obj: Any, *, new: bool) -> list[Event]:
    if isinstance(obj, CVEAlert):
        out: list[Event] = []
        if new:
            out.append(
                Event(
                    "alert.created",
                    {"id": str(obj.id), "cve_id": obj.cve_id, "priority": str(obj.priority)},
                )
            )
        if _added(obj, "acknowledged_at"):
            out.append(Event("alert.acknowledged", {"id": str(obj.id), "cve_id": obj.cve_id}))
        return out
    if isinstance(obj, Incident) and new:
        return [Event("incident.created", {"id": str(obj.id), "severity": str(obj.severity)})]
    if isinstance(obj, IncidentEvent) and new:
        return [
            Event(
                "incident.updated",
                {"id": str(obj.incident_id), "event_type": str(obj.event_type)},
            )
        ]
    if isinstance(obj, CollectionRun) and new:
        return [
            Event(
                "feed.collected",
                {
                    "feed_id": str(obj.feed_id),
                    "succeeded": bool(obj.succeeded),
                    "inserted": int(obj.inserted or 0),
                },
            )
        ]
    if isinstance(obj, HuntingSession) and _added(obj, "finished_at"):
        return [
            Event(
                "hunt.completed",
                {"id": str(obj.id), "status": str(obj.status), "matches": obj.matches_count},
            )
        ]
    return []


@sa_event.listens_for(Session, "after_flush")
def _derive(session: Session, _flush_context: object) -> None:
    seen: set[tuple[str, str]] = session.info.setdefault(_SEEN_KEY, set())
    candidates = [(obj, True) for obj in session.new] + [(obj, False) for obj in session.dirty]
    for obj, new in candidates:
        for item in _events_for(obj, new=new):
            # Un incident créé puis modifié dans la même transaction : un seul `incident.updated`.
            key = (item.kind, str(item.data.get("id") or item.data.get("feed_id")))
            if key in seen and item.kind != "feed.collected":
                continue
            seen.add(key)
            emit(session, item)


@sa_event.listens_for(Session, "after_commit")
def _reset(session: Session) -> None:
    session.info.pop(_SEEN_KEY, None)


@sa_event.listens_for(Session, "after_soft_rollback")
def _reset_on_rollback(session: Session, previous_transaction: Any) -> None:
    if previous_transaction.parent is None:
        session.info.pop(_SEEN_KEY, None)
