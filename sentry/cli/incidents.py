"""CLI `sentry incidents` — gestion des incidents (phase 4).

    sentry incidents list [--open] [--severity CRITICAL]
    sentry incidents show <id>
    sentry incidents create --title … --severity HIGH [--description …]
    sentry incidents move <id> ANALYSE [--note …] [--summary …]   # transition NIST
    sentry incidents note <id> "message" [--action]
    sentry incidents from-alert <id-alerte>

Les actions faites en ligne de commande sont tracées sans auteur (opérateur système) ; l'API
trace l'utilisateur authentifié.
"""

import asyncio
from collections.abc import Awaitable, Callable
from uuid import UUID

import click
from rich.console import Console
from rich.table import Table
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app.models import Incident
from sentry.modules.incidents import service
from sentry.modules.incidents.service import (
    IncidentClosedError,
    IncidentNotFoundError,
    LinkTargetNotFoundError,
)
from sentry.modules.incidents.state_machine import (
    ClosureRequirementError,
    InvalidTransitionError,
    next_states,
)
from sentry.shared.enums import IncidentEventType, IncidentStatus, Severity

console = Console()

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "green",
}
_ERRORS = (
    IncidentNotFoundError,
    IncidentClosedError,
    LinkTargetNotFoundError,
    InvalidTransitionError,
    ClosureRequirementError,
    ValueError,
)


def _run[T](work: Callable[[AsyncSession], Awaitable[T]]) -> T:
    from sentry.app.database import dispose_engine, get_session_factory

    async def _main() -> T:
        try:
            async with get_session_factory()() as session:
                result = await work(session)
                await session.commit()
                return result
        finally:
            await dispose_engine()

    try:
        return asyncio.run(_main())
    except _ERRORS as exc:
        console.print(f"[red]Refusé :[/] {exc}")
        raise SystemExit(1) from exc


def _uuid(value: str) -> UUID:
    try:
        return UUID(value)
    except ValueError as exc:
        raise click.BadParameter(f"identifiant invalide : {value}") from exc


@click.group()
def incidents() -> None:
    """Incidents de sécurité : cycle de vie NIST SP 800-61, chronologie immuable."""


@incidents.command("list")
@click.option("--open", "open_only", is_flag=True, help="Seulement les incidents non clos.")
@click.option("--severity", type=click.Choice([s.value for s in Severity]), default=None)
@click.option("--limit", type=click.IntRange(1, 200), default=20, show_default=True)
def incidents_list(open_only: bool, severity: str | None, limit: int) -> None:
    """Incidents, les plus graves d'abord."""

    async def _list(session: AsyncSession) -> service.IncidentPage:
        return await service.list_incidents(
            session,
            limit=limit,
            offset=0,
            severity=Severity(severity) if severity else None,
            open_only=open_only,
        )

    page = _run(_list)
    if not page.items:
        console.print("Aucun incident.")
        return
    table = Table(title=f"Incidents ({len(page.items)} sur {page.total})")
    table.add_column("Identifiant", no_wrap=True)
    for column in ("Sévérité", "Statut", "Titre", "Ouvert le"):
        table.add_column(column)
    for i in page.items:
        sev = Severity(i.severity)
        table.add_row(
            str(i.id),
            f"[{_SEVERITY_STYLE[sev]}]{sev}[/]",
            i.status,
            i.title,
            f"{i.created_at:%Y-%m-%d %H:%M}",
        )
    console.print(table)


def _print(incident: Incident) -> None:
    sev = Severity(incident.severity)
    console.print(
        f"[bold]{incident.title}[/]\n{incident.id} · [{_SEVERITY_STYLE[sev]}]{sev}[/] · "
        f"{incident.status}"
    )
    console.print(incident.description)
    allowed = ", ".join(sorted(next_states(IncidentStatus(incident.status)))) or "aucune"
    console.print(f"Transitions possibles : {allowed}")
    if incident.cves:
        console.print("CVE : " + ", ".join(link.cve_id for link in incident.cves))
    if incident.indicators:
        console.print(f"IOC associés : {len(incident.indicators)}")
    table = Table(title="Chronologie (immuable)")
    for column in ("Date", "Événement", "Message"):
        table.add_column(column)
    for e in incident.events:
        table.add_row(f"{e.created_at:%Y-%m-%d %H:%M:%S}", e.event_type, e.message)
    console.print(table)


@incidents.command("show")
@click.argument("incident_id")
def incidents_show(incident_id: str) -> None:
    """Détail d'un incident et sa chronologie."""

    async def _show(session: AsyncSession) -> Incident:
        return await service.get_incident(session, _uuid(incident_id))

    _print(_run(_show))


@incidents.command("create")
@click.option("--title", required=True)
@click.option("--severity", required=True, type=click.Choice([s.value for s in Severity]))
@click.option("--description", default="", help="Contexte (défaut : le titre).")
def incidents_create(title: str, severity: str, description: str) -> None:
    """Ouvre un incident en statut NOUVEAU."""

    async def _create(session: AsyncSession) -> Incident:
        incident = await service.create_incident(
            session,
            title=title,
            description=description,
            severity=Severity(severity),
            author_id=None,
        )
        return incident

    incident = _run(_create)
    console.print(f"[green]Incident ouvert :[/] {incident.id}")


@incidents.command("move")
@click.argument("incident_id")
@click.argument("target", type=click.Choice([s.value for s in IncidentStatus]))
@click.option("--note", default=None)
@click.option("--summary", default=None, help="Résumé de clôture (obligatoire pour CLOTURE).")
def incidents_move(incident_id: str, target: str, note: str | None, summary: str | None) -> None:
    """Transition d'état (NOUVEAU → ANALYSE → … → CLOTURE)."""

    async def _move(session: AsyncSession) -> Incident:
        return await service.transition(
            session,
            _uuid(incident_id),
            IncidentStatus(target),
            author_id=None,
            note=note,
            closure_summary=summary,
        )

    incident = _run(_move)
    console.print(f"[green]{incident.id} :[/] {incident.status}")


@incidents.command("note")
@click.argument("incident_id")
@click.argument("message")
@click.option("--action", is_flag=True, help="Action menée (plutôt qu'un commentaire).")
def incidents_note(incident_id: str, message: str, action: bool) -> None:
    """Ajoute un commentaire ou une action à la chronologie."""
    kind = IncidentEventType.ACTION_TAKEN if action else IncidentEventType.COMMENT

    async def _note(session: AsyncSession) -> None:
        await service.add_note(session, _uuid(incident_id), message, author_id=None, kind=kind)

    _run(_note)
    console.print("[green]Ajouté à la chronologie.[/]")


@incidents.command("from-alert")
@click.argument("alert_id")
def incidents_from_alert(alert_id: str) -> None:
    """Ouvre l'incident de réponse à une alerte CVE (idempotent)."""

    async def _open(session: AsyncSession) -> tuple[Incident, bool]:
        return await service.open_from_alert(session, _uuid(alert_id), author_id=None)

    incident, created = _run(_open)
    verb = "ouvert" if created else "déjà ouvert"
    console.print(f"[green]Incident {verb} :[/] {incident.id} — {incident.title}")
