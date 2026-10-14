"""`illwatch attack` — référentiel MITRE ATT&CK Enterprise (M10, ADR-023).

    illwatch attack import                     # télécharge la dernière version publiée par MITRE
    illwatch attack import --file enterprise-attack.json   # poste sans accès direct
    illwatch attack status
    illwatch attack show T1190

ATT&CK® © The MITRE Corporation ; reproduit et distribué avec l'autorisation de MITRE.
"""

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import click
from rich.console import Console

console = Console()

DEFAULT_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
MAX_BYTES = 120 * 1024 * 1024


def _run[T](work: Callable[[Any], Awaitable[T]]) -> T:
    from illwatch.app.database import dispose_engine, get_session_factory

    async def _main() -> T:
        try:
            async with get_session_factory()() as session:
                result = await work(session)
                await session.commit()
                return result
        finally:
            await dispose_engine()

    return asyncio.run(_main())


def _download(url: str) -> bytes:
    import httpx

    chunks: list[bytes] = []
    size = 0
    with httpx.stream("GET", url, timeout=120, follow_redirects=True) as response:
        response.raise_for_status()
        for chunk in response.iter_bytes():
            size += len(chunk)
            if size > MAX_BYTES:
                raise click.ClickException("Bundle trop volumineux (> 120 Mo) : refusé.")
            chunks.append(chunk)
    return b"".join(chunks)


@click.group()
def attack() -> None:
    """Référentiel MITRE ATT&CK : techniques, groupes, logiciels (M10)."""


@attack.command("import")
@click.option(
    "--file",
    "path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Bundle STIX déjà téléchargé (enterprise-attack.json).",
)
@click.option("--url", default=DEFAULT_URL, show_default=True)
def attack_import(path: Path | None, url: str) -> None:
    """Importe (ou remplace) le référentiel ATT&CK Enterprise."""
    from illwatch.modules.attack.service import import_attack
    from illwatch.modules.attack.stix import AttackBundleError, parse_bundle
    from illwatch.modules.foundation.audit import cli_actor, record_in_session

    if path is not None:
        content = path.read_bytes()
    else:
        console.print(f"Téléchargement de {url} …")
        try:
            content = _download(url)
        except click.ClickException:
            raise
        except Exception as exc:  # noqa: BLE001 - message lisible, sans trace
            raise click.ClickException(
                f"Téléchargement impossible ({exc}). Téléchargez le fichier puis "
                "`illwatch attack import --file enterprise-attack.json`."
            ) from exc
    try:
        data = parse_bundle(content)
    except AttackBundleError as exc:
        raise click.ClickException(str(exc)) from exc

    async def _work(session: Any) -> dict[str, Any]:
        report = await import_attack(session, data)
        await record_in_session(
            session, "attack.import", actor_name=cli_actor(), target_type="attack", detail=report
        )
        return report

    report = _run(_work)
    console.print(
        f"[green]✔[/] ATT&CK {report['version'] or '?'} : {report['techniques']} techniques, "
        f"{report['actors']} groupes et logiciels, {report['uses']} relations « utilise »."
    )
    console.print("ATT&CK® © The MITRE Corporation, reproduit avec son autorisation.")


@attack.command("status")
def attack_status_command() -> None:
    """Date d'import et volumes du référentiel."""
    from illwatch.modules.attack.service import attack_status

    state = _run(attack_status)
    if not state.techniques or state.imported_at is None:
        console.print("Référentiel ATT&CK non importé : `illwatch attack import`.")
        return
    console.print(
        f"ATT&CK importé le {state.imported_at:%d/%m/%Y %H:%M} UTC · "
        f"{state.techniques} techniques · {state.actors} groupes et logiciels"
    )


@attack.command("show")
@click.argument("technique_id")
def attack_show(technique_id: str) -> None:
    """Une technique et les groupes ou logiciels qui l'emploient."""
    from sqlalchemy import select

    from illwatch.app.models import AttackActor, AttackTechnique, AttackUse

    async def _work(session: Any) -> tuple[Any, list[tuple[str, str, str]]]:
        technique = await session.get(AttackTechnique, technique_id.upper())
        rows = (
            await session.execute(
                select(AttackActor.id, AttackActor.kind, AttackActor.name)
                .join(AttackUse, AttackUse.actor_id == AttackActor.id)
                .where(AttackUse.technique_id == technique_id.upper())
                .order_by(AttackActor.kind, AttackActor.name)
            )
        ).all()
        return technique, [tuple(r) for r in rows]

    technique, actors = _run(_work)
    if technique is None:
        raise click.ClickException(f"{technique_id} inconnue (référentiel importé ?).")
    console.print(f"[bold]{technique.id}[/] {technique.name} · {', '.join(technique.tactics)}")
    for actor_id, kind, name in actors[:60]:
        console.print(f"  {actor_id:<6} {kind:<8} {name}")
    if len(actors) > 60:
        console.print(f"  … et {len(actors) - 60} autres")
