"""Machine d'état des incidents — RF-18 (NIST SP 800-61 Rev. 2).

Transitions autorisées :

    NOUVEAU → ANALYSE → CONFINEMENT → ERADICATION → RECUPERATION → CLOTURE

Règles de gestion (§3.3.4) :
  * aucune transition arrière n'est autorisée hors retour explicite ANALYSE ;
  * un incident ne peut être clôturé sans résumé de clôture / post-mortem ;
  * chaque transition génère un événement immuable dans `incident_events`.
"""

from illwatch.shared.enums import IncidentStatus

ALLOWED_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.NOUVEAU: frozenset({IncidentStatus.ANALYSE}),
    IncidentStatus.ANALYSE: frozenset({IncidentStatus.CONFINEMENT}),
    IncidentStatus.CONFINEMENT: frozenset({IncidentStatus.ERADICATION, IncidentStatus.ANALYSE}),
    IncidentStatus.ERADICATION: frozenset({IncidentStatus.RECUPERATION, IncidentStatus.ANALYSE}),
    IncidentStatus.RECUPERATION: frozenset({IncidentStatus.CLOTURE, IncidentStatus.ANALYSE}),
    IncidentStatus.CLOTURE: frozenset(),
}


class InvalidTransitionError(ValueError):
    """Transition d'état interdite par la machine d'état."""


class ClosureRequirementError(ValueError):
    """Clôture tentée sans résumé de post-mortem."""


def can_transition(current: IncidentStatus, target: IncidentStatus) -> bool:
    """Indique si la transition `current → target` est permise."""
    return target in ALLOWED_TRANSITIONS[current]


def validate_transition(
    current: IncidentStatus,
    target: IncidentStatus,
    *,
    closure_summary: str | None = None,
) -> None:
    """Valide une transition ou lève une exception explicite.

    Raises:
        InvalidTransitionError: la transition n'est pas dans le graphe autorisé.
        ClosureRequirementError: clôture sans résumé de post-mortem renseigné.
    """
    if not can_transition(current, target):
        allowed = ", ".join(sorted(ALLOWED_TRANSITIONS[current])) or "aucune (état terminal)"
        raise InvalidTransitionError(
            f"Transition interdite {current} → {target}. Transitions permises : {allowed}."
        )

    if target is IncidentStatus.CLOTURE and not (closure_summary and closure_summary.strip()):
        raise ClosureRequirementError(
            "Un incident ne peut être clôturé sans résumé de clôture ou note de post-mortem."
        )


def next_states(current: IncidentStatus) -> frozenset[IncidentStatus]:
    """États atteignables depuis `current`."""
    return ALLOWED_TRANSITIONS[current]
