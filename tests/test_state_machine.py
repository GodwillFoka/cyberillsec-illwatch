"""Tests de la machine d'état des incidents — RF-18."""

import pytest

from sentry.modules.incidents.state_machine import (
    ClosureRequirementError,
    InvalidTransitionError,
    can_transition,
    next_states,
    validate_transition,
)
from sentry.shared.enums import IncidentStatus

NOMINAL_PATH = [
    IncidentStatus.NOUVEAU,
    IncidentStatus.ANALYSE,
    IncidentStatus.CONFINEMENT,
    IncidentStatus.ERADICATION,
    IncidentStatus.RECUPERATION,
    IncidentStatus.CLOTURE,
]


def test_parcours_nominal_complet() -> None:
    for current, target in zip(NOMINAL_PATH, NOMINAL_PATH[1:], strict=False):
        summary = "Post-mortem rédigé." if target is IncidentStatus.CLOTURE else None
        validate_transition(current, target, closure_summary=summary)


def test_saut_d_etape_interdit() -> None:
    with pytest.raises(InvalidTransitionError):
        validate_transition(IncidentStatus.NOUVEAU, IncidentStatus.CLOTURE)


def test_cloture_sans_post_mortem_refusee() -> None:
    with pytest.raises(ClosureRequirementError):
        validate_transition(IncidentStatus.RECUPERATION, IncidentStatus.CLOTURE)

    with pytest.raises(ClosureRequirementError):
        validate_transition(
            IncidentStatus.RECUPERATION, IncidentStatus.CLOTURE, closure_summary="   "
        )


def test_cloture_est_un_etat_terminal() -> None:
    assert next_states(IncidentStatus.CLOTURE) == frozenset()
    for target in IncidentStatus:
        assert not can_transition(IncidentStatus.CLOTURE, target)


def test_retour_en_analyse_autorise_apres_confinement() -> None:
    assert can_transition(IncidentStatus.CONFINEMENT, IncidentStatus.ANALYSE)
    assert can_transition(IncidentStatus.ERADICATION, IncidentStatus.ANALYSE)


def test_tous_les_etats_sont_couverts_par_le_graphe() -> None:
    from sentry.modules.incidents.state_machine import ALLOWED_TRANSITIONS

    assert set(ALLOWED_TRANSITIONS) == set(IncidentStatus)
