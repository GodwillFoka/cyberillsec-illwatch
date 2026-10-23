"""Parité entre le moteur et le simulateur du site de présentation (ADR-027, décision 6).

Le site (Website/src/assets/js/score.js) affiche la formule du moteur ; s'ils divergent, le
site promet un comportement que la plateforme n'a pas. Les mêmes cas sont vérifiés côté
JavaScript par Website/tests/score.test.mjs.
"""

import json
from pathlib import Path

import pytest

from illwatch.modules.cve_tracker.scoring import compute_risk_breakdown

VECTORS = Path(__file__).resolve().parents[1] / "Website" / "tests" / "score-vectors.json"
CASES = json.loads(VECTORS.read_text(encoding="utf-8"))["cases"]


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_moteur_conforme_aux_cas_du_site(case: dict[str, object]) -> None:
    given = case["input"]
    expected = case["expected"]
    assert isinstance(given, dict) and isinstance(expected, dict)
    result = compute_risk_breakdown(
        cvss=given["cvss"],
        epss=given["epss"],
        is_kev=given["kev"],
        has_public_exploit=given["exploit"],
        has_ransomware_campaign=given["ransomware"],
    )
    assert result.total == expected["total"]
    assert result.priority.value.startswith(expected["priority"])
    assert result.kev_floor is expected["kevFloor"]
