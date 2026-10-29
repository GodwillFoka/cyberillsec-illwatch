"""Score de confiance des IOC : M8, ADR-017."""

from datetime import UTC, datetime, timedelta

import pytest

from illwatch.modules.correlation.confidence import (
    HIGH,
    MEDIUM,
    ConfidenceBreakdown,
    compute_confidence,
)

NOW = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)


def score(
    reliabilities: list[str], ioc_type: str = "IPV4", age_days: float = 0, hits: int = 1
) -> ConfidenceBreakdown:
    return compute_confidence(
        reliabilities=reliabilities,
        ioc_type=ioc_type,
        last_seen=NOW - timedelta(days=age_days),
        hit_count=hits,
        now=NOW,
    )


def test_bornes_et_niveaux() -> None:
    best = score(["A", "A", "B"], hits=1000)
    assert best.total <= 100 and best.level == "ELEVEE"
    worst = score(["F"], age_days=365)
    assert worst.total >= 0 and worst.level == "FAIBLE"
    assert MEDIUM < HIGH


def test_corroboration_augmente_la_confiance() -> None:
    one = score(["C"])
    two = score(["C", "C"])
    assert two.sources > one.sources and two.total > one.total
    assert two.level == "ELEVEE" and one.level == "MOYENNE"


def test_fiabilite_ordonnee() -> None:
    totals = [score([cote]).total for cote in "ABCDEF"]
    assert totals == sorted(totals, reverse=True)


@pytest.mark.parametrize(
    ("ioc_type", "half_life"), [("IPV4", 7), ("DOMAIN", 30), ("HASH_SHA256", 180)]
)
def test_fraicheur_demi_vie_par_type(ioc_type: str, half_life: int) -> None:
    fresh = score(["C"], ioc_type=ioc_type)
    halved = score(["C"], ioc_type=ioc_type, age_days=half_life)
    assert fresh.freshness == 30.0
    assert halved.freshness == pytest.approx(15.0, abs=0.1)


def test_ip_ancienne_moins_fiable_qu_une_empreinte_ancienne() -> None:
    assert score(["B"], "IPV4", age_days=60).total < score(["B"], "HASH_SHA256", age_days=60).total


def test_recurrence_plafonnee() -> None:
    assert score(["C"], hits=1).recurrence == 0
    assert 0 < score(["C"], hits=3).recurrence < 10
    assert score(["C"], hits=10_000).recurrence == 10


def test_soumission_manuelle_sans_source() -> None:
    assert score([]).total == score(["C"]).total


def test_date_naive_traitee_en_utc() -> None:
    naive = compute_confidence(
        reliabilities=["C"],
        ioc_type="URL",
        last_seen=NOW.replace(tzinfo=None),
        hit_count=1,
        now=NOW,
    )
    assert naive.freshness == 30.0
