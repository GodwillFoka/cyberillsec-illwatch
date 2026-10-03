"""Analyse des formats de flux — RF-06 (CSV, JSON, STIX 2.1)."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentry.modules.threat_feeds.parsers import (
    FeedParseError,
    parse_csv,
    parse_feed,
    parse_json,
    parse_stix,
)
from sentry.shared.enums import FeedType, Severity

FIXTURES = Path(__file__).parent / "fixtures" / "feeds"


def _read(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def test_csv_urlhaus_en_tete_commente() -> None:
    result = parse_csv(_read("urlhaus_recent.csv"))
    values = [o.value for o in result.observations]
    assert values[0] == "http://198.51.100.23:40125/i"
    assert "hxxps://Payload.Example.net/drop/Stage2.EXE" in values  # normalisé à l'ingestion
    assert len(values) == 4  # la ligne invalide est transmise : l'ingestion la rejettera
    first = result.observations[0]
    assert first.observed_at == datetime(2026, 9, 27, 10, 1, 11, tzinfo=UTC)
    assert first.description == "malware_download"


def test_csv_feodo_colonne_dst_ip() -> None:
    result = parse_csv(_read("feodo_ipblocklist.csv"), default_severity=Severity.HIGH)
    assert [o.value for o in result.observations] == [
        "203.0.113.50",
        "203.0.113.51",
        "2001:db8:0:0:0:0:0:77",
    ]
    assert {o.severity for o in result.observations} == {Severity.HIGH}
    assert result.observations[0].description == "QakBot"


def test_csv_en_tete_explicite_et_liste_simple() -> None:
    explicit = parse_csv(b"indicator,severity,date\nevil.example.com,critical,2026-09-01\n")
    assert explicit.observations[0].severity is Severity.CRITICAL
    assert explicit.observations[0].observed_at == datetime(2026, 9, 1, tzinfo=UTC)

    bare = parse_csv(b"# liste brute\n1.2.3.4\nexample.org\n\n")
    assert [o.value for o in bare.observations] == ["1.2.3.4", "example.org"]


def test_csv_sans_colonne_identifiable_ignore_les_lignes() -> None:
    result = parse_csv(b"a,b\n1,2\n")
    assert result.observations == []
    assert result.skipped == 2


def test_json_formes_multiples() -> None:
    result = parse_json(_read("generic.json"))
    assert [o.value for o in result.observations] == [
        "evil.example.com",
        "198.51.100.99",
        "d41d8cd98f00b204e9800998ecf8427e",
    ]
    assert result.skipped == 2
    first, second = result.observations[:2]
    assert first.severity is Severity.HIGH
    assert first.description == "phishing"
    assert first.observed_at == datetime(2026, 9, 26, 10, tzinfo=UTC)
    assert second.description == "c2, cobalt-strike"


@pytest.mark.parametrize("content", [b"{pas du json", b'{"total": 3}', b'"texte"'])
def test_json_invalide(content: bytes) -> None:
    with pytest.raises(FeedParseError):
        parse_json(content)


def test_stix_bundle() -> None:
    result = parse_stix(_read("stix_bundle.json"))
    values = [o.value for o in result.observations]
    assert values == [
        "192.0.2.200",
        "Update-Check.Example.org",
        "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        "https://phish.example.com/login?id=A1",
    ]
    assert result.skipped == 2  # indicateur révoqué + motif YARA
    assert result.observations[0].description == "C2 QakBot"
    assert result.observations[0].observed_at == datetime(2026, 9, 25, 12, tzinfo=UTC)


def test_stix_invalide() -> None:
    with pytest.raises(FeedParseError):
        parse_stix(b'{"type": "indicator"}')


def test_aiguillage_par_format() -> None:
    assert parse_feed(b"1.2.3.4\n", FeedType.CSV).observations[0].value == "1.2.3.4"
    assert parse_feed(b'["1.2.3.4"]', FeedType.JSON).observations[0].value == "1.2.3.4"
    assert parse_feed(_read("stix_bundle.json"), FeedType.STIX).observations
