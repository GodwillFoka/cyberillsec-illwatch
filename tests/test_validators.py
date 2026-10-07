"""Tests de détection et normalisation des IOC — RF-07 / RF-08."""

import pytest

from sentry.modules.threat_feeds.validators import (
    InvalidIndicatorError,
    detect_indicator_type,
    is_private_ip,
    normalize_indicator,
)
from sentry.shared.enums import IndicatorType


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("185.220.101.5", IndicatorType.IPV4),
        ("2001:db8::1", IndicatorType.IPV6),
        ("secure-login-bank.xyz", IndicatorType.DOMAIN),
        ("https://phish.example.com/login", IndicatorType.URL),
        ("http://1.2.3.4/payload.bin", IndicatorType.URL),
        ("d41d8cd98f00b204e9800998ecf8427e", IndicatorType.HASH_MD5),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", IndicatorType.HASH_SHA1),
        (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            IndicatorType.HASH_SHA256,
        ),
        ("attacker@evil.tld", IndicatorType.EMAIL),
    ],
)
def test_detection_des_types(value: str, expected: IndicatorType) -> None:
    assert detect_indicator_type(value) is expected


@pytest.mark.parametrize("value", ["", "   ", "pas un ioc", "http://", "localhost"])
def test_valeurs_invalides_rejetees(value: str) -> None:
    with pytest.raises(InvalidIndicatorError):
        detect_indicator_type(value)


def test_normalisation_insensible_a_la_casse() -> None:
    assert normalize_indicator("  EVIL.Example.COM ") == (IndicatorType.DOMAIN, "evil.example.com")
    assert normalize_indicator("D41D8CD98F00B204E9800998ECF8427E") == (
        IndicatorType.HASH_MD5,
        "d41d8cd98f00b204e9800998ecf8427e",
    )


def test_normalisation_ipv6_canonique() -> None:
    a = normalize_indicator("2001:0db8:0000:0000:0000:0000:0000:0001")
    b = normalize_indicator("2001:db8::1")
    assert a == b


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("10.0.0.1", True),
        ("192.168.1.1", True),
        ("127.0.0.1", True),
        ("169.254.1.1", True),
        ("185.220.101.5", False),
        ("8.8.8.8", False),
        ("pas-une-ip", False),
    ],
)
def test_detection_des_plages_privees(value: str, expected: bool) -> None:
    assert is_private_ip(value) is expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Example.COM.", (IndicatorType.DOMAIN, "example.com")),
        ("evil[.]example[.]com", (IndicatorType.DOMAIN, "evil.example.com")),
        (
            "hxxps://Evil.Example.com:443/Payload.EXE#x",
            (IndicatorType.URL, "https://evil.example.com/Payload.EXE"),
        ),
        ("HTTP://evil.example.com:8080", (IndicatorType.URL, "http://evil.example.com:8080/")),
        ("https://evil.example.com/a?Q=1", (IndicatorType.URL, "https://evil.example.com/a?Q=1")),
        ("198.51.100[.]7", (IndicatorType.IPV4, "198.51.100.7")),
        ("Attacker[@]Evil.example.com", (IndicatorType.EMAIL, "attacker@evil.example.com")),
    ],
)
def test_normalisation_des_graphies_equivalentes(
    raw: str, expected: tuple[IndicatorType, str]
) -> None:
    assert normalize_indicator(raw) == expected


def test_graphies_equivalentes_convergent_vers_une_seule_cle() -> None:
    variants = ["Example.COM", "example.com", "EXAMPLE.COM", "example.com.", "example[.]com"]
    assert {normalize_indicator(v) for v in variants} == {(IndicatorType.DOMAIN, "example.com")}


@pytest.mark.parametrize(
    "value",
    [
        "http://hote.example:99999/charge",  # port hors 0-65535 (OTX, 07/10)
        "https://[::1/chemin",  # hôte IPv6 non refermé
    ],
)
def test_url_malformee_rejetee_sans_exception_brute(value: str) -> None:
    """Une URL que `urllib` refuse doit être rejetée seule, jamais faire échouer le lot."""
    with pytest.raises(InvalidIndicatorError):
        normalize_indicator(value)
