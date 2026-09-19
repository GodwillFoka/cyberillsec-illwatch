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
