"""Validation et typage automatique des IOC — §3.3.2 du Cahier des Charges."""

import ipaddress
import re
from urllib.parse import urlparse

from sentry.shared.enums import IndicatorType

_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
_EMAIL_RE = re.compile(r"^[^@\s]+@(?=.{1,253}$)[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


class InvalidIndicatorError(ValueError):
    """La valeur fournie ne correspond à aucun type d'IOC supporté."""


def is_private_ip(value: str) -> bool:
    """Vrai si l'adresse est privée, de loopback, link-local ou réservée."""
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved


def detect_indicator_type(value: str) -> IndicatorType:
    """Détermine le type d'un IOC à partir de sa valeur brute.

    L'ordre d'évaluation est significatif : les hashs sont testés avant les
    domaines, et les URL avant les domaines, pour éviter tout recouvrement.

    Raises:
        InvalidIndicatorError: aucune forme reconnue.
    """
    candidate = value.strip()
    if not candidate:
        raise InvalidIndicatorError("Valeur d'indicateur vide.")

    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        return IndicatorType.IPV4 if addr.version == 4 else IndicatorType.IPV6

    if _SHA256_RE.match(candidate):
        return IndicatorType.HASH_SHA256
    if _SHA1_RE.match(candidate):
        return IndicatorType.HASH_SHA1
    if _MD5_RE.match(candidate):
        return IndicatorType.HASH_MD5

    if candidate.lower().startswith(("http://", "https://")):
        parsed = urlparse(candidate)
        if parsed.netloc:
            return IndicatorType.URL
        raise InvalidIndicatorError(f"URL malformée : {value!r}")

    if _EMAIL_RE.match(candidate):
        return IndicatorType.EMAIL

    if _DOMAIN_RE.match(candidate):
        return IndicatorType.DOMAIN

    raise InvalidIndicatorError(f"Type d'indicateur non reconnu pour : {value!r}")


def normalize_indicator(value: str) -> tuple[IndicatorType, str]:
    """Retourne le couple (type, valeur normalisée) prêt pour la déduplication.

    La normalisation garantit qu'une même entité observée sous deux graphies
    (casse différente, espaces) ne crée pas deux lignes distinctes en base.
    """
    candidate = value.strip()
    ioc_type = detect_indicator_type(candidate)

    if ioc_type in (IndicatorType.DOMAIN, IndicatorType.EMAIL):
        return ioc_type, candidate.lower()
    if ioc_type in (IndicatorType.HASH_MD5, IndicatorType.HASH_SHA1, IndicatorType.HASH_SHA256):
        return ioc_type, candidate.lower()
    if ioc_type is IndicatorType.IPV6:
        return ioc_type, str(ipaddress.ip_address(candidate))
    return ioc_type, candidate
