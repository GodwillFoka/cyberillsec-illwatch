"""Validation et typage automatique des IOC : §3.3.2 du Cahier des Charges."""

import ipaddress
import re
from urllib.parse import urlparse, urlsplit, urlunsplit

from illwatch.shared.enums import IndicatorType

_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
_EMAIL_RE = re.compile(r"^[^@\s]+@(?=.{1,253}$)[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


class InvalidIndicatorError(ValueError):
    """La valeur fournie ne correspond à aucun type d'IOC supporté."""


# Plages CIDR : au-delà de ces tailles, un « IOC » couvrirait des opérateurs entiers et
# rendrait suspecte une part notable d'Internet. Les réseaux internes ne sont jamais des IOC.
MIN_PREFIX = {4: 16, 6: 32}
_INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/8",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)


_INTERNAL_V4 = tuple(n for n in _INTERNAL_NETWORKS if isinstance(n, ipaddress.IPv4Network))
_INTERNAL_V6 = tuple(n for n in _INTERNAL_NETWORKS if isinstance(n, ipaddress.IPv6Network))


def _is_internal_network(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    if isinstance(network, ipaddress.IPv4Network):
        return any(network.overlaps(internal) for internal in _INTERNAL_V4)
    return any(network.overlaps(internal) for internal in _INTERNAL_V6)


def _network(candidate: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    if "/" not in candidate or "://" in candidate:
        return None
    try:
        return ipaddress.ip_network(candidate, strict=False)
    except ValueError:
        return None


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

    if _network(candidate) is not None:
        return IndicatorType.NETWORK

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


# Formes « désamorcées » (defanged) courantes dans les bulletins CTI, pour qu'un IOC
# copié depuis un rapport (`hxxps://evil[.]com`) ne soit pas cliquable par erreur.
_DEFANG_REPLACEMENTS = (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[:]", ":"), ("[@]", "@"))
_DEFANG_SCHEMES = {"hxxp://": "http://", "hxxps://": "https://"}
_DEFAULT_PORTS = {"http": 80, "https": 443}


def refang(value: str) -> str:
    """Rétablit la forme exploitable d'un IOC désamorcé (`hxxps://evil[.]com` → `https://evil.com`)."""
    result = value
    for defanged, plain in _DEFANG_REPLACEMENTS:
        result = result.replace(defanged, plain)
    lowered = result.lower()
    for defanged, plain in _DEFANG_SCHEMES.items():
        if lowered.startswith(defanged):
            return plain + result[len(defanged) :]
    return result


def _normalize_url(url: str) -> str:
    """Schéma et hôte en minuscules (insensibles à la casse selon la RFC 3986), port par
    défaut et fragment retirés. Le chemin et la requête gardent leur casse : ils sont
    sensibles à la casse côté serveur."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").rstrip(".")
    netloc = f"[{host}]" if ":" in host else host
    if parts.port is not None and parts.port != _DEFAULT_PORTS.get(scheme):
        netloc = f"{netloc}:{parts.port}"
    if parts.username is not None:
        userinfo = parts.username + (f":{parts.password}" if parts.password is not None else "")
        netloc = f"{userinfo}@{netloc}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def normalize_indicator(value: str) -> tuple[IndicatorType, str]:
    """Retourne le couple (type, valeur normalisée) prêt pour la déduplication.

    La normalisation garantit qu'une même entité observée sous plusieurs graphies
    (casse, espaces, forme désamorcée, point final DNS, notation IP) ne crée pas
    plusieurs lignes en base : `Example.COM`, `example.com.` et `example[.]com`
    deviennent tous `example.com`.
    """
    try:
        return _normalize(value)
    except InvalidIndicatorError:
        raise
    except ValueError as exc:
        # `urllib` lève ValueError sur un port hors 0-65535 ou un hôte IPv6 mal formé
        # (`http://hote:99999/`, vu dans OTX le 07/10) : la valeur seule est rejetée,
        # jamais le lot entier.
        raise InvalidIndicatorError(f"Valeur malformée {value!r} : {exc}") from exc


def _normalize(value: str) -> tuple[IndicatorType, str]:
    candidate = refang(value.strip())
    if candidate.endswith(".") and "://" not in candidate:
        candidate = candidate.rstrip(".")
    ioc_type = detect_indicator_type(candidate)

    if ioc_type in (IndicatorType.DOMAIN, IndicatorType.EMAIL):
        return ioc_type, candidate.lower()
    if ioc_type in (IndicatorType.HASH_MD5, IndicatorType.HASH_SHA1, IndicatorType.HASH_SHA256):
        return ioc_type, candidate.lower()
    if ioc_type in (IndicatorType.IPV4, IndicatorType.IPV6):
        return ioc_type, str(ipaddress.ip_address(candidate))
    if ioc_type is IndicatorType.URL:
        return ioc_type, _normalize_url(candidate)
    if ioc_type is IndicatorType.NETWORK:
        return _normalize_network(candidate)
    return ioc_type, candidate


def _normalize_network(candidate: str) -> tuple[IndicatorType, str]:
    """`203.0.113.7/24` → `203.0.113.0/24` ; une plage d'une seule adresse (/32, /128)
    devient cette adresse (type IPv4/IPv6) ; plage trop large ou interne refusée."""
    network = _network(candidate)
    if network is None:  # pragma: no cover - garanti par detect_indicator_type
        raise InvalidIndicatorError(f"Plage CIDR malformée : {candidate!r}")
    if network.prefixlen == network.max_prefixlen:
        address = network.network_address
        return (
            IndicatorType.IPV4 if address.version == 4 else IndicatorType.IPV6,
            str(address),
        )
    minimum = MIN_PREFIX[network.version]
    if network.prefixlen < minimum:
        raise InvalidIndicatorError(
            f"Plage {network} trop large (/{minimum} au plus large) : elle couvrirait des "
            f"opérateurs entiers."
        )
    if _is_internal_network(network):
        raise InvalidIndicatorError(f"Plage {network} interne ou réservée : pas un IOC.")
    return IndicatorType.NETWORK, str(network)


def network_contains(cidr: str, address: str) -> bool:
    """Vrai si l'adresse appartient à la plage (versions différentes : faux)."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.version == network.version and ip in network
