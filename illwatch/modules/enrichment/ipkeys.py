"""Clés de comparaison des adresses IP.

Une adresse devient une chaîne hexadécimale de 32 caractères : l'adresse IPv6 sur 128 bits,
ou pour une IPv4 l'adresse IPv6 correspondante « ::ffff:a.b.c.d ». Toutes les clés ont la
même longueur, donc l'ordre alphabétique est l'ordre numérique : une recherche « dernière
plage dont le début est ≤ à l'adresse » suffit, avec un simple index B-tree.
"""

import ipaddress

KEY_LENGTH = 32


def ip_key(value: str) -> str:
    """Clé d'une adresse IPv4 ou IPv6. Lève `ValueError` si la valeur n'en est pas une."""
    address = ipaddress.ip_address(value.strip())
    if isinstance(address, ipaddress.IPv4Address):
        address = ipaddress.IPv6Address(f"::ffff:{address}")
    return f"{int(address):032x}"


def is_public(value: str) -> bool:
    """Adresse routable sur Internet : seules celles-ci ont un pays ou un opérateur utiles."""
    try:
        return ipaddress.ip_address(value.strip()).is_global
    except ValueError:
        return False
