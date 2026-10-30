"""Version installée contre versions vulnérables (configurations CPE de la NVD) : ADR-021.

La correspondance par nom de produit (ADR-020) est complétée par ce que la NVD publie pour
chaque CVE : produits touchés et plages de versions (« de 5.8 incluse à 5.10.102 exclue »).

- Aucun produit de la CVE ne correspond à l'actif → la description cite le produit sans qu'il
  soit vulnérable (Shellshock : faille de Bash, OpenSSH cité comme vecteur) → pas d'évènement.
- La version déclarée est hors de toutes les plages → pas d'évènement (Dirty COW, corrigée en
  4.8.3, sur un noyau 7.1.5).
- Plages inconnues (CVE pas encore analysée) ou version non déclarée → évènement conservé :
  dans le doute, ILLWATCH signale.
- Version dans la plage mais seulement sur certaines plateformes (configuration ET de la NVD :
  « Redis sur Debian 9 à 11 », CVE-2022-0543) ou version « - » (sans objet : faille d'un paquet
  de distribution) → « conditionnel » : évènement conservé, condition affichée à l'analyste.
  Si l'actif déclare sa plateforme (« Debian 12 »), la condition est tranchée : plateforme
  requise → « vulnérable » ; plateforme différente → « hors_plateforme », pas d'évènement.

Comparaison « naturelle » : 10.5p1 > 10.5 ; 5.10.102 > 5.10.9 ; les suffixes de distribution
(+kali, -1, ~deb12) sont ignorés.
"""

import re
from collections.abc import Sequence
from typing import Any, Literal

Verdict = Literal[
    "vulnerable",
    "conditionnel",
    "hors_plage",
    "hors_plateforme",
    "autre_produit",
    "inconnu",
    "version_non_declaree",
]

_WILDCARDS = {"", "*", "-"}
_DISTRO_SUFFIX = re.compile(r"[+~].*$|-\d+(\.\d+)*$")
_TOKEN = re.compile(r"\d+|[a-z]+")


def product_key(name: str) -> str:
    """« Exchange Server » → exchange_server ; « Linux kernel » → linux_kernel."""
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def same_product(asset_product: str, cpe_product: str) -> bool:
    """Même produit, ou édition du produit (« confluence » ~ confluence_data_center)."""
    mine, theirs = product_key(asset_product), product_key(cpe_product)
    if not mine or not theirs:
        return False
    return mine == theirs or theirs.startswith(mine + "_") or mine.startswith(theirs + "_")


def version_key(raw: str) -> tuple[tuple[int, int | str], ...]:
    cleaned = _DISTRO_SUFFIX.sub("", raw.strip().lower())
    return tuple((0, int(t)) if t.isdigit() else (1, t) for t in _TOKEN.findall(cleaned))


_RANGES = (
    "versionStartIncluding",
    "versionStartExcluding",
    "versionEndIncluding",
    "versionEndExcluding",
)


def _conditional(entry: dict[str, Any]) -> bool:
    """Vulnérable seulement sous condition : plateforme requise, ou version « - » sans plage."""
    if entry.get("platforms"):
        return True
    return str(entry.get("version") or "") == "-" and not any(entry.get(k) for k in _RANGES)


def platforms(product: str, affected: Sequence[dict[str, Any]] | None) -> str | None:
    """Conditions à vérifier pour ce produit (plateformes requises par la NVD), ou None."""
    found = {
        str(e["platforms"])
        for e in affected or []
        if e.get("platforms") and same_product(product, str(e.get("product") or ""))
    }
    return " ; ".join(sorted(found))[:300] or None


def _trimmed(key: tuple[tuple[int, int | str], ...]) -> tuple[tuple[int, int | str], ...]:
    """9.0 ≡ 9 ; 20.04 reste 20.04."""
    out = list(key)
    while out and out[-1] == (0, 0):
        out.pop()
    return tuple(out)


def platform_matches(declared: str, required: str) -> bool:
    """Plateforme déclarée de l'actif (« Debian 12.5 ») contre une plateforme NVD
    (« debian_linux 12.0 », « windows_server_2022 »). Même famille, et même version quand
    les deux en ont une (la plus courte est préfixe de l'autre : 12 ≡ 12.5)."""
    name, _, required_version = required.strip().partition(" ")
    tokens = declared.split()
    declared_version = tokens[-1] if len(tokens) > 1 and tokens[-1][:1].isdigit() else ""
    declared_name = " ".join(tokens[:-1]) if declared_version else declared
    if not required_version:
        return same_product(declared, name) or same_product(declared_name, name)
    if not same_product(declared_name, name):
        return False
    if not declared_version:
        return True  # version de la plateforme inconnue : on ne peut pas l'écarter
    mine, theirs = _trimmed(version_key(declared_version)), _trimmed(version_key(required_version))
    shortest = min(len(mine), len(theirs))
    return mine[:shortest] == theirs[:shortest]


def _platform_verdict(entry: dict[str, Any], platform: str | None) -> bool | None:
    """True : plateforme requise présente ; False : absente ; None : impossible à trancher."""
    required = [p for p in str(entry.get("platforms") or "").split(" ; ") if p.strip()]
    if not platform or not required:
        return None
    return any(platform_matches(platform, r) for r in required)


def _within(version: str, entry: dict[str, Any]) -> bool:
    exact = str(entry.get("version") or "")
    has_range = any(
        entry.get(k)
        for k in (
            "versionStartIncluding",
            "versionStartExcluding",
            "versionEndIncluding",
            "versionEndExcluding",
        )
    )
    mine = version_key(version)
    if exact not in _WILDCARDS and not has_range:
        return mine == version_key(exact)
    if not has_range:
        return True  # toutes les versions du produit
    if (bound := entry.get("versionStartIncluding")) and mine < version_key(str(bound)):
        return False
    if (bound := entry.get("versionStartExcluding")) and mine <= version_key(str(bound)):
        return False
    if (bound := entry.get("versionEndIncluding")) and mine > version_key(str(bound)):
        return False
    return not ((bound := entry.get("versionEndExcluding")) and mine >= version_key(str(bound)))


def assess(
    product: str,
    version: str | None,
    affected: Sequence[dict[str, Any]] | None,
    platform: str | None = None,
) -> Verdict:
    """Verdict pour un actif (produit, version et plateforme déclarées) et les versions
    vulnérables d'une CVE."""
    if not affected:
        return "inconnu"
    relevant = [e for e in affected if same_product(product, str(e.get("product") or ""))]
    if not relevant:
        return "autre_produit"
    if not version or not version_key(version):
        return "version_non_declaree"
    matching = [e for e in relevant if _within(version, e)]
    if not matching:
        return "hors_plage"
    if any(not _conditional(e) for e in matching):
        return "vulnerable"
    verdicts = [_platform_verdict(e, platform) for e in matching]
    if any(v is True for v in verdicts):
        return "vulnerable"
    if verdicts and all(v is False for v in verdicts):
        return "hors_plateforme"
    return "conditionnel"


VERDICT_LABEL: dict[str, str] = {
    "vulnerable": "version déclarée dans une plage vulnérable (NVD)",
    "hors_plateforme": "plateforme de l'actif différente de celles visées par la NVD",
    "conditionnel": "vulnérable seulement sur certaines plateformes ou paquets de distribution "
    "(NVD) : à vérifier",
    "inconnu": "versions vulnérables pas encore publiées par la NVD : à vérifier",
    "version_non_declaree": "version de l'actif non déclarée : à vérifier",
}

VERDICT_LABEL_EN: dict[str, str] = {
    "vulnerable": "declared version within a vulnerable range (NVD)",
    "hors_plateforme": "asset platform differs from those targeted by the NVD",
    "conditionnel": "vulnerable only on some platforms or distribution packages (NVD): "
    "to be checked",
    "inconnu": "vulnerable versions not yet published by the NVD: to be checked",
    "version_non_declaree": "asset version not declared: to be checked",
}
