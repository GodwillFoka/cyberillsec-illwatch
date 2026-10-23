"""Choix de la langue d'affichage (ADR-027) — fonctions pures, sans base ni réseau.

Ordre de décision, demandé par CYBERILL le 23/10/2026 (« la langue s'adapte au pays ») :

1. **pays** : celui du visiteur (adresse IP publique → base DB-IP Lite locale) ; à défaut
   (adresse privée : réseau interne, VPN d'entreprise), celui où l'instance est installée
   (`INSTANCE_COUNTRY`). Dans un pays à plusieurs langues prises en charge (Suisse,
   Belgique, Canada, Luxembourg, Cameroun, Singapour), la langue du navigateur départage ;
2. **langue du navigateur** (`Accept-Language`), si le pays n'en donne aucune ;
3. **langue de l'instance** (`DEFAULT_LANGUAGE`) ;
4. **anglais**.

Le choix explicite de l'utilisateur, mémorisé par le navigateur, l'emporte toujours : il est
appliqué côté client avant même d'interroger le serveur.

`Accept-Language` est une entrée non fiable : longueur, nombre d'étiquettes et syntaxe sont
bornés, toute valeur invalide est ignorée sans erreur.
"""

import re
from dataclasses import dataclass
from typing import Final, Literal

Language = Literal["fr", "en", "de", "es", "zh"]
Source = Literal["country", "browser", "instance", "default"]

SUPPORTED: Final[tuple[Language, ...]] = ("fr", "en", "de", "es", "zh")
FALLBACK: Final[Language] = "en"

MAX_HEADER_LENGTH: Final = 512
MAX_TAGS: Final = 20
_TAG = re.compile(r"^(?:\*|[A-Za-z]{1,8}(?:-[A-Za-z0-9]{1,8})*)$")
_QUALITY = re.compile(r"^q=(?:0(?:\.\d{0,3})?|1(?:\.0{0,3})?)$")
_COUNTRY = re.compile(r"^[A-Z]{2}$")


def _countries(lang: Language, codes: str) -> dict[str, tuple[Language, ...]]:
    return dict.fromkeys(codes.split(), (lang,))


# Pays → langues prises en charge, la première étant la langue par défaut du pays.
COUNTRY_LANGUAGES: Final[dict[str, tuple[Language, ...]]] = {
    # Français : France et outre-mer, Monaco, Afrique francophone, Maghreb, Haïti.
    **_countries(
        "fr",
        "FR MC RE GP MQ GF YT NC PF PM WF BL MF SN CI ML BF NE TD GN BJ TG CF CG CD GA DJ KM "
        "MG BI DZ TN MA MR HT",
    ),
    # Allemand.
    **_countries("de", "DE AT LI"),
    # Espagnol : Espagne, Amérique hispanophone, Guinée équatoriale.
    **_countries(
        "es",
        "ES MX AR CO PE VE CL EC GT CU BO DO HN PY SV NI CR PA UY GQ",
    ),
    # Chinois.
    **_countries("zh", "CN TW HK MO"),
    # Anglais : pays anglophones principaux (le reste du monde tombe aussi sur l'anglais).
    **_countries(
        "en",
        "US GB IE AU NZ IN PK NG GH KE UG TZ ZA ZM ZW BW MW SL LR GM JM TT BS BB PH MY",
    ),
    # Pays à plusieurs langues prises en charge : le navigateur départage.
    "CH": ("de", "fr"),
    "BE": ("fr", "de"),
    "LU": ("fr", "de"),
    "CA": ("en", "fr"),
    "CM": ("fr", "en"),
    "SG": ("en", "zh"),
    "PR": ("es", "en"),
}


@dataclass(frozen=True, slots=True)
class LocaleChoice:
    lang: Language
    source: Source


def normalize_country(value: str | None) -> str | None:
    """Code pays ISO 3166-1 alpha-2 en majuscules, ou None."""
    if not value:
        return None
    code = value.strip().upper()
    return code if _COUNTRY.match(code) else None


def as_language(value: str | None) -> Language | None:
    """Langue prise en charge correspondant à une étiquette BCP 47 (« de-AT » → « de »)."""
    if not value:
        return None
    primary = value.strip().lower().replace("_", "-").split("-")[0]
    for lang in SUPPORTED:
        if primary == lang:
            return lang
    return None


def parse_accept_language(header: str | None) -> list[Language]:
    """Langues prises en charge, par préférence décroissante, d'après `Accept-Language`.

    Les étiquettes de qualité nulle (`q=0`, « refusée ») sont exclues ; l'ordre d'origine
    départage les qualités égales. Un en-tête trop long ou malformé ne lève jamais d'erreur.
    """
    if not header or len(header) > MAX_HEADER_LENGTH:
        return []
    weighted: list[tuple[float, int, Language]] = []
    for position, part in enumerate(header.split(",")[:MAX_TAGS]):
        fields = [f.strip() for f in part.split(";")]
        tag = fields[0]
        if not _TAG.match(tag):
            continue
        quality = 1.0
        if len(fields) > 1:
            if len(fields) > 2 or not _QUALITY.match(fields[1].replace(" ", "")):
                continue
            quality = float(fields[1].replace(" ", "")[2:])
        lang = as_language(tag)
        if lang is None or quality <= 0:
            continue
        weighted.append((-quality, position, lang))
    ordered: list[Language] = []
    for _, _, lang in sorted(weighted):
        if lang not in ordered:
            ordered.append(lang)
    return ordered


def choose_language(
    *,
    visitor_country: str | None,
    accept_language: str | None,
    instance_country: str | None = None,
    instance_language: str | None = None,
) -> LocaleChoice:
    """Langue d'affichage selon l'ordre décrit en tête de module."""
    browser = parse_accept_language(accept_language)
    instance = as_language(instance_language)
    country = normalize_country(visitor_country) or normalize_country(instance_country)
    candidates = COUNTRY_LANGUAGES.get(country or "", ())
    if candidates:
        # Pays bilingue : le navigateur départage, puis la langue de l'instance si elle fait
        # partie des langues du pays, puis la langue principale du pays.
        fallback = instance if instance in candidates else candidates[0]
        preferred = next((lang for lang in browser if lang in candidates), fallback)
        return LocaleChoice(preferred, "country")
    if browser:
        return LocaleChoice(browser[0], "browser")
    if instance:
        return LocaleChoice(instance, "instance")
    return LocaleChoice(FALLBACK, "default")
