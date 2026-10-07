"""Catalogue de règles de threat hunting — RF-25, RF-26 (phase 6, ADR-009).

Une règle reçoit le **contexte de chasse** (observables soumis, IOC de la base, inventaire
d'actifs, listes de référence) et produit des correspondances. Elle est déterministe :
mêmes entrées, mêmes résultats ; aucune ne dépend d'un service tiers à l'exécution, hormis
RULE-01 qui charge la liste officielle des relais de sortie Tor.

Deux modes, selon que l'analyste soumet ou non des observables :

- **Chasse sur observables** (IP, domaines, URL, hashs extraits de journaux de pare-feu, de
  proxy, d'EDR…) : chaque observable est confronté aux règles et à la base d'IOC (RULE-06).
- **Chasse sur la base** (aucun observable, ou session planifiée) : les règles parcourent les
  IOC actifs pour y repérer des motifs à surveiller (DGA, DNS dynamique, infrastructures
  ransomware, relais Tor).

| Règle   | Détection                                                       | Sévérité |
|---------|-----------------------------------------------------------------|----------|
| RULE-01 | Relais de sortie Tor (liste officielle torproject.org)          | MEDIUM   |
| RULE-02 | Domaine chez un fournisseur de DNS dynamique gratuit            | HIGH     |
| RULE-03 | Domaine à forte entropie (généré par algorithme, DGA)           | MEDIUM   |
| RULE-04 | IP d'infrastructure ransomware connue (IOC étiqueté)            | CRITICAL |
| RULE-05 | CVE critique à exploit public touchant un actif de l'inventaire  | CRITICAL |
| RULE-06 | Observable déjà connu comme IOC actif                           | IOC      |
"""

import math
import re
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from urllib.parse import urlsplit
from uuid import UUID

from illwatch.shared.enums import IndicatorType, Severity

# --- Données de référence ----------------------------------------------------------------

DYNAMIC_DNS_SUFFIXES = frozenset(
    {
        "duckdns.org",
        "no-ip.com",
        "no-ip.org",
        "no-ip.biz",
        "noip.me",
        "ddns.net",
        "hopto.org",
        "zapto.org",
        "sytes.net",
        "serveftp.com",
        "servehttp.com",
        "myftp.biz",
        "myftp.org",
        "redirectme.net",
        "dynu.net",
        "dynu.com",
        "dyndns.org",
        "dyndns.info",
        "dynv6.net",
        "freeddns.org",
        "afraid.org",
        "mooo.com",
        "chickenkiller.com",
        "ydns.eu",
        "dedyn.io",
        "linkpc.net",
        "3utilities.com",
        "bounceme.net",
        "gotdns.ch",
        "publicvm.com",
        "kozow.com",
        "loseyourip.com",
        "ooguy.com",
        "theworkpc.com",
        "duckdns.com",
        "ngrok.io",
        "ngrok-free.app",
        "trycloudflare.com",
    }
)
RANSOMWARE_PATTERN = re.compile(
    r"\b(ransom\w*|lockbit|blackcat|alphv|cl0p|clop|akira|black\s?basta|blackbasta|royal|"
    r"8base|medusa|play\s?crypt|rhysida|bianlian|conti|revil|sodinokibi|ryuk|hive|"
    r"qilin|ransomhub|hunters\s?international|inc\s?ransom|cactus|noescape|blacksuit)\b",
    re.IGNORECASE,
)
# Suffixes publics à deux niveaux les plus courants : le libellé enregistré de
# `x.example.co.uk` est `example`, pas `co`.
_TWO_LEVEL_SUFFIXES = frozenset(
    {
        "co.uk",
        "org.uk",
        "ac.uk",
        "com.au",
        "net.au",
        "co.jp",
        "com.br",
        "com.cn",
        "co.za",
        "com.mx",
        "co.in",
        "com.tr",
        "co.kr",
        "com.sg",
        "com.ar",
    }
)
DGA_MIN_LENGTH = 12
DGA_MIN_ENTROPY = 3.5
DGA_MAX_VOWEL_RATIO = 0.35


# --- Contexte et résultats ----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Observable:
    """Valeur normalisée à chasser (observable soumis ou IOC de la base)."""

    type: IndicatorType
    value: str
    indicator_id: UUID | None = None  # renseigné si l'observable est un IOC de la base
    description: str | None = None


@dataclass(frozen=True, slots=True)
class KnownCVE:
    id: str
    description: str
    score: float
    priority: str


@dataclass(slots=True)
class HuntContext:
    """Tout ce que voient les règles. Les listes coûteuses sont chargées à la demande."""

    observables: Sequence[Observable]  # soumis par l'analyste, ou IOC de la base
    known_iocs: dict[tuple[IndicatorType, str], Observable] = field(default_factory=dict)
    submitted: bool = False  # True : chasse sur observables ; False : chasse sur la base
    assets: Sequence[str] = ()
    exploitable_cves: Sequence[KnownCVE] = ()
    tor_exits: frozenset[str] | None = None


@dataclass(frozen=True, slots=True)
class Match:
    rule_id: str
    severity: Severity
    observable: str
    detail: str
    indicator_id: UUID | None = None
    cve_id: str | None = None


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    name: str
    description: str
    severity: Severity
    needs_tor_list: bool
    evaluate: Callable[[HuntContext], Iterable[Match]]


# --- Outils --------------------------------------------------------------------------------


def _host(observable: Observable) -> str | None:
    if observable.type is IndicatorType.DOMAIN:
        return observable.value
    if observable.type is IndicatorType.URL:
        return (urlsplit(observable.value).hostname or "").lower() or None
    if observable.type is IndicatorType.EMAIL:
        return observable.value.rpartition("@")[2]
    return None


def registered_label(host: str) -> str:
    """Libellé enregistré d'un nom d'hôte : `a.b.example.co.uk` → `example`."""
    labels = host.rstrip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_LEVEL_SUFFIXES:
        return labels[-3]
    return labels[-2] if len(labels) >= 2 else labels[0]


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def looks_generated(label: str) -> tuple[bool, float]:
    """Heuristique DGA : libellé long, entropie élevée, peu de voyelles ou beaucoup de chiffres.

    Volontairement conservatrice (faux positifs coûteux) : un domaine IDN (`xn--`) ou un
    libellé à tirets (mots composés) n'est jamais considéré comme généré.
    """
    clean = label.lower()
    if len(clean) < DGA_MIN_LENGTH or clean.startswith("xn--") or "-" in clean:
        return False, shannon_entropy(clean)
    entropy = shannon_entropy(clean)
    letters = [c for c in clean if c.isalpha()]
    vowels = sum(1 for c in letters if c in "aeiouy")
    digits = sum(1 for c in clean if c.isdigit())
    vowel_ratio = vowels / len(letters) if letters else 0.0
    generated = entropy >= DGA_MIN_ENTROPY and (
        vowel_ratio <= DGA_MAX_VOWEL_RATIO or digits / len(clean) >= 0.25
    )
    return generated, entropy


# --- Règles --------------------------------------------------------------------------------


def _tor(ctx: HuntContext) -> Iterable[Match]:
    exits = ctx.tor_exits or frozenset()
    for o in ctx.observables:
        if o.type in (IndicatorType.IPV4, IndicatorType.IPV6) and o.value in exits:
            yield Match(
                "RULE-01",
                Severity.MEDIUM,
                o.value,
                "Relais de sortie Tor : trafic anonymisé, à corréler avec l'activité "
                "observée (le relais lui-même n'est pas malveillant).",
                o.indicator_id,
            )


def _ddns(ctx: HuntContext) -> Iterable[Match]:
    for o in ctx.observables:
        host = _host(o)
        if host is None:
            continue
        suffix = next(
            (s for s in DYNAMIC_DNS_SUFFIXES if host == s or host.endswith("." + s)), None
        )
        if suffix is not None and host != suffix:
            yield Match(
                "RULE-02",
                Severity.HIGH,
                o.value,
                f"Hébergé sous {suffix}, fournisseur de DNS dynamique gratuit prisé "
                "des serveurs C2 et du phishing.",
                o.indicator_id,
            )


def _dga(ctx: HuntContext) -> Iterable[Match]:
    for o in ctx.observables:
        host = _host(o)
        if host is None:
            continue
        generated, entropy = looks_generated(registered_label(host))
        if generated:
            yield Match(
                "RULE-03",
                Severity.MEDIUM,
                o.value,
                f"Nom probablement généré par algorithme (entropie {entropy:.2f} bits, "
                f"libellé « {registered_label(host)} »).",
                o.indicator_id,
            )


def _ransomware_ip(ctx: HuntContext) -> Iterable[Match]:
    for o in ctx.observables:
        if o.type not in (IndicatorType.IPV4, IndicatorType.IPV6):
            continue
        known = ctx.known_iocs.get((o.type, o.value)) if ctx.submitted else o
        if known is None or not known.description:
            continue
        found = RANSOMWARE_PATTERN.search(known.description)
        if found:
            yield Match(
                "RULE-04",
                Severity.CRITICAL,
                o.value,
                f"IP liée à une infrastructure ransomware ({found.group(0)}) : "
                f"{known.description[:200]}",
                known.indicator_id,
            )


def _exploitable_assets(ctx: HuntContext) -> Iterable[Match]:
    for asset in ctx.assets:
        pattern = re.compile(rf"\b{re.escape(asset.strip())}\b", re.IGNORECASE)
        for cve in ctx.exploitable_cves:
            if asset.strip() and pattern.search(cve.description):
                yield Match(
                    "RULE-05",
                    Severity.CRITICAL,
                    asset.strip(),
                    f"{cve.id} ({cve.priority}, score {cve.score:.1f}) : exploit public "
                    f"vérifié pour un produit de l'inventaire.",
                    cve_id=cve.id,
                )


def _known_ioc(ctx: HuntContext) -> Iterable[Match]:
    if not ctx.submitted:
        return
    for o in ctx.observables:
        known = ctx.known_iocs.get((o.type, o.value))
        if known is not None:
            yield Match(
                "RULE-06",
                Severity.HIGH,
                o.value,
                f"IOC actif connu d'ILLWATCH ({known.description or 'sans description'}).",
                known.indicator_id,
            )


CATALOG: tuple[Rule, ...] = (
    Rule(
        "RULE-01",
        "Relais de sortie Tor",
        "IP correspondant à un relais de sortie Tor (liste officielle).",
        Severity.MEDIUM,
        True,
        _tor,
    ),
    Rule(
        "RULE-02",
        "DNS dynamique suspect",
        "Domaine hébergé chez un fournisseur de DNS dynamique gratuit (duckdns.org, no-ip…).",
        Severity.HIGH,
        False,
        _ddns,
    ),
    Rule(
        "RULE-03",
        "Domaine à forte entropie (DGA)",
        "Nom de domaine probablement généré par algorithme (entropie de Shannon élevée).",
        Severity.MEDIUM,
        False,
        _dga,
    ),
    Rule(
        "RULE-04",
        "IP d'extorsion ransomware",
        "IP associée à une infrastructure ransomware (IOC étiqueté par sa source).",
        Severity.CRITICAL,
        False,
        _ransomware_ip,
    ),
    Rule(
        "RULE-05",
        "CVE critique + exploit sur un actif",
        "CVE P0/P1 à exploit public dont la description cite un produit de l'inventaire.",
        Severity.CRITICAL,
        False,
        _exploitable_assets,
    ),
    Rule(
        "RULE-06",
        "IOC connu",
        "Observable soumis déjà présent comme IOC actif dans ILLWATCH.",
        Severity.HIGH,
        False,
        _known_ioc,
    ),
)
RULES = {rule.id: rule for rule in CATALOG}
