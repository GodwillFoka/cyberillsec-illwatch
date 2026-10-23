"""Techniques ATT&CK de chaque détection d'ILLWATCH — M10, ADR-023.

Chaque règle de chasse et de corrélation déclare la ou les techniques qu'elle révèle. La
table est versionnée avec les règles ; les noms ci-dessous servent tant que le référentiel
n'est pas importé (`illwatch attack import` les remplace par ceux de la version courante).
Une règle sans technique honnêtement attribuable n'en déclare pas (RULE-06 : un IOC connu
dit « déjà vu », pas « comment »).
"""

ATTACK_URL = "https://attack.mitre.org/techniques/{path}/"
GROUP_URL = "https://attack.mitre.org/groups/{id}/"
SOFTWARE_URL = "https://attack.mitre.org/software/{id}/"

BUILTIN_TECHNIQUES: dict[str, str] = {
    "T1090.003": "Proxy: Multi-hop Proxy",
    "T1568": "Dynamic Resolution",
    "T1568.002": "Dynamic Resolution: Domain Generation Algorithms",
    "T1486": "Data Encrypted for Impact",
    "T1190": "Exploit Public-Facing Application",
}

RULE_TECHNIQUES: dict[str, tuple[str, ...]] = {
    # Chasse (ADR-009)
    "RULE-01": ("T1090.003",),  # relais de sortie Tor : proxy à plusieurs sauts
    "RULE-02": ("T1568",),  # DNS dynamique : résolution dynamique de l'infrastructure
    "RULE-03": ("T1568.002",),  # domaine généré par algorithme
    "RULE-04": ("T1486",),  # infrastructure de rançongiciel : chiffrement pour impact
    "RULE-05": ("T1190",),  # CVE exploitée sur un produit exposé
    "RULE-06": (),
    # Corrélation (ADR-020)
    "CORR-01": ("T1190",),
    "CORR-02": ("T1190",),
    "CORR-03": (),
}


def technique_url(technique_id: str) -> str:
    return ATTACK_URL.format(path=technique_id.replace(".", "/"))


def actor_url(actor_id: str, kind: str) -> str:
    return (GROUP_URL if kind == "group" else SOFTWARE_URL).format(id=actor_id)
