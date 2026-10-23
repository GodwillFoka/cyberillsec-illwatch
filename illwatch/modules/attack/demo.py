"""Extrait ATT&CK minimal pour la démonstration (`illwatch demo load`) — M10, ADR-023.

Quelques techniques, un groupe et un logiciel réels d'ATT&CK Enterprise, pour que les
écrans montrent le contexte ATT&CK sans téléchargement. `illwatch attack import` le
remplace par le référentiel complet. ATT&CK® © The MITRE Corporation.
"""

from illwatch.modules.attack.stix import Actor, AttackData, Technique
from illwatch.shared.server_text import tr


def demo_attack_data() -> AttackData:
    data = AttackData(version=tr("extrait de démonstration", "demonstration extract"))
    for technique in (
        Technique("T1190", "Exploit Public-Facing Application", ["initial-access"], False),
        Technique("T1486", "Data Encrypted for Impact", ["impact"], False),
        Technique("T1490", "Inhibit System Recovery", ["impact"], False),
        Technique("T1566", "Phishing", ["initial-access"], False),
        Technique("T1566.001", "Phishing: Spearphishing Attachment", ["initial-access"], True),
        Technique("T1055", "Process Injection", ["defense-evasion", "privilege-escalation"], False),
        Technique(
            "T1059.001", "Command and Scripting Interpreter: PowerShell", ["execution"], True
        ),
        Technique("T1568", "Dynamic Resolution", ["command-and-control"], False),
        Technique(
            "T1568.002",
            "Dynamic Resolution: Domain Generation Algorithms",
            ["command-and-control"],
            True,
        ),
        Technique("T1090.003", "Proxy: Multi-hop Proxy", ["command-and-control"], True),
    ):
        data.techniques[technique.id] = technique
    data.actors["S0650"] = Actor(
        "S0650",
        "malware",
        "QakBot",
        ["Pinkslipbot", "QBot", "QuackBot"],
        tr(
            "Cheval de Troie bancaire devenu chargeur d'accès initial pour des rançongiciels.",
            "Banking trojan turned initial-access loader for ransomware.",
        ),
    )
    data.actors["G0102"] = Actor(
        "G0102",
        "group",
        "Wizard Spider",
        ["UNC1878", "TEMP.MixMaster", "Grim Spider"],
        tr(
            "Groupe criminel à motivation financière, opérateur des rançongiciels Ryuk et Conti.",
            "Financially motivated criminal group, operator of the Ryuk and Conti ransomware.",
        ),
    )
    data.uses |= {
        ("S0650", "T1566.001"),
        ("S0650", "T1055"),
        ("G0102", "T1486"),
        ("G0102", "T1490"),
        ("G0102", "T1059.001"),
        ("G0102", "T1566.001"),
    }
    return data
