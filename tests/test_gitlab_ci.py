"""Configuration GitLab CI : chaque ligne de script doit rester une chaîne.

Une ligne YAML non citée qui contient « : » suivi d'un espace devient une clé de dictionnaire ;
GitLab refuse alors tout le pipeline sans lancer aucun travail (pipeline #57 du 23/10/2026).
"""

from pathlib import Path

import yaml

CONFIG = Path(__file__).resolve().parents[1] / ".gitlab-ci.yml"


def test_lignes_de_script_en_chaines() -> None:
    config = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    bad = [
        f"{name}.{key}[{index}]"
        for name, job in config.items()
        if isinstance(job, dict)
        for key in ("script", "before_script", "after_script")
        for index, line in enumerate(job.get(key) or [])
        if not isinstance(line, str)
    ]
    assert not bad, bad


def test_publication_pages_sur_main() -> None:
    config = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    pages = config["pages"]
    assert pages["stage"] in config["stages"]
    assert pages["artifacts"]["paths"] == ["public"]
