"""Règle éditoriale (docs/DESIGN_SYSTEM.md, 30/10/2026) : ni tiret long ni tiret moyen.

Le dépôt entier est concerné : code, textes affichés, documentation, rapports. Une donnée
externe qui en contient (nom d'une ancienne source, fichier d'exemple) s'écrit en échappement
(`\\u2014`), jamais avec le caractère lui-même.
"""

from pathlib import Path

ROOT = Path(__file__).parents[1]
SKIPPED_DIRS = {".git", ".venv", "node_modules", "dist", "site", "htmlcov", "__pycache__", "build"}
FORBIDDEN = ("\u2014", "\u2013")


def _text_files() -> list[Path]:
    files = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or SKIPPED_DIRS.intersection(path.relative_to(ROOT).parts):
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\0" in raw or len(raw) > 5_000_000:
            continue
        files.append(path)
    return files


def test_aucun_tiret_long_ni_moyen() -> None:
    offenders = []
    for path in _text_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if any(dash in line for dash in FORBIDDEN):
                offenders.append(f"{path.relative_to(ROOT)}:{number}")
    assert not offenders, "Tiret long ou moyen : " + ", ".join(offenders[:20])
