"""Prépare le site de documentation : copie dans docs/ ce qui vit hors de docs/.

Lancé par .github/workflows/docs.yml avant `mkdocs build`. Les copies sont ignorées par git
(.gitignore) : la source reste unique (Rapport/, CHANGELOG.md, CONTRIBUTING.md…).
"""

import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
REPO = "https://github.com/GodwillFoka/cyberillsec-illwatch/blob/main"

COPIES = {
    "CHANGELOG.md": "changelog.md",
    "CONTRIBUTING.md": "contributing.md",
    "SECURITY.md": "security.md",
    "CODE_OF_CONDUCT.md": "code_of_conduct.md",
}

# Un lien relatif vers un fichier du dépôt (hors docs/) devient un lien vers GitHub.
DATE = re.compile(r"(\d{2})/(\d{2})/(\d{4})")
LINK = re.compile(r"\]\((?!https?://|#|mailto:)([^)\s]+)\)")


def _rewrite(text: str, source_dir: Path) -> str:
    def repl(match: re.Match[str]) -> str:
        target = match.group(1)
        path, _, anchor = target.partition("#")
        resolved = (source_dir / path).resolve()
        try:
            rel = resolved.relative_to(ROOT)
        except ValueError:
            return match.group(0)
        if rel.parts and rel.parts[0] == "docs":
            return match.group(0)
        return f"]({REPO}/{rel.as_posix()}{'#' + anchor if anchor else ''})"

    return LINK.sub(repl, text)


def main() -> None:
    for src, dst in COPIES.items():
        text = (ROOT / src).read_text(encoding="utf-8")
        (DOCS / dst).write_text(_rewrite(text, ROOT), encoding="utf-8")

    target = DOCS / "rapport"
    shutil.rmtree(target, ignore_errors=True)
    target.mkdir()
    reports = sorted((ROOT / "Rapport").glob("*.md"), key=lambda p: p.name)
    for report in reports:
        if report.name in {"README.md", "TEMPLATE.md"}:
            continue
        text = (report).read_text(encoding="utf-8")
        (target / report.name).write_text(_rewrite(text, report.parent), encoding="utf-8")

    lines = [
        "# Rapports et bilans",
        "",
        "Bilans d'étape, audits et rapports d'avancement, du plus récent au plus ancien.",
        "",
    ]
    entries = []
    for report in target.glob("*.md"):
        if report.name == "index.md":
            continue
        head = report.read_text(encoding="utf-8").splitlines()
        title = head[0].lstrip("# ").strip()
        found = DATE.search("\n".join(head[:12]))
        key = (found.group(3), found.group(2), found.group(1)) if found else ("0", "0", "0")
        label = f"{found.group(1)}/{found.group(2)}/{found.group(3)} — " if found else ""
        entries.append((key, f"- {label}[{title}]({report.name})"))
    lines += [line for _, line in sorted(entries, reverse=True)]
    (target / "index.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"docs prêtes : {len(COPIES)} pages racine, {len(reports)} rapports")


if __name__ == "__main__":
    main()
