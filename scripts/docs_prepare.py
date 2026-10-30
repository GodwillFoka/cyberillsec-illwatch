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

    (target / "index.md").write_text(_reports_index(target), encoding="utf-8")
    print(f"docs prêtes : {len(COPIES)} pages racine, {len(reports)} rapports")


# Catalogue des rapports : catégorie, jalon, résumé. Un rapport absent du catalogue est rangé
# dans « Autres documents », avec la date trouvée dans ses premières lignes.
CATEGORIES = [
    (
        "avancement",
        ":material-chart-timeline-variant:",
        "Rapports d'avancement",
        "Ce qui a avancé, ce qui est en risque, ce qui est décidé : la photographie d'une étape.",
    ),
    (
        "bilan",
        ":material-flag-checkered:",
        "Bilans de jalon",
        "Un jalon est clos quand son critère de sortie est constaté sur données réelles : chaque "
        "bilan dit ce qui l'est, et ce qui ne l'est pas encore.",
    ),
    (
        "audit",
        ":material-shield-search:",
        "Audits et états globaux",
        "Revues indépendantes du dépôt complet et états des lieux après intégration.",
    ),
    (
        "mesure",
        ":material-target:",
        "Mesures",
        "Chiffres obtenus sur jeu de données figé ou sur données réelles, avec leur méthode.",
    ),
    (
        "plan",
        ":material-map-marker-path:",
        "Plans et revues",
        "Plans de travail et revues de méthode qui ont orienté les étapes suivantes.",
    ),
]
CATALOGUE = {
    "01_24-09-2026.md": (
        "avancement",
        "M1",
        "Phase 1 terminée côté code : migrations PostgreSQL, "
        "CLI complète, authentification JWT, 95 tests verts, couverture 94 %.",
    ),
    "03_06-10-2026.md": (
        "avancement",
        "M7",
        "Baseline v0.1.1 publiée (tag, release, image), "
        "durcissement M7 fusionné, miroir GitHub complet, M3 atteint sur données réelles.",
    ),
    "03b_06-10-2026.md": (
        "avancement",
        "M2",
        "Clone neuf sur Kali : quatre défauts corrigés, "
        "clés externes configurées, M2 atteint pour la première fois (67 495 IOC).",
    ),
    "RAPPORT_GLOBAL.md": (
        "avancement",
        "M1 à M6",
        "Du lancement du dépôt au code complet des six "
        "modules : 388 tests sur PostgreSQL 16, couverture 94 %.",
    ),
    "BILAN_PHASE_1.md": (
        "bilan",
        "M1",
        "Clôture de la phase « Foundation » : configuration validée, "
        "base, migrations, CLI et authentification.",
    ),
    "BILAN_SPRINT_3.md": (
        "bilan",
        "M2",
        "Code de l'ingestion livré et vert ; jalon M2 non atteint "
        "faute de collecte réelle : la règle du constat est posée.",
    ),
    "BILAN_M2_PHASE_3.md": (
        "bilan",
        "M2, M3",
        "Clôture de M2 et moteur CVE : NVD, KEV, EPSS, score composite et alertes.",
    ),
    "BILAN_TAXII_PHASES_4_6.md": (
        "bilan",
        "M4 à M6",
        "Client TAXII 2.1 réel, incidents, tableau de bord et chasse livrés et testés.",
    ),
    "BILAN_M7_LOT1.md": (
        "bilan",
        "M7",
        "Lot 1 du durcissement : audit en ajout seul, sondes, en-têtes "
        "HTTP, verrouillage compte et adresse, sauvegarde et restauration.",
    ),
    "BILAN_M7_LOT2.md": (
        "bilan",
        "M7",
        "Lot 2 : rôle PostgreSQL applicatif sans droit de structure, "
        "Redis protégé, rotation de clé, sessions révocables.",
    ),
    "BILAN_M7_LOT3.md": (
        "bilan",
        "M7",
        "Lot 3 : TLS par Caddy, migrations isolées, analyse d'image ; "
        "M7 codé en entier, le serveur européen reste à constater.",
    ),
    "BILAN_M8.md": (
        "bilan",
        "M8",
        "M8 clos : confiance des IOC, enrichissement, inventaire et "
        "corrélation par version ; 100 % de détection sur le jeu figé.",
    ),
    "BILAN_M9.md": (
        "bilan",
        "M9",
        "Opérations SOC : niveaux L1 à L3, escalade, faux positifs, "
        "écran Pilotage ; à rejouer sur données réelles.",
    ),
    "BILAN_M11.md": (
        "bilan",
        "M11",
        "Observabilité : métriques Prometheus, Grafana, acceptation en CI, "
        "restauration testée ; clôture après 7 jours de préproduction.",
    ),
    "ETAT_GLOBAL_SENTRY_2026-10-03.md": (
        "audit",
        "M1 à M6",
        "État global après intégration des six "
        "modules : CI rejouée, base neuve alimentée par de vraies sources.",
    ),
    "AUDIT_GLOBAL_2026-10-10.md": (
        "audit",
        "M7",
        "Revue indépendante du dépôt complet : 1 écart "
        "élevé et 6 moyens, tous corrigés et vérifiés par la CI.",
    ),
    "M8_MESURE_13-10-2026.md": (
        "mesure",
        "M8",
        "Corrélation sur jeu figé versionné : 100 % des cas "
        "attendus détectés, 0 % de faux positifs.",
    ),
    "M8_MESURE_REELLE_13-10-2026.md": (
        "mesure",
        "M8",
        "Corrélation sur la base réelle de Kali avec "
        "5 actifs déclarés : le nom du produit ne suffit pas, la version compte.",
    ),
    "PLAN_DIRECTEUR.md": (
        "plan",
        "M1 à M6",
        "Fil conducteur jusqu'à la v1.0 : état, tâches par étape, attentes et perspectives.",
    ),
    "REVUE_POST_PHASE1_SPRINT2.md": (
        "plan",
        "M2",
        "Revue de méthode après la phase 1 : hygiène Git, règles de branche, plan du sprint 2.",
    ),
}


def _title(path: Path) -> str:
    first = path.read_text(encoding="utf-8").splitlines()[0]
    title = first.lstrip("# ").strip()
    # Les emojis d'en-tête des anciens rapports alourdissent les cartes.
    return re.sub(r"^[^\w«]+", "", title).strip()


def _date(path: Path) -> tuple[tuple[str, str, str], str]:
    head = "\n".join(path.read_text(encoding="utf-8").splitlines()[:12])
    found = DATE.search(head)
    if not found:
        return ("0", "0", "0"), ""
    return (found.group(3), found.group(2), found.group(1)), found.group(0)


def _card(path: Path, milestone: str, summary: str) -> str:
    _, date = _date(path)
    meta = " · ".join(x for x in (date, milestone) if x)
    return (
        f"-   __[{_title(path)}]({path.name})__\n\n"
        f"    ---\n\n    {summary}\n\n"
        f'    <span class="iw-meta">{meta}</span>\n'
    )


def _reports_index(target: Path) -> str:
    files = {p.name: p for p in target.glob("*.md") if p.name != "index.md"}
    live = files.pop("ETAT_AVANCEMENT.md", None)
    out = [
        "---",
        "hide:",
        "  - toc",
        "---",
        "",
        "# Rapports et bilans",
        "",
        "<p class=\"iw-lead\">L'histoire du projet, racontée au moment où elle s'écrivait : "
        "rapports d'avancement, bilans de jalon, audits indépendants et mesures. Les faits "
        "n'ont pas été modifiés après coup : chaque document est daté et garde le nom que "
        "portait le projet à cette date (SENTRY jusqu'au 08/10/2026, ILLWATCH ensuite). Vous "
        "y verrez les réussites, mais aussi les erreurs et la façon dont elles ont été "
        "corrigées.</p>",
        "",
    ]
    if live is not None:
        _, date = _date(live)
        out += [
            '<div class="iw-featured" markdown>',
            "",
            ":material-pulse: **Document vivant**",
            "",
            "### [État d'avancement des travaux](ETAT_AVANCEMENT.md)",
            "",
            "La position courante du projet : jalons, chantier en cours, journal des livraisons, "
            f"indicateurs, risques et prochaines étapes. Mis à jour le **{date}**.",
            "",
            "[Lire l'état d'avancement](ETAT_AVANCEMENT.md){ .md-button .md-button--primary }",
            "[Feuille de route](../ROADMAP.md){ .md-button }",
            "",
            "</div>",
            "",
        ]
    grouped: dict[str, list[tuple[tuple[str, str, str], str]]] = {c[0]: [] for c in CATEGORIES}
    others = []
    for name, path in files.items():
        key, _ = _date(path)
        if name in CATALOGUE:
            cat, milestone, summary = CATALOGUE[name]
            grouped[cat].append((key, _card(path, milestone, summary)))
        else:
            others.append((key, _card(path, "", "Rapport du projet.")))
    for cat, icon, label, intro in CATEGORIES:
        cards = [c for _, c in sorted(grouped[cat], reverse=True)]
        if not cards:
            continue
        out += [f"## {icon} {label}", "", intro, "", '<div class="grid cards" markdown>', ""]
        out += cards
        out += ["</div>", ""]
    if others:
        out += ["## Autres documents", "", '<div class="grid cards" markdown>', ""]
        out += [c for _, c in sorted(others, reverse=True)] + ["</div>", ""]
    # Chronologie compacte : tout sur une ligne par document.
    rows = []
    for name, path in files.items():
        key, date = _date(path)
        cat = CATALOGUE.get(name, ("autre", "", ""))
        label = next((c[2] for c in CATEGORIES if c[0] == cat[0]), "Autre")
        rows.append((key, f"| {date} | [{_title(path)}]({name}) | {label} | {cat[1]} |"))
    out += [
        "## :material-calendar-month: Chronologie",
        "",
        "| Date | Document | Type | Jalon |",
        "|---|---|---|---|",
    ]
    out += [r for _, r in sorted(rows, reverse=True)]
    out += [
        "",
        '!!! note "Conventions"',
        "    Les rapports hebdomadaires suivent le nom `NN_JJ-MM-AAAA.md` et le gabarit "
        "`Rapport/TEMPLATE.md`. Les bilans de jalon s'appellent `BILAN_<jalon>.md`. Les sources "
        "sont dans le dossier `Rapport/` du dépôt ; cette page est générée à chaque publication "
        "par `scripts/docs_prepare.py`.",
        "",
    ]
    return "\n".join(out)


if __name__ == "__main__":
    main()
