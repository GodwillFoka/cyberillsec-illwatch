"""Calibration de RULE-03 (domaine généré par algorithme) — point en attente de M8.

Mesure, pour les seuils en vigueur et pour une grille de seuils voisins :

- le **taux de faux positifs** sur les domaines les plus visités (liste Tranco : domaines
  légitimes par construction) ;
- le **taux de détection** sur un corpus DGA **synthétique** et reproductible (graine fixe) :
  libellés aléatoires en lettres, alphanumériques et hexadécimaux, 12 à 24 caractères, soit
  la famille de DGA visée par une heuristique d'entropie. Les DGA à dictionnaire (mots
  concaténés : suppobox, matsnu) sont hors de portée de cette règle, par construction.

Usage (le workflow « Calibration DGA » télécharge la liste Tranco) :

    python3 scripts/calibrate_dga.py --tranco top-1m.csv --top 100000 --report dga.md

Sortie : rapport Markdown et annotations GitHub (::notice::) lisibles depuis l'onglet Checks.
Bibliothèque standard uniquement ; la règle réelle est importée pour vérifier que la
réimplémentation paramétrée donne les mêmes verdicts aux seuils en vigueur.
"""

from __future__ import annotations

import argparse
import csv
import random
import string
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from illwatch.modules.threat_hunting.rules import (  # noqa: E402
    DGA_MAX_VOWEL_RATIO,
    DGA_MIN_ENTROPY,
    DGA_MIN_LENGTH,
    looks_generated,
    registered_label,
    shannon_entropy,
)

MAX_FALSE_POSITIVE_RATE = 0.001  # 1 domaine légitime sur 1 000 au plus


@dataclass(frozen=True)
class Thresholds:
    min_length: int
    min_entropy: float
    max_vowel_ratio: float

    def label(self) -> str:
        return (
            f"longueur ≥ {self.min_length}, entropie ≥ {self.min_entropy:.2f}, "
            f"voyelles ≤ {self.max_vowel_ratio:.2f}"
        )


CURRENT = Thresholds(DGA_MIN_LENGTH, DGA_MIN_ENTROPY, DGA_MAX_VOWEL_RATIO)


def generated(label: str, t: Thresholds) -> bool:
    """Même heuristique que `looks_generated`, aux seuils `t`."""
    clean = label.lower()
    if len(clean) < t.min_length or clean.startswith("xn--") or "-" in clean:
        return False
    entropy = shannon_entropy(clean)
    letters = [c for c in clean if c.isalpha()]
    vowels = sum(1 for c in letters if c in "aeiouy")
    digits = sum(1 for c in clean if c.isdigit())
    vowel_ratio = vowels / len(letters) if letters else 0.0
    return entropy >= t.min_entropy and (
        vowel_ratio <= t.max_vowel_ratio or digits / len(clean) >= 0.25
    )


def benign_labels(path: Path, top: int) -> list[str]:
    labels: dict[str, None] = {}
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.reader(handle):
            if len(row) < 2:
                continue
            labels.setdefault(registered_label(row[1].strip().lower()), None)
            if len(labels) >= top:
                break
    return list(labels)


def synthetic_dga(count: int, seed: int = 20261014) -> list[str]:
    rng = random.Random(seed)  # noqa: S311 (corpus reproductible, pas de cryptographie)
    alphabets = (
        string.ascii_lowercase,
        string.ascii_lowercase + string.digits,
        "0123456789abcdef",
    )
    out: list[str] = []
    for index in range(count):
        alphabet = alphabets[index % len(alphabets)]
        length = rng.randint(12, 24)
        out.append("".join(rng.choice(alphabet) for _ in range(length)))
    return out


def rate(labels: list[str], t: Thresholds) -> tuple[float, list[str]]:
    hits = [label for label in labels if generated(label, t)]
    return (len(hits) / len(labels) if labels else 0.0), hits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tranco", type=Path, required=True)
    parser.add_argument("--top", type=int, default=100_000)
    parser.add_argument("--synthetic", type=int, default=30_000)
    parser.add_argument("--report", type=Path, default=None)
    args = parser.parse_args()

    benign = benign_labels(args.tranco, args.top)
    dga = synthetic_dga(args.synthetic)
    # Garde-fou : la réimplémentation colle à la règle en production.
    sample = benign[:5000] + dga[:3000]
    drift = [x for x in sample if generated(x, CURRENT) != looks_generated(x)[0]]
    if drift:
        print(f"::error title=Calibration DGA::Réimplémentation divergente : {drift[:5]}")
        return 1

    grid = [
        Thresholds(length, entropy, vowels)
        for length in (10, 12, 14)
        for entropy in (3.0, 3.25, 3.5, 3.75, 4.0)
        for vowels in (0.25, 0.30, 0.35, 0.40)
    ]
    results = []
    for t in grid:
        fp, _ = rate(benign, t)
        recall, _ = rate(dga, t)
        results.append((t, fp, recall))
    fp_now, fp_examples = rate(benign, CURRENT)
    recall_now, _ = rate(dga, CURRENT)
    eligible = [r for r in results if r[1] <= MAX_FALSE_POSITIVE_RATE]
    best = max(eligible, key=lambda r: (r[2], -r[1])) if eligible else None

    lines = [
        "# Calibration de RULE-03 (DGA)",
        "",
        f"Corpus légitime : {len(benign)} libellés (Tranco, premiers domaines enregistrés).",
        f"Corpus DGA synthétique : {len(dga)} libellés aléatoires (graine fixe).",
        "",
        "| Seuils | Faux positifs | Détection |",
        "|---|---|---|",
        f"| **En vigueur** : {CURRENT.label()} | {fp_now:.3%} | {recall_now:.1%} |",
    ]
    if best:
        t, fp, recall = best
        lines.append(f"| Meilleur (FP ≤ 0,1 %) : {t.label()} | {fp:.3%} | {recall:.1%} |")
    lines += ["", "Faux positifs aux seuils en vigueur (extrait) :", ""]
    lines += [f"- `{label}`" for label in fp_examples[:40]]
    lines += ["", "Grille complète :", "", "| Seuils | FP | Détection |", "|---|---|---|"]
    lines += [f"| {t.label()} | {fp:.3%} | {r:.1%} |" for t, fp, r in results]
    report = "\n".join(lines) + "\n"
    if args.report:
        args.report.write_text(report, encoding="utf-8")

    def annotate(title: str, message: str) -> None:
        body = message.replace("%", "%25").replace("\n", "%0A")
        print(f"::notice title={title}::{body}")

    annotate(
        "DGA en vigueur",
        f"{CURRENT.label()}\nFP {fp_now:.3%} sur {len(benign)} domaines Tranco · détection "
        f"{recall_now:.1%} sur {len(dga)} DGA synthétiques\nExemples de FP : "
        + ", ".join(fp_examples[:25]),
    )
    if best:
        annotate(
            "DGA recommandé",
            f"{best[0].label()}\nFP {best[1]:.3%} · détection {best[2]:.1%}",
        )
    top_rows = sorted(results, key=lambda r: (r[1] > MAX_FALSE_POSITIVE_RATE, -r[2], r[1]))[:12]
    annotate(
        "DGA grille (extrait)",
        "\n".join(f"{t.label()} : FP {fp:.3%} · détection {r:.1%}" for t, fp, r in top_rows),
    )
    print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
