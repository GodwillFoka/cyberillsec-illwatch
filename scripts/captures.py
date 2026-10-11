"""Captures d'écran de l'interface, pour la revue visuelle (CI « Préproduction »).

Usage : python scripts/captures.py URL_BASE DOSSIER   (mot de passe : variable CAPTURE_PASSWORD)

Se connecte avec le compte « admin », parcourt chaque écran et l'enregistre en PNG, en grand
écran (1440 × 900) et, pour quelques écrans, en largeur mobile (390 × 844). Échoue si une page
affiche une erreur, si la console du navigateur signale une erreur ou une violation de la
politique de sécurité (CSP) : une capture « réussie » d'un écran cassé ne doit pas passer.
"""

import os
import re
import sys
from pathlib import Path

from playwright.sync_api import Page, sync_playwright

BASE = sys.argv[1].rstrip("/")
OUT = Path(sys.argv[2])
PASSWORD = os.environ["CAPTURE_PASSWORD"]

SCREENS = [
    ("01-vue-ensemble", "/"),
    ("02-triage", "/triage"),
    ("03-incidents", "/incidents"),
    ("05-indicateurs", "/indicateurs"),
    ("06-cve", "/cve"),
    ("07-chasse", "/chasse"),
    ("08-sources", "/sources"),
    ("09-administration", "/administration"),
]
MOBILE = {"01-vue-ensemble", "02-triage", "05-indicateurs", "08-sources", "09-administration"}

problems: list[str] = []


def settle(page: Page) -> None:
    # Pas de « networkidle » : le flux temps réel (SSE) garde une connexion ouverte en permanence.
    page.wait_for_load_state("load")
    # Laisse finir chargements et animations (graphiques, mise en évidence des nouveautés).
    # Attente côté Python : la CSP de l'interface (script-src 'self') refuse, à juste titre,
    # le JavaScript passé en chaîne par wait_for_function.
    for _ in range(60):
        if "Chargement…" not in page.inner_text("body"):
            break
        page.wait_for_timeout(250)
    page.wait_for_timeout(900)


OVERFLOW_PROBE = """() => {
  const root = document.documentElement;
  const main = document.querySelector("main");
  const limit = Math.min(root.clientWidth, main ? main.getBoundingClientRect().right : 1e9) + 1;
  const out = [];
  if (root.scrollWidth > root.clientWidth + 1) {
    out.push(`page : ${root.scrollWidth} px de large pour ${root.clientWidth} px visibles`);
  }
  for (const el of document.querySelectorAll("body *")) {
    const box = el.getBoundingClientRect();
    if (box.width === 0 || box.right <= limit) continue;
    // Contenu d'une zone qui défile volontairement (tableau dans sa carte) : ignoré.
    // La zone principale (<main>) ne compte pas : elle ne défile que verticalement.
    // Un élément positionné hors flux échappe aux zones qui défilent : jamais ignoré.
    const position = getComputedStyle(el).position;
    let node = position === "absolute" || position === "fixed" ? null : el.parentElement;
    let clipped = false;
    while (node && node !== main && node !== document.body) {
      const ox = getComputedStyle(node).overflowX;
      if (ox === "auto" || ox === "scroll" || ox === "hidden") { clipped = true; break; }
      node = node.parentElement;
    }
    if (clipped) continue;
    const cls = typeof el.className === "string" ? el.className.split(" ").join(".") : "";
    const right = Math.round(box.right);
    const tag = el.tagName.toLowerCase();
    out.push(`${tag}.${cls} jusqu'à ${right} px (limite ${Math.round(limit)})`);
    if (out.length >= 5) break;
  }
  return out;
}"""


def check(page: Page, name: str) -> None:
    text = page.inner_text("body")
    for marker in ("Données indisponibles", "Page introuvable", "Something went wrong"):
        if marker in text:
            problems.append(f"{name} : « {marker} » affiché")
    # Mise en page : aucun élément ne doit dépasser la largeur de l'écran (hors zones qui
    # défilent volontairement, comme un tableau dans sa carte).
    for overflow in page.evaluate(OVERFLOW_PROBE):
        problems.append(f"{name} ({page.viewport_size['width']} px) : déborde : {overflow}")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        context = browser.new_context(
            viewport={"width": 1440, "height": 900},
            ignore_https_errors=True,
            locale="fr-FR",
            timezone_id="Europe/Paris",
            color_scheme="dark",
        )
        page = context.new_page()
        page.on(
            "console",
            lambda m: (
                problems.append(f"console {m.type} : {m.text[:200]}")
                if m.type == "error" or "Content Security Policy" in m.text
                else None
            ),
        )
        page.on("pageerror", lambda e: problems.append(f"exception : {e}"[:240]))

        page.goto(f"{BASE}/")
        settle(page)
        page.screenshot(path=OUT / "00-connexion.png")
        page.get_by_label("Identifiant").fill("admin")
        page.get_by_label("Mot de passe").fill(PASSWORD)
        page.get_by_role("button", name=re.compile("connexion|Se connecter", re.I)).click()
        page.wait_for_selector("nav")
        settle(page)

        for name, path in SCREENS:
            page.goto(f"{BASE}{path}")
            settle(page)
            check(page, name)
            page.screenshot(path=OUT / f"{name}.png", full_page=True)

        # Page d'investigation : premier incident de la liste.
        page.goto(f"{BASE}/incidents")
        settle(page)
        link = page.locator("table a[href^='/incidents/']").first
        if link.count():
            link.click()
            settle(page)
            check(page, "04-incident")
            page.screenshot(path=OUT / "04-incident.png", full_page=True)
        else:
            problems.append("aucun incident à ouvrir")

        page.set_viewport_size({"width": 390, "height": 844})
        for name, path in SCREENS:
            if name in MOBILE:
                page.goto(f"{BASE}{path}")
                settle(page)
                check(page, f"{name}-mobile")
                page.screenshot(path=OUT / f"{name}-mobile.png", full_page=True)
        browser.close()

    for problem in problems:
        print(f"::error title=Capture::{problem}")
    print(f"{len(list(OUT.glob('*.png')))} captures dans {OUT}, {len(problems)} problème(s).")
    return 1 if problems else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - rendre l'échec lisible dans les annotations CI
        import traceback

        frames = traceback.extract_tb(exc.__traceback__)
        where = next(
            (f for f in reversed(frames) if f.filename.endswith("captures.py")), frames[-1]
        )
        message = f"{type(exc).__name__} : {str(exc).splitlines()[0][:300]}"
        print(f"::error title=Capture (ligne {where.lineno})::{message}")
        for problem in problems:
            print(f"::error title=Capture::{problem}")
        sys.exit(1)
