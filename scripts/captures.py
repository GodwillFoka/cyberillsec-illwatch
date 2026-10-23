"""Captures d'écran de l'interface, pour la revue visuelle (CI « Préproduction »).

Usage : python scripts/captures.py URL_BASE DOSSIER   (mot de passe : variable CAPTURE_PASSWORD)

Se connecte avec le compte « admin », parcourt chaque écran et l'enregistre en PNG, en grand
écran (1440 × 900) et en largeur mobile (390 × 844). Les captures principales sont **en
anglais** (interface et, avec `DEFAULT_LANGUAGE=en`, données de démonstration) : ce sont elles
que reprend le site de présentation ; la vue d'ensemble et le triage sont aussi capturés dans
les quatre autres langues (suffixe `-fr`, `-de`, `-es`, `-zh`). Échoue si une page
affiche une erreur, si la console du navigateur signale une erreur ou une violation de la
politique de sécurité (CSP) : une capture « réussie » d'un écran cassé ne doit pas passer.
"""

import os
import re
import sys
from pathlib import Path
from urllib.parse import quote

from playwright.sync_api import Page, sync_playwright

BASE = sys.argv[1].rstrip("/")
OUT = Path(sys.argv[2])
PASSWORD = os.environ["CAPTURE_PASSWORD"]

# Valeur longue de la démonstration (illwatch/modules/foundation/demo.py, LONG_URL) : la fiche
# d'un IOC à rallonge doit tenir dans son panneau.
LONG_URL = (
    "https://secure-login.microsoftonline-verification.phish.example/common/oauth2/v2.0/"
    "authorize?client_id=4765445b-32c6-49b0-83e6-1d93765276ca&response_type=code&redirect_uri="
    "https%3A%2F%2Fsecure-login.microsoftonline-verification.phish.example%2Fcallback&scope="
    "openid%20profile%20offline_access&state=a8f5f167f44f4964e6c998dee827110c&nonce="
    "6f1ed002ab5595859014ebf0951522d9"
)

SCREENS = [
    ("01-vue-ensemble", "/"),
    ("02-triage", "/triage"),
    ("03-incidents", "/incidents"),
    ("05-indicateurs", "/indicateurs"),
    ("05b-indicateur-ip", "/indicateurs?valeur=203.0.113.50"),
    ("05c-indicateur-url-longue", f"/indicateurs?valeur={quote(LONG_URL, safe='')}"),
    ("06-cve", "/cve"),
    ("06b-cve-avis-long", "/cve?cve=CVE-2099-90011"),
    ("07-chasse", "/chasse"),
    ("08-sources", "/sources"),
    ("09-administration", "/administration"),
    ("09b-parametres", "/administration?onglet=parametres"),
    ("09c-journal", "/administration?onglet=audit"),
    ("10-correlations", "/correlations"),
    ("11-inventaire", "/inventaire"),
    ("12-pilotage", "/pilotage"),
    ("12b-pilotage-30j", "/pilotage?jours=30"),
    ("13-campagnes", "/campagnes"),
]
# Téléphone : tous les écrans (les débordements y sont les plus fréquents).
MOBILE = {name for name, _ in SCREENS}

problems: list[str] = []


# « Chargement… » dans les cinq langues de l'interface (ADR-027).
LOADING = ("Chargement…", "Loading…", "Wird geladen…", "Cargando…", "加载中…")


def settle(page: Page) -> None:
    # Pas de « networkidle » : le flux temps réel (SSE) garde une connexion ouverte en permanence.
    page.wait_for_load_state("load")
    # Laisse finir chargements et animations (graphiques, mise en évidence des nouveautés).
    # Attente côté Python : la CSP de l'interface (script-src 'self') refuse, à juste titre,
    # le JavaScript passé en chaîne par wait_for_function.
    for _ in range(60):
        body = page.inner_text("body")
        if not any(text in body for text in LOADING):
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
  // Un panneau de détail ne défile jamais latéralement : son contenu doit s'y plier.
  for (const panel of document.querySelectorAll(".detail")) {
    if (panel.scrollWidth > panel.clientWidth + 1) {
      const wide = panel.scrollWidth;
      out.push(`panneau de détail : contenu de ${wide} px pour ${panel.clientWidth} px`);
    }
  }
  // Texte qui sort de son cadre (mot très long : adresse, empreinte, message d'erreur). Ignoré :
  // un élément qui tronque volontairement (overflow ≠ visible) ou qui vit dans une zone qui défile.
  for (const el of document.querySelectorAll("p, dd, li, h1, h2, h3, .notice, .title")) {
    if (el.scrollWidth <= el.clientWidth + 1 || el.clientWidth === 0) continue;
    if (getComputedStyle(el).overflowX !== "visible") continue;
    let scroller = el.parentElement;
    let inside = false;
    while (scroller && scroller !== document.body) {
      const ox = getComputedStyle(scroller).overflowX;
      const scrolls = ox === "auto" || ox === "scroll";
      if (scrolls && !scroller.matches(".card, main")) { inside = true; break; }
      scroller = scroller.parentElement;
    }
    if (inside) continue;
    const text = (el.textContent || "").trim().slice(0, 40);
    const size = `${el.scrollWidth} px pour ${el.clientWidth}`;
    out.push(`texte qui déborde de son cadre : « ${text}… » (${size})`);
    if (out.length >= 5) return out;
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


def shoot(page: Page, path: Path) -> None:
    """Capture de toute la page : la zone principale défile seule, la fenêtre est donc agrandie
    à la hauteur de son contenu le temps de la capture (6 000 px au plus)."""
    size = page.viewport_size or {"width": 1440, "height": 900}
    height = page.evaluate(
        "() => { const m = document.querySelector('main');"
        " return m ? m.scrollHeight + m.getBoundingClientRect().top + 8"
        " : document.documentElement.scrollHeight; }"
    )
    page.set_viewport_size(
        {"width": size["width"], "height": max(size["height"], min(int(height), 6000))}
    )
    page.wait_for_timeout(400)
    page.screenshot(path=path, full_page=True)
    page.set_viewport_size(size)


def check(page: Page, name: str) -> None:
    text = page.inner_text("body")
    for marker in (
        "Données indisponibles",
        "Data unavailable",
        "Daten nicht verfügbar",
        "Datos no disponibles",
        "数据不可用",
        "Page introuvable",
        "Something went wrong",
    ):
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
            locale="en-GB",
            timezone_id="Europe/London",
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

        # Interface en anglais dès l'écran de connexion (choix mémorisé, comme le sélecteur).
        page.goto(f"{BASE}/")
        page.evaluate("localStorage.setItem('illwatch.lang', 'en')")
        page.reload()
        settle(page)
        page.screenshot(path=OUT / "00-connexion.png")
        page.get_by_label("Username").fill("admin")
        page.get_by_label("Password").fill(PASSWORD)
        page.get_by_role("button", name=re.compile("^Sign in$", re.I)).click()
        page.wait_for_selector("nav")
        settle(page)

        for name, path in SCREENS:
            page.goto(f"{BASE}{path}")
            settle(page)
            check(page, name)
            html_lang = page.evaluate("document.documentElement.lang")
            if not html_lang.startswith("en"):
                problems.append(f"{name} : langue du document « {html_lang} » (anglais attendu)")
            shoot(page, OUT / f"{name}.png")

        # Page d'investigation : premier incident de la liste.
        page.goto(f"{BASE}/incidents")
        settle(page)
        link = page.locator("table a[href^='/incidents/']").first
        if link.count():
            link.click()
            settle(page)
            check(page, "04-incident")
            shoot(page, OUT / "04-incident.png")
        else:
            problems.append("aucun incident à ouvrir")

        # Interface multilingue (ADR-027) : la vue d'ensemble et le triage dans les quatre autres
        # langues, choix mémorisé comme le ferait le sélecteur ; erreurs de console contrôlées.
        for lang in ("fr", "de", "es", "zh"):
            page.evaluate("lang => localStorage.setItem('illwatch.lang', lang)", lang)
            for name, path in (("01-vue-ensemble", "/"), ("02-triage", "/triage")):
                page.goto(f"{BASE}{path}")
                settle(page)
                html_lang = page.evaluate("document.documentElement.lang")
                if not html_lang.startswith(lang):
                    problems.append(f"{name}-{lang} : langue du document « {html_lang} »")
                check(page, f"{name}-{lang}")
                shoot(page, OUT / f"{name}-{lang}.png")
        page.evaluate("localStorage.setItem('illwatch.lang', 'en')")

        page.set_viewport_size({"width": 390, "height": 844})
        for name, path in SCREENS:
            if name in MOBILE:
                page.goto(f"{BASE}{path}")
                settle(page)
                check(page, f"{name}-mobile")
                shoot(page, OUT / f"{name}-mobile.png")
        # Investigation sur téléphone : titre long, chronologie, panneau d'actions.
        page.goto(f"{BASE}/incidents")
        settle(page)
        link = page.locator("table a[href^='/incidents/']").first
        if link.count():
            link.click()
            settle(page)
            check(page, "04-incident-mobile")
            shoot(page, OUT / "04-incident-mobile.png")
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
