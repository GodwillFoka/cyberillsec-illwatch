"""Captures et contrôles du site de présentation (ADR-027), lancés par le workflow « Site web ».

    python Website/scripts/captures.py http://127.0.0.1:8080 Website/captures \
        [--demo http://127.0.0.1:8091] [--axe chemin/axe.min.js]

Pour chaque langue et chaque page, en grand écran et sur téléphone : échec si la page écrit une
erreur dans la console, viole la CSP ou déborde horizontalement. Captures pleine page de
l'accueil et des pages principales. Contrôles fonctionnels : simulateur, onglets,
explorateur ATT&CK, détection de la langue, choix mémorisé. Avec `--demo` : formulaire de
démonstration contre l'API factice (scripts/mock_api.py). Avec `--axe` : accessibilité
WCAG 2.x niveau A et AA (axe-core), échec sur toute violation grave ou critique.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from playwright.sync_api import Page, sync_playwright

LANGS = ["fr", "en", "de", "es", "zh"]
PAGES = ["", "platform/", "security/", "pricing/", "about/", "demo/", "legal/", "privacy/"]
SHOTS = {"", "platform/", "pricing/"}  # pages capturées (les autres sont seulement contrôlées)
VIEWPORTS = {"bureau": (1440, 900), "telephone": (390, 844)}


def page_name(slug: str) -> str:
    return slug.strip("/") or "accueil"


def check_home(page: Page, lang: str, problems: list[str]) -> None:
    # Le simulateur réagit : préréglage « critique » → P0, « modérée mais exploitée » → plancher.
    page.locator("[data-preset]").first.click()
    badge = page.locator('[data-out="priority"]').inner_text()
    if not badge.startswith("P0"):
        problems.append(f"{lang} : simulateur, P0 attendu, obtenu « {badge} »")
    page.locator("[data-preset]").nth(2).click()
    if page.locator('[data-out="floor"]').is_hidden():
        problems.append(f"{lang} : simulateur, plancher KEV non affiché")
    # Onglets des fonctionnalités : un seul panneau visible, celui choisi.
    page.locator("#tab-hunt").click()
    visible = page.locator('#produit [role="tabpanel"]:visible')
    if visible.count() != 1 or visible.first.get_attribute("id") != "panel-hunt":
        problems.append(f"{lang} : onglets des fonctionnalités inopérants")


def check_platform(page: Page, lang: str, problems: list[str]) -> None:
    page.locator("#tech-T1486").click()
    visible = page.locator('#attack [role="tabpanel"]:visible')
    if visible.count() != 1 or visible.first.get_attribute("id") != "tech-panel-T1486":
        problems.append(f"{lang} : explorateur ATT&CK inopérant")
    page.keyboard.press("ArrowUp")
    if page.locator("#tech-T1568\\.002").get_attribute("aria-selected") != "true":
        problems.append(f"{lang} : explorateur ATT&CK, navigation au clavier inopérante")


def check_pages(browser, base: str, out: Path, problems: list[str]) -> None:
    for lang in LANGS:
        for name, (width, height) in VIEWPORTS.items():
            context = browser.new_context(
                viewport={"width": width, "height": height}, locale=lang, reduced_motion="reduce"
            )
            page = context.new_page()
            errors: list[str] = []
            page.on("console", lambda m, e=errors: e.append(m.text) if m.type == "error" else None)
            page.on("pageerror", lambda exc, e=errors: e.append(str(exc)))
            for slug in PAGES:
                errors.clear()
                page.goto(f"{base}/{lang}/{slug}", wait_until="networkidle")
                label = f"{lang} {name} {page_name(slug)}"
                overflow = page.evaluate("document.documentElement.scrollWidth - window.innerWidth")
                if overflow > 0:
                    problems.append(f"{label} : débordement horizontal de {overflow} px")
                if name == "bureau" and slug == "":
                    check_home(page, lang, problems)
                if name == "bureau" and slug == "platform/":
                    check_platform(page, lang, problems)
                if slug in SHOTS:
                    shot = out / f"{lang}-{page_name(slug)}-{name}.png"
                    page.screenshot(path=str(shot), full_page=True)
                problems += [f"{label} : console : {e}" for e in errors]
            context.close()


def check_language(browser, base: str, problems: list[str]) -> None:
    # Détection hors serveur : pays (fuseau horaire) d'abord, navigateur pour départager
    # un pays bilingue ou à défaut de pays, puis anglais.
    for browser_lang, zone, expected in (
        ("en-US", "Europe/Berlin", "de"),
        ("fr-CH", "Europe/Zurich", "fr"),
        ("en-CA", "America/Toronto", "en"),
        ("de-AT", "UTC", "de"),
        ("zh-CN", "UTC", "zh"),
        ("es-MX", "UTC", "es"),
        ("fr-CA", "UTC", "fr"),
        ("ja-JP", "Europe/Paris", "fr"),
        ("ja-JP", "UTC", "en"),
    ):
        context = browser.new_context(locale=browser_lang, timezone_id=zone)
        page = context.new_page()
        page.goto(f"{base}/", wait_until="networkidle")
        if not page.url.rstrip("/").endswith(f"/{expected}"):
            problems.append(f"racine : {browser_lang} / {zone} → {page.url}, attendu /{expected}/")
        context.close()
    # Choix manuel mémorisé : il l'emporte sur la langue du navigateur, et le sélecteur garde
    # la page courante.
    context = browser.new_context(locale="de-DE")
    page = context.new_page()
    page.goto(f"{base}/de/pricing/", wait_until="networkidle")
    page.locator(".langmenu summary").click()
    page.locator('.langmenu [data-lang-choice="es"]').click()
    page.wait_for_load_state("networkidle")
    if not page.url.rstrip("/").endswith("/es/pricing"):
        problems.append(f"sélecteur : page courante non conservée → {page.url}")
    page.goto(f"{base}/", wait_until="networkidle")
    if not page.url.rstrip("/").endswith("/es"):
        problems.append(f"racine : choix manuel « es » ignoré → {page.url}")
    context.close()


def check_demo_form(browser, demo: str, problems: list[str]) -> None:
    context = browser.new_context(viewport={"width": 1440, "height": 900})
    page = context.new_page()
    errors: list[str] = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.goto(f"{demo}/en/demo/", wait_until="networkidle")
    status = page.locator(".demo-form__status")
    page.locator('button[type="submit"]').click()
    if page.locator("[aria-invalid]").count() == 0 or not status.inner_text():
        problems.append("formulaire : champs invalides non signalés")
    page.fill('input[name="name"]', "Ada Lovelace")
    page.fill('input[name="email"]', "ada@example.org")
    page.fill('input[name="organisation"]', "CERT Example")
    page.select_option('select[name="country"]', "GB")
    page.select_option('select[name="interest"]', "PILOT")
    page.check('input[name="consent"]')
    page.locator('button[type="submit"]').click()
    page.wait_for_function(
        "el => el.dataset.tone === 'ok'", arg=status.element_handle(), timeout=5000
    )
    for _ in range(3):  # l'API factice limite au-delà de trois demandes
        page.check('input[name="consent"]')
        page.fill('input[name="name"]', "Ada Lovelace")
        page.fill('input[name="email"]', "ada@example.org")
        page.fill('input[name="organisation"]', "CERT Example")
        page.locator('button[type="submit"]').click()
        page.wait_for_timeout(400)
    if status.get_attribute("data-tone") != "error":
        problems.append("formulaire : limitation de débit (429) non signalée")
    problems += [f"formulaire : console : {e}" for e in errors if "429" not in e]
    context.close()


def check_accessibility(browser, base: str, axe: Path, problems: list[str]) -> None:
    # Le script axe-core est injecté en contournant la CSP du site, pour le seul contrôle.
    # Animations réduites : les sections s'affichent d'emblée (sinon, encore transparentes avant
    # le défilement, elles fausseraient le calcul des contrastes).
    context = browser.new_context(
        viewport={"width": 1440, "height": 900}, bypass_csp=True, reduced_motion="reduce"
    )
    page = context.new_page()
    for lang in ("en", "zh"):
        for slug in PAGES:
            page.goto(f"{base}/{lang}/{slug}", wait_until="networkidle")
            page.add_script_tag(path=str(axe))
            result = page.evaluate(
                """async () => {
                  const tags = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];
                  const r = await axe.run(document, { runOnly: tags });
                  return r.violations.map(v => ({ id: v.id, impact: v.impact, count: v.nodes.length,
                    target: v.nodes[0] && v.nodes[0].target.join(" ") }));
                }"""
            )
            for v in result:
                where = f"{lang} {page_name(slug)}"
                line = (
                    f"accessibilité {where} : {v['id']} ({v['impact']}, "
                    f"{v['count']} élément(s), ex. {v['target']})"
                )
                if v["impact"] in ("serious", "critical"):
                    problems.append(line)
                else:
                    print(f"::warning title=Accessibilité::{line}")
    context.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("base")
    parser.add_argument("out", type=Path)
    parser.add_argument("--demo", help="site construit avec le formulaire, servi par mock_api.py")
    parser.add_argument("--axe", type=Path, help="axe.min.js (axe-core)")
    args = parser.parse_args()
    base = args.base.rstrip("/")
    args.out.mkdir(parents=True, exist_ok=True)
    problems: list[str] = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        check_pages(browser, base, args.out, problems)
        check_language(browser, base, problems)
        if args.demo:
            check_demo_form(browser, args.demo.rstrip("/"), problems)
        if args.axe:
            check_accessibility(browser, base, args.axe, problems)
        browser.close()

    for problem in problems:
        print(f"✘ {problem}")
        print(f"::error title=Site web::{problem}")  # annotation lisible sans les journaux
    pages = len(LANGS) * len(VIEWPORTS) * len(PAGES)
    print(f"{'✘' if problems else '✔'} {pages} pages contrôlées, captures dans {args.out}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
