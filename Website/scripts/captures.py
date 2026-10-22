"""Captures et contrôles du site de présentation (ADR-027), lancés par le workflow « Site web ».

    python Website/scripts/captures.py http://127.0.0.1:8080 Website/captures

Pour chaque langue, en grand écran et sur téléphone : capture pleine page, et échec si la page
écrit une erreur dans la console, viole la CSP, déborde horizontalement, ou si le simulateur et
la détection de langue ne fonctionnent pas.
"""

from __future__ import annotations

import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

LANGS = ["fr", "en", "de", "es", "zh"]
VIEWPORTS = {"bureau": (1440, 900), "telephone": (390, 844)}


def main(base: str, out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    problems: list[str] = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for lang in LANGS:
            for name, (width, height) in VIEWPORTS.items():
                context = browser.new_context(
                    viewport={"width": width, "height": height},
                    locale=lang,
                    reduced_motion="reduce",
                )
                page = context.new_page()
                errors: list[str] = []
                page.on(
                    "console", lambda m, e=errors: e.append(m.text) if m.type == "error" else None
                )
                page.on("pageerror", lambda exc, e=errors: e.append(str(exc)))
                page.goto(f"{base}/{lang}/", wait_until="networkidle")
                overflow = page.evaluate("document.documentElement.scrollWidth - window.innerWidth")
                if overflow > 0:
                    problems.append(f"{lang} {name} : débordement horizontal de {overflow} px")
                if name == "bureau":
                    # Le simulateur réagit : préréglage « critique » → P0.
                    page.locator("[data-preset]").first.click()
                    badge = page.locator('[data-out="priority"]').inner_text()
                    if not badge.startswith("P0"):
                        problems.append(f"{lang} : simulateur, P0 attendu, obtenu « {badge} »")
                    page.locator("[data-preset]").nth(2).click()
                    if page.locator('[data-out="floor"]').is_hidden():
                        problems.append(f"{lang} : simulateur, plancher KEV non affiché")
                page.screenshot(path=str(out / f"{lang}-{name}.png"), full_page=True)
                problems += [f"{lang} {name} : console : {e}" for e in errors]
                context.close()

        # Détection : langue du navigateur, puis pays (fuseau horaire), puis anglais.
        for browser_lang, zone, expected in (
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
                problems.append(
                    f"racine : {browser_lang} / {zone} → {page.url}, attendu /{expected}/"
                )
            context.close()
        # Choix manuel mémorisé : il l'emporte sur la langue du navigateur.
        context = browser.new_context(locale="de-DE")
        page = context.new_page()
        page.goto(f"{base}/de/", wait_until="networkidle")
        page.locator(".langmenu summary").click()
        page.locator('.langmenu [data-lang-choice="es"]').click()
        page.goto(f"{base}/", wait_until="networkidle")
        if not page.url.rstrip("/").endswith("/es"):
            problems.append(f"racine : choix manuel « es » ignoré → {page.url}")
        context.close()
        browser.close()

    for problem in problems:
        print(f"✘ {problem}")
    print(f"{'✘' if problems else '✔'} {len(LANGS) * len(VIEWPORTS)} captures dans {out}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1].rstrip("/"), Path(sys.argv[2])))
