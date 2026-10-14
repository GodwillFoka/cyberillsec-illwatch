"""Captures des tableaux Grafana (M11, revue visuelle en CI « Préproduction »).

Usage : python scripts/captures_grafana.py http://127.0.0.1:3000 DOSSIER
(mot de passe admin Grafana : variable GRAFANA_ADMIN_PASSWORD)

Échoue si un tableau est absent ou si un panneau affiche une erreur de requête.
"""

import base64
import os
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE = sys.argv[1].rstrip("/")
OUT = Path(sys.argv[2])
TOKEN = base64.b64encode(f"admin:{os.environ['GRAFANA_ADMIN_PASSWORD']}".encode()).decode()
BOARDS = [("14-grafana-service", "illwatch-service"), ("15-grafana-collecte", "illwatch-cti")]


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    problems: list[str] = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(
            viewport={"width": 1440, "height": 1100},
            # En-tête envoyé d'emblée : Grafana redirige vers /login au lieu de répondre 401.
            extra_http_headers={"Authorization": f"Basic {TOKEN}"},
            color_scheme="dark",
        )
        page = context.new_page()
        console: list[str] = []
        page.on(
            "console",
            lambda m: console.append(f"{m.type}: {m.text}") if m.type == "error" else None,
        )
        page.on("pageerror", lambda e: console.append(f"exception : {e}"))
        page.on("requestfailed", lambda r: console.append(f"échec {r.url} {r.failure}"))
        page.on(
            "response",
            lambda r: console.append(f"HTTP {r.status} {r.url}") if r.status >= 400 else None,
        )
        for name, uid in BOARDS:
            page.goto(f"{BASE}/d/{uid}?orgId=1&from=now-30m&to=now&kiosk", wait_until="load")
            try:
                page.wait_for_selector(".react-grid-layout", timeout=45_000)
            except Exception:  # noqa: BLE001 - signalé ci-dessous, avec la capture
                console.append("grille du tableau absente après 45 s")
            page.wait_for_timeout(5000)
            if page.locator("text=failed to load its application files").first.is_visible():
                problems.append(f"{uid} : interface Grafana non chargée")
                problems += [f"{uid} : {line[:300]}" for line in console[:8]]
            if page.locator("text=Dashboard not found").count():
                problems.append(f"{uid} : tableau absent")
            errors = page.locator('[data-testid="data-testid Panel status error"]').count()
            if errors:
                problems.append(f"{uid} : {errors} panneau(x) en erreur")
            page.screenshot(path=str(OUT / f"{name}.png"), full_page=True)
            print(f"{name}.png")
        browser.close()
    for problem in problems:
        print(f"::error title=Grafana::{problem}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
