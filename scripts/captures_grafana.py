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
BOARDS = [
    ("14-grafana-service", "illwatch-service", "API joignable"),
    ("15-grafana-collecte", "illwatch-cti", "IOC actifs"),
]


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    problems: list[str] = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(
            viewport={"width": 1440, "height": 1300},
            # En-tête envoyé d'emblée : Grafana redirige vers /login au lieu de répondre 401.
            extra_http_headers={"Authorization": f"Basic {TOKEN}"},
            color_scheme="dark",
            # Sans langue explicite, Chromium sans interface transmet une langue que l'API Intl
            # refuse (« Incorrect locale information provided ») et Grafana ne démarre pas.
            locale="fr-FR",
            timezone_id="Europe/Paris",
        )
        for name, uid, first_panel in BOARDS:
            page = context.new_page()  # page neuve : aucun état d'un tableau précédent
            console: list[str] = []
            page.on(
                "console",
                lambda m, log=console: (
                    log.append(f"{m.type}: {m.text}") if m.type == "error" else None
                ),
            )
            page.on("pageerror", lambda e, log=console: log.append(f"exception : {e}"))
            page.goto(f"{BASE}/d/{uid}?orgId=1&from=now-30m&to=now&kiosk", wait_until="load")
            try:
                page.get_by_text(first_panel, exact=True).first.wait_for(timeout=45_000)
            except Exception:  # noqa: BLE001 - signalé ci-dessous, avec la capture
                problems.append(f"{uid} : panneau « {first_panel} » absent après 45 s")
                problems += [f"{uid} : {line[:300]}" for line in console[:8]]
            page.wait_for_timeout(5000)
            if page.locator("text=Dashboard not found").count():
                problems.append(f"{uid} : tableau absent")
            errors = page.locator('[data-testid="data-testid Panel status error"]').count()
            if errors:
                problems.append(f"{uid} : {errors} panneau(x) en erreur")
            # Pas de full_page : le redimensionnement relance la mise en page (capture vide).
            page.screenshot(path=str(OUT / f"{name}.png"))
            page.close()
            print(f"{name}.png")
        browser.close()
    for problem in problems:
        print(f"::error title=Grafana::{problem}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
