"""Scénario d'acceptation SOC de bout en bout contre une instance SENTRY réelle.

Usage : python scripts/scenario_soc.py [URL_BASE]   (défaut : http://localhost:8000)

Prérequis : base migrée et alimentée (`sentry seed`, `sentry feeds fetch-all`,
`sentry cves sync`), quatre comptes créés (admin, analyst, analyst2, viewer) avec le mot de
passe de la variable SCENARIO_PASSWORD. Le script n'écrit que via l'API publique, mesure
la latence de chaque appel et sort en code 1 au premier écart à l'attendu.
"""

import json
import os
import statistics
import sys
import time
from typing import Any

import httpx

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
API = f"{BASE}/api/v1"
PASSWORD = os.environ.get("SCENARIO_PASSWORD", "Audit-Passw0rd-2026")
results: list[tuple[str, bool, str]] = []
latencies: dict[str, list[float]] = {}


def check(label: str, ok: bool, detail: str = "") -> None:
    results.append((label, ok, detail))
    print(f"{'✔' if ok else '✘'} {label}{' — ' + detail if detail else ''}")


def call(c: httpx.Client, method: str, url: str, key: str, **kw: Any) -> httpx.Response:
    start = time.perf_counter()
    r = c.request(method, url, **kw)
    latencies.setdefault(key, []).append((time.perf_counter() - start) * 1000)
    return r


def login(c: httpx.Client, user: str, password: str = PASSWORD) -> httpx.Response:
    return call(
        c, "POST", f"{API}/auth/token", "auth", data={"username": user, "password": password}
    )


def headers(c: httpx.Client, user: str) -> dict[str, str]:
    r = login(c, user)
    r.raise_for_status()
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def main() -> int:
    c = httpx.Client(timeout=60)
    adm, ana, ana2, vie = (headers(c, u) for u in ("admin", "analyst", "analyst2", "viewer"))
    me2 = call(c, "GET", f"{API}/users/me", "users", headers=ana2).json()

    # --- 1-3. Renseignement collecté (M2) ------------------------------------------------
    iocs = call(c, "GET", f"{API}/indicators", "iocs", headers=vie, params={"limit": 5})
    check(
        "IOC réels consultables (VIEWER)",
        iocs.status_code == 200 and iocs.json()["total"] > 0,
        f"{iocs.json().get('total')} IOC",
    )
    ioc = iocs.json()["items"][0]
    detail = call(c, "GET", f"{API}/indicators/{ioc['id']}", "iocs", headers=vie).json()
    check(
        "Provenance d'un IOC exposée",
        len(detail["sources"]) >= 1,
        f"{ioc['value']} ← {detail['sources'][0]['feed_name']}",
    )

    # --- 4-5. CVE et score (M3) ---------------------------------------------------------
    cves = call(c, "GET", f"{API}/cves", "cves", headers=vie, params={"limit": 5})
    check(
        "CVE réelles consultables",
        cves.status_code == 200 and cves.json()["total"] > 0,
        f"{cves.json().get('total')} CVE",
    )
    cve = cves.json()["items"][0]
    cdet = call(c, "GET", f"{API}/cves/{cve['id']}", "cves", headers=vie)
    check("Décomposition du score d'une CVE", cdet.status_code == 200, cve["id"])

    # --- 8-13. Incident complet (M4) ------------------------------------------------------
    r = call(
        c,
        "POST",
        f"{API}/incidents",
        "incidents",
        headers=ana,
        json={
            "title": "C2 connu observé sur le proxy",
            "description": "Connexion sortante vers une IP de la liste IPsum niveau 5.",
            "severity": "HIGH",
        },
    )
    check("Ouverture d'incident (ANALYST)", r.status_code == 201, str(r.status_code))
    inc = r.json()["id"]
    r = call(
        c,
        "POST",
        f"{API}/incidents",
        "incidents",
        headers=vie,
        json={"title": "x", "description": "x", "severity": "LOW"},
    )
    check("VIEWER ne peut pas ouvrir d'incident", r.status_code == 403, str(r.status_code))
    r = call(
        c,
        "PUT",
        f"{API}/incidents/{inc}/assignee",
        "incidents",
        headers=ana,
        json={"user_id": me2["id"]},
    )
    check("Assignation à un analyste", r.status_code == 200, str(r.status_code))
    r = call(
        c,
        "POST",
        f"{API}/incidents/{inc}/indicators",
        "incidents",
        headers=ana,
        json={"indicator_id": ioc["id"]},
    )
    check("Liaison IOC réel", r.status_code in (200, 201), str(r.status_code))
    r = call(
        c,
        "POST",
        f"{API}/incidents/{inc}/cves",
        "incidents",
        headers=ana,
        json={"cve_id": cve["id"]},
    )
    check("Liaison CVE réelle", r.status_code in (200, 201), str(r.status_code))
    r = call(
        c,
        "POST",
        f"{API}/incidents/{inc}/transitions",
        "incidents",
        headers=ana,
        json={"target": "CLOTURE"},
    )
    check(
        "Transition interdite NOUVEAU → CLOTURE refusée", r.status_code == 409, str(r.status_code)
    )
    for target in ("ANALYSE", "CONFINEMENT", "ERADICATION", "RECUPERATION"):
        r = call(
            c,
            "POST",
            f"{API}/incidents/{inc}/transitions",
            "incidents",
            headers=ana,
            json={"target": target, "note": f"Passage en {target}"},
        )
        check(f"Transition → {target}", r.status_code == 200, str(r.status_code))
    r = call(
        c,
        "POST",
        f"{API}/incidents/{inc}/notes",
        "incidents",
        headers=ana2,
        json={"message": "Poste isolé, IP bloquée sur le pare-feu."},
    )
    check("Note d'investigation", r.status_code in (200, 201), str(r.status_code))
    r = call(
        c,
        "POST",
        f"{API}/incidents/{inc}/transitions",
        "incidents",
        headers=ana,
        json={"target": "CLOTURE"},
    )
    check("Clôture sans post-mortem refusée", r.status_code in (409, 422), str(r.status_code))
    r = call(
        c,
        "POST",
        f"{API}/incidents/{inc}/transitions",
        "incidents",
        headers=ana,
        json={
            "target": "CLOTURE",
            "closure_summary": "Cause : poste compromis par un chargeur. Actions : "
            "réimage, rotation des secrets, règle de blocage.",
        },
    )
    check("Clôture avec post-mortem", r.status_code == 200, str(r.status_code))
    full = call(c, "GET", f"{API}/incidents/{inc}", "incidents", headers=vie).json()
    check(
        "Chronologie complète",
        len(full["timeline"]) >= 8,
        f"{len(full['timeline'])} évènements, statut {full['status']}",
    )

    # --- 12. Dashboard (M5) ----------------------------------------------------------------
    s = call(c, "GET", f"{API}/dashboard/summary", "dashboard", headers=vie)
    check("Synthèse SOC", s.status_code == 200, json.dumps(s.json())[:160])
    rec = call(c, "GET", f"{API}/dashboard/recent", "dashboard", headers=vie)
    check("Activité récente", rec.status_code == 200, f"{len(rec.json())} évènements")
    for ds in ("iocs", "cves", "incidents", "alerts"):
        for fmt in ("csv", "json"):
            e = call(
                c,
                "GET",
                f"{API}/dashboard/export",
                f"export-{ds}",
                headers=vie,
                params={"dataset": ds, "format": fmt},
            )
            size = len(e.content)
            check(f"Export {ds}.{fmt}", e.status_code == 200, f"{size} octets")

    # --- 10. Threat hunting (M6) -------------------------------------------------------------
    obs = [
        ioc["value"],
        "update-check.duckdns.org",
        "xjq7v9kz2lq8w3rt.com",
        "8.8.8.8",
        "pas-un-observable@@",
    ]
    h = call(
        c,
        "POST",
        f"{API}/hunting/sessions",
        "hunt",
        headers=ana,
        json={"observables": obs, "rules": ["RULE-02", "RULE-03", "RULE-04", "RULE-06"]},
    )
    hj = h.json()
    rules_hit = sorted({m["rule_id"] for m in hj.get("matches", [])})
    check(
        "Chasse sur observables",
        h.status_code == 201 and hj["status"] == "TERMINEE",
        f"{hj.get('matches_count')} corresp. {rules_hit}, rejetés {hj.get('rejected_count')}",
    )
    h = call(
        c,
        "POST",
        f"{API}/hunting/sessions",
        "hunt-base",
        headers=ana,
        json={"rules": ["RULE-02", "RULE-03", "RULE-04"]},
    )
    hj = h.json()
    check(
        "Chasse sur la base complète",
        h.status_code == 201,
        f"{hj.get('observables_count')} IOC, {hj.get('matches_count')} corresp., "
        f"{latencies['hunt-base'][-1]:.0f} ms",
    )
    h = call(c, "POST", f"{API}/hunting/sessions", "hunt", headers=vie, json={"rules": None})
    check("VIEWER ne peut pas chasser", h.status_code == 403, str(h.status_code))

    # --- Sécurité -----------------------------------------------------------------------------
    r = c.get(f"{API}/incidents")
    check("Sans jeton → 401", r.status_code == 401, str(r.status_code))
    bad = ana["Authorization"][:-4] + "AAAA"
    r = c.get(f"{API}/incidents", headers={"Authorization": bad})
    check("Jeton altéré → 401", r.status_code == 401, str(r.status_code))
    none_alg = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + ana["Authorization"].split(".")[1] + "."
    r = c.get(f"{API}/incidents", headers={"Authorization": f"Bearer {none_alg}"})
    check("Jeton alg=none → 401", r.status_code == 401, str(r.status_code))
    r = call(
        c,
        "POST",
        f"{API}/feeds",
        "feeds",
        headers=adm,
        json={
            "name": "ssrf",
            "url": "https://169.254.169.254/latest/meta-data/",
            "feed_type": "JSON",
        },
    )
    check(
        "Source vers métadonnées cloud refusée (SSRF)",
        r.status_code == 422 and "interne ou réservée" in r.text,
        f"{r.status_code} {r.text[:120]}",
    )
    r = call(
        c,
        "POST",
        f"{API}/feeds",
        "feeds",
        headers=ana,
        json={"name": "x", "url": "https://example.org/x.json", "feed_type": "JSON"},
    )
    check("ANALYST ne peut pas créer de source", r.status_code == 403, str(r.status_code))
    r = c.get(f"{API}/incidents/00000000-0000-0000-0000-000000000000", headers=vie)
    check("Incident inexistant → 404", r.status_code == 404, str(r.status_code))
    r = c.get(f"{API}/cves/CVE-2021-44228' OR '1'='1", headers=vie)
    check(
        "Injection dans l'identifiant CVE sans effet",
        r.status_code in (404, 422),
        str(r.status_code),
    )
    codes = [login(c, "viewer", "mauvais-mot-de-passe").status_code for _ in range(6)]
    check("Force brute : 429 après 5 échecs", codes[-1] == 429, str(codes))
    r = login(c, "viewer")
    check(
        "Adresse de l'attaquant bloquée même avec le bon mot de passe",
        r.status_code == 429,
        str(r.status_code),
    )

    # --- M7 : titulaire épargné, audit, sondes ------------------------------------------------
    # uvicorn fait confiance à X-Forwarded-For venant de 127.0.0.1 (FORWARDED_ALLOW_IPS) :
    # on simule ainsi la titulaire du compte qui se connecte depuis une autre adresse.
    r = c.post(
        f"{API}/auth/token",
        data={"username": "viewer", "password": PASSWORD},
        headers={"X-Forwarded-For": "192.0.2.50"},
    )
    check(
        "Titulaire non bloquée depuis une autre adresse (M7)",
        r.status_code == 200,
        str(r.status_code),
    )
    ready = c.get(f"{BASE}/ready")
    check("Sonde /ready", ready.status_code in (200, 503), ready.text[:120])
    page = call(c, "GET", f"{API}/audit", "audit", headers=adm, params={"limit": 500})
    if page.status_code == 404:
        check("Journal d'audit (M7)", False, "route absente : version antérieure à M7")
    else:
        actions = {(i["action"], i["outcome"]) for i in page.json()["items"]}
        expected = {
            ("auth.login", "SUCCESS"),
            ("auth.login", "FAILURE"),
            ("auth.login", "DENIED"),
            ("authz.denied", "DENIED"),
            ("data.export", "SUCCESS"),
            ("hunt.run", "SUCCESS"),
        }
        missing = expected - actions
        check(
            "Journal d'audit complet (M7)",
            not missing,
            f"manquants : {sorted(missing)}" if missing else f"{page.json()['total']} lignes",
        )
    r = c.get(f"{API}/audit", headers=vie)
    check("Journal d'audit réservé aux ADMIN", r.status_code == 403, str(r.status_code))

    # --- Latences -------------------------------------------------------------------------------
    print("\nLatences (ms) : appel · n · médiane · max")
    for key, values in sorted(latencies.items()):
        print(f"  {key:<18} {len(values):>3} {statistics.median(values):>8.1f} {max(values):>8.1f}")
    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)}/{len(results)} vérifications réussies")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
