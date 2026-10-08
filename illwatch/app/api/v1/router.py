"""Agrégateur des routes `/api/v1`.

Chaque module métier branche ici son propre `APIRouter` au fur et à mesure des
phases du planning (§5.1). Les routes non encore implémentées ne sont pas
déclarées : l'OpenAPI exposé reflète strictement ce qui fonctionne.
"""

from fastapi import APIRouter

from illwatch.app.api.v1 import (
    audit,
    auth,
    cves,
    dashboard,
    feeds,
    hunting,
    incidents,
    indicators,
    stream,
)

api_router = APIRouter()

# Phase 1 — MOD-01 : authentification
api_router.include_router(auth.router)

# Phase 2 — MOD-02 : sources de flux (T2.2) et indicateurs (RF-07, RF-08)
api_router.include_router(feeds.router)
api_router.include_router(indicators.router)

# Phase 3 — MOD-03 : moteur CVE (RF-11 à RF-15) et alertes (RF-16)
api_router.include_router(cves.router)
api_router.include_router(cves.alerts_router)

# Phase 4 — MOD-04 : gestion d'incidents (RF-17 à RF-20)
api_router.include_router(incidents.router)
api_router.include_router(incidents.alert_router)

# Phase 5 — MOD-05 : tableau de bord SOC (RF-21 à RF-24)
api_router.include_router(dashboard.router)

# Phase 6 — MOD-06 : threat hunting (RF-25 à RF-28)
api_router.include_router(hunting.router)

# M7 — Production Hardening : journal d'audit de sécurité (ADR-011)
api_router.include_router(audit.router)

# ADR-016 — interface web : flux temps réel (Server-Sent Events)
api_router.include_router(stream.router)
