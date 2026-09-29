"""Agrégateur des routes `/api/v1`.

Chaque module métier branche ici son propre `APIRouter` au fur et à mesure des
phases du planning (§5.1). Les routes non encore implémentées ne sont pas
déclarées : l'OpenAPI exposé reflète strictement ce qui fonctionne.
"""

from fastapi import APIRouter

from sentry.app.api.v1 import auth, cves, feeds, indicators

api_router = APIRouter()

# Phase 1 — MOD-01 : authentification
api_router.include_router(auth.router)

# Phase 2 — MOD-02 : sources de flux (T2.2) et indicateurs (RF-07, RF-08)
api_router.include_router(feeds.router)
api_router.include_router(indicators.router)

# Phase 3 — MOD-03 : moteur CVE (RF-14) et alertes (RF-15)
api_router.include_router(cves.router)
api_router.include_router(cves.alerts_router)
# Phase 4 — MOD-04 : from sentry.app.api.v1 import incidents
# Phase 5 — MOD-05 : from sentry.app.api.v1 import dashboard
# Phase 6 — MOD-06 : from sentry.app.api.v1 import hunting
