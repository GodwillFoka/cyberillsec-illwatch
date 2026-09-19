"""Agrégateur des routes `/api/v1`.

Chaque module métier branche ici son propre `APIRouter` au fur et à mesure des
phases du planning (§5.1). Les routes non encore implémentées ne sont pas
déclarées : l'OpenAPI exposé reflète strictement ce qui fonctionne.
"""

from fastapi import APIRouter

api_router = APIRouter()

# Phase 2 — MOD-02 : from sentry.app.api.v1 import feeds, indicators
# Phase 3 — MOD-03 : from sentry.app.api.v1 import cves
# Phase 4 — MOD-04 : from sentry.app.api.v1 import incidents
# Phase 5 — MOD-05 : from sentry.app.api.v1 import dashboard
# Phase 6 — MOD-06 : from sentry.app.api.v1 import hunting
