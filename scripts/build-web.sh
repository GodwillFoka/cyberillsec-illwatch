#!/usr/bin/env bash
# ============================================================================
# ILLWATCH — Construire l'interface web servie par uvicorn (frontend/dist)
#
# Les types TypeScript sont générés depuis le schéma OpenAPI de l'API : après un `git pull`
# qui modifie l'API, `npm run build` seul compile avec l'ancien schéma et échoue (TS2339).
# Ce script enchaîne tout, dans l'ordre de la CI :
#   schéma OpenAPI → dépendances npm → types → compilation → construction.
#
# Prérequis : venv activé (commande `illwatch`), Node.js ≥ 20.
#   ./scripts/build-web.sh
# Puis redémarrer uvicorn (il sert frontend/dist).
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

command -v illwatch >/dev/null || { echo "✘ commande illwatch absente : source .venv/bin/activate" >&2; exit 1; }
command -v npm >/dev/null || { echo "✘ npm absent : sudo apt install nodejs npm" >&2; exit 1; }

echo "▶ Schéma OpenAPI de l'API"
illwatch openapi -o frontend/openapi.json
cd frontend
echo "▶ Dépendances (verrouillées)"
npm ci --no-audit --no-fund
echo "▶ Types générés, compilation, construction"
npm run gen:api
npm run build
echo "✔ Interface construite dans frontend/dist : redémarrez uvicorn, puis Ctrl+Maj+R dans le navigateur."
