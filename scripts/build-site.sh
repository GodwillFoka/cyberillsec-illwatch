#!/usr/bin/env bash
# ============================================================================
# ILLWATCH — Construire le site de présentation servi par Caddy (ADR-027, lot S6)
#
#   ILLWATCH_SITE_DOMAIN=illwatch.exemple.eu ./scripts/build-site.sh
#
# Construit Website/dist pour le domaine du site, avec la langue selon le pays (/langue) et le
# formulaire de démonstration relayés vers l'API par Caddy (deploy/Caddyfile). Node.js n'est
# pas requis sur l'hôte : la construction tourne dans un conteneur node:22-alpine éphémère.
# Variables facultatives : INSTANCE_COUNTRY, DEFAULT_LANGUAGE (mêmes rôles que l'API),
# ILLWATCH_SITE_PUBLIC=1 pour refuser la construction tant que les mentions légales sont
# incomplètes (Website/src/data/legal.json).
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

domain="${ILLWATCH_SITE_DOMAIN:-}"
[[ -n "${domain}" ]] || { echo "✘ ILLWATCH_SITE_DOMAIN requis (ex. illwatch.exemple.eu)" >&2; exit 1; }

run() {
  if command -v node >/dev/null && node -e 'process.exit(+process.versions.node.split(".")[0] < 20)'; then
    node Website/build.mjs
  else
    docker run --rm -u "$(id -u):$(id -g)" -v "${PWD}:/w" -w /w \
      -e ILLWATCH_SITE_URL -e ILLWATCH_SITE_GEO_ENDPOINT -e ILLWATCH_SITE_DEMO_ENDPOINT \
      -e ILLWATCH_SITE_COUNTRY -e ILLWATCH_SITE_DEFAULT_LANG -e ILLWATCH_SITE_PUBLIC \
      node:22-alpine node Website/build.mjs
  fi
}

export ILLWATCH_SITE_URL="https://${domain}"
export ILLWATCH_SITE_GEO_ENDPOINT="/langue"
export ILLWATCH_SITE_DEMO_ENDPOINT="/api/v1/demo-requests"
export ILLWATCH_SITE_COUNTRY="${INSTANCE_COUNTRY:-}"
export ILLWATCH_SITE_DEFAULT_LANG="${DEFAULT_LANGUAGE:-}"
export ILLWATCH_SITE_PUBLIC="${ILLWATCH_SITE_PUBLIC:-0}"
run
echo "✔ Site construit dans Website/dist pour https://${domain} — docker compose restart caddy"
