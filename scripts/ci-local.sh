#!/usr/bin/env bash
# ============================================================================
# ILLWATCH — Réplique locale du pipeline GitLab (.gitlab-ci.yml)
#
# À lancer avant chaque push : un pipeline rouge sur GitLab coûte un aller-retour,
# celui-ci coûte une minute. Mêmes étapes, même ordre, même seuils.
#
# Prérequis : venv activé (pip install -e ".[dev]"), PostgreSQL joignable (par défaut la base
# Docker Compose, port hôte 5433), Node.js ≥ 20 pour l'interface. `psql` n'est pas requis :
# à défaut, il est appelé dans le conteneur illwatch-postgres.
#
#   ./scripts/ci-local.sh                  # réseau, qualité, tests, migrations, interface
#   ./scripts/ci-local.sh --sans-interface # sans l'étape Node
#   ./scripts/ci-local.sh --docker         # + construction de l'image
#
# Tout est aussi écrit dans /tmp/illwatch-ci-local.log (à joindre en cas d'échec).
# ============================================================================
set -euo pipefail
exec > >(tee /tmp/illwatch-ci-local.log) 2>&1

WITH_UI=1
WITH_DOCKER=0
for arg in "$@"; do
  case "$arg" in
    --sans-interface) WITH_UI=0 ;;
    --docker) WITH_DOCKER=1 ;;
    *) echo "Option inconnue : $arg" >&2; exit 2 ;;
  esac
done
STARTED=$SECONDS

PG_URL_BASE="${CI_LOCAL_PG:-postgresql+asyncpg://illwatch:illwatch@localhost:5433}"
export SECRET_KEY="${SECRET_KEY:-ci-secret-key-not-for-production}"
export ENVIRONMENT=development
# Comme en CI : aucun `.env` lu. Celui du poste définit MIGRATION_DATABASE_URL vers la base
# de travail ; l'étape 2b (`alembic downgrade base`) aurait alors vidé cette base au lieu de
# la base jetable. Les variables héritées du shell sont écartées pour la même raison.
export ILLWATCH_ENV_FILE=""
unset MIGRATION_DATABASE_URL DATABASE_APP_ROLE

step() { printf '\n\033[1;36m▶ %s\033[0m\n' "$1"; }
ok()   { printf '\033[1;32m✔ %s\033[0m\n' "$1"; }
fail() { printf '\033[1;31m✘ %s\033[0m\n' "$1" >&2; exit 1; }

step "Étape 0 — Réseau et outils"
# Les coupures DNS de la VM (09-10/10) font échouer pip, npm et git avec des messages obscurs :
# on les détecte d'abord, avec le remède.
for host in github.com pypi.org registry.npmjs.org; do
  getent hosts "$host" >/dev/null || fail "DNS : $host introuvable. Vérifiez la connexion, puis
  sudo nmcli con mod \"Wired connection 1\" ipv4.dns \"1.1.1.1 9.9.9.9\" ipv4.ignore-auto-dns yes
  sudo nmcli con up \"Wired connection 1\""
done
command -v ruff >/dev/null || fail "ruff absent : activez le venv (source .venv/bin/activate)"
if [[ $WITH_UI == 1 ]]; then
  command -v node >/dev/null || fail "Node.js absent (sudo apt install nodejs npm) ou relancez avec --sans-interface"
  node_major=$(node -p 'process.versions.node.split(".")[0]')
  (( node_major >= 20 )) || fail "Node.js $node_major trop ancien (≥ 20 requis)"
fi
ok "réseau et outils"

step "Étape 1 — Qualité : lint, formatage, typage strict"
ruff check .
ruff format --check .
mypy illwatch
ok "qualité"

PSQL_URL="${PG_URL_BASE/+asyncpg/}/postgres"
TEST_DB="illwatch_test"   # jamais la base de travail : les tests détruisent le schéma

# psql de l'hôte s'il existe, sinon celui du conteneur PostgreSQL de Docker Compose.
pg() {
  if command -v psql >/dev/null; then
    psql "$PSQL_URL" "$@"
  else
    docker exec -i illwatch-postgres psql -U illwatch -d postgres "$@"
  fi
}

step "Étape 2a — Tests sur PostgreSQL (base dédiée ${TEST_DB})"
pg -tAc "SELECT 1 FROM pg_database WHERE datname='${TEST_DB}'" | grep -q 1 \
  || pg -qc "CREATE DATABASE ${TEST_DB}" >/dev/null
DATABASE_URL="${PG_URL_BASE}/${TEST_DB}" pytest -q
ok "tests"

step "Étape 2b — Migrations : montée, alembic check, descente, remontée"
# Base dédiée et jetable : ne touche jamais aux données de la base de travail.
MIG_DB="illwatch_ci_migrations"
pg -qc "DROP DATABASE IF EXISTS ${MIG_DB}" -c "CREATE DATABASE ${MIG_DB}" >/dev/null
export DATABASE_URL="${PG_URL_BASE}/${MIG_DB}"
alembic upgrade head
alembic check
alembic downgrade base
alembic upgrade head
pg -qc "DROP DATABASE ${MIG_DB}" >/dev/null
ok "migrations"
unset DATABASE_URL

if [[ $WITH_UI == 1 ]]; then
  step "Étape 2c — Interface web : schéma, audit, types, tests, build (comme la CI)"
  illwatch openapi -o frontend/openapi.json
  (
    cd frontend
    npm ci --no-audit --no-fund
    npm audit --omit=dev --audit-level=high
    npm run gen:api
    npx tsc --noEmit --pretty false
    npm test
    npx vite build
    ! grep -E "<script>[^<]" dist/index.html
  )
  ok "interface (frontend/dist prêt : uvicorn le sert sur http://localhost:8000)"
fi

if [[ $WITH_DOCKER == 1 ]]; then
  step "Étape 3 — Build : l'image doit se construire et la CLI répondre"
  docker build -t illwatch:ci-local .
  docker run --rm --entrypoint illwatch illwatch:ci-local version
  ok "image"
fi

printf '\n\033[1;32m✔ Pipeline local vert en %d s : prêt à pousser.\033[0m\n' $((SECONDS - STARTED))
printf 'Journal complet : /tmp/illwatch-ci-local.log. Les analyses de sécurité (SAST, secrets,\n'
printf 'dépendances Python) ne tournent que sur GitLab et GitHub.\n'
