#!/usr/bin/env bash
# ============================================================================
# SENTRY — Réplique locale du pipeline GitLab (.gitlab-ci.yml)
#
# À lancer avant chaque push : un pipeline rouge sur GitLab coûte un aller-retour,
# celui-ci coûte une minute. Mêmes étapes, même ordre, même seuils.
#
# Prérequis : venv activé (pip install -e ".[dev]") et PostgreSQL joignable.
# Par défaut : la base Docker Compose (port hôte 5433, voir docker-compose.yml).
#
#   ./scripts/ci-local.sh              # qualité + tests + migrations
#   ./scripts/ci-local.sh --docker     # + construction de l'image
# ============================================================================
set -euo pipefail

PG_URL_BASE="${CI_LOCAL_PG:-postgresql+asyncpg://sentry:sentry@localhost:5433}"
export SECRET_KEY="${SECRET_KEY:-ci-secret-key-not-for-production}"
export ENVIRONMENT=development

step() { printf '\n\033[1;36m▶ %s\033[0m\n' "$1"; }
ok()   { printf '\033[1;32m✔ %s\033[0m\n' "$1"; }

step "Étape 1 — Qualité : lint, formatage, typage strict"
ruff check .
ruff format --check .
mypy sentry
ok "qualité"

PSQL_URL="${PG_URL_BASE/+asyncpg/}/postgres"
TEST_DB="sentry_test"   # jamais la base de travail : les tests détruisent le schéma

step "Étape 2a — Tests sur PostgreSQL (base dédiée ${TEST_DB})"
psql "$PSQL_URL" -tAc "SELECT 1 FROM pg_database WHERE datname='${TEST_DB}'" | grep -q 1 \
  || psql "$PSQL_URL" -qc "CREATE DATABASE ${TEST_DB}" >/dev/null
DATABASE_URL="${PG_URL_BASE}/${TEST_DB}" pytest -q
ok "tests"

step "Étape 2b — Migrations : montée, alembic check, descente, remontée"
# Base dédiée et jetable : ne touche jamais aux données de la base de travail.
MIG_DB="sentry_ci_migrations"
psql "$PSQL_URL" -qc "DROP DATABASE IF EXISTS ${MIG_DB}" -c "CREATE DATABASE ${MIG_DB}" >/dev/null
export DATABASE_URL="${PG_URL_BASE}/${MIG_DB}"
alembic upgrade head
alembic check
alembic downgrade base
alembic upgrade head
psql "$PSQL_URL" -qc "DROP DATABASE ${MIG_DB}" >/dev/null
ok "migrations"

if [[ "${1:-}" == "--docker" ]]; then
  step "Étape 3 — Build : l'image doit se construire et la CLI répondre"
  docker build -t sentry:ci-local .
  docker run --rm --entrypoint sentry sentry:ci-local version
  ok "image"
fi

printf '\n\033[1;32m✔ Pipeline local vert : prêt à pousser.\033[0m\n'
printf 'Les analyses de sécurité (SAST, secrets, dépendances) ne tournent que sur GitLab.\n'
