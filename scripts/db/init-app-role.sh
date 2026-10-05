#!/bin/sh
# ============================================================================
# SENTRY — création du rôle PostgreSQL applicatif au premier démarrage du conteneur
# (M7 lot 2, ADR-012). Exécuté une seule fois par l'image postgres, à l'initialisation
# d'un volume vide (/docker-entrypoint-initdb.d). Les droits sont posés ensuite par
# `sentry db upgrade` (DATABASE_APP_ROLE), après chaque migration.
#
# Volume déjà initialisé : créer le rôle à la main, une fois :
#   SENTRY_APP_DB_PASSWORD=… sentry db app-role sentry_app --create
# ============================================================================
set -eu
: "${POSTGRES_APP_PASSWORD:?POSTGRES_APP_PASSWORD manquant}"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v app_password="$POSTGRES_APP_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE sentry_app LOGIN PASSWORD %L', :'app_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentry_app') \gexec
SQL
