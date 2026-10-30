#!/usr/bin/env bash
# ============================================================================
# ILLWATCH, Test de restauration (M11) : la sauvegarde la plus récente est-elle utilisable ?
#
#   scripts/restore-test.sh [DOSSIER]      (défaut : /srv/illwatch-backups)
#
# Sans toucher à la base de production : vérifie l'empreinte SHA-256, restaure dans une base
# jetable (restore_check), compare quelques volumes à la production (une sauvegarde de la
# nuit peut avoir quelques lignes de moins, jamais davantage ni zéro), puis supprime la base
# jetable. Code de sortie non nul en cas d'écart : programmé chaque mois par deploy-vps.sh,
# résultat dans /var/log/illwatch-restore-test.log.
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

DIR="${1:-/srv/illwatch-backups}"
LATEST=$(ls -1t "${DIR}"/illwatch-*.dump 2>/dev/null | head -n 1 || true)
[[ -n "${LATEST}" ]] || { echo "✘ aucune sauvegarde dans ${DIR}" >&2; exit 1; }
echo "▶ $(date -u +%FT%TZ) test de restauration de ${LATEST}"
if [[ -f "${LATEST}.sha256" ]]; then
  sha256sum --check --quiet "${LATEST}.sha256" && echo "✔ empreinte SHA-256 vérifiée"
else
  echo "✘ empreinte SHA-256 absente" >&2; exit 1
fi

psql_admin() { docker compose exec -T postgres psql -U illwatch -v ON_ERROR_STOP=1 -q "$@"; }
cleanup() { psql_admin -d postgres -c 'DROP DATABASE IF EXISTS restore_check;' >/dev/null 2>&1 || true; }
trap cleanup EXIT

cleanup
psql_admin -d postgres -c 'CREATE DATABASE restore_check;' >/dev/null
started=$(date +%s)
docker compose exec -T postgres pg_restore -U illwatch -d restore_check --no-owner --exit-on-error < "${LATEST}"
echo "✔ restauration complète en $(( $(date +%s) - started )) s"

FAILED=0
for table in users threat_feeds indicators cves incidents audit_events; do
  live=$(psql_admin -d illwatch -tAc "SELECT count(*) FROM ${table}")
  restored=$(psql_admin -d restore_check -tAc "SELECT count(*) FROM ${table}")
  if [[ "${restored}" -gt 0 && "${restored}" -le "${live}" ]] || [[ "${live}" -eq 0 && "${restored}" -eq 0 ]]; then
    echo "✔ ${table} : ${restored} lignes restaurées (production : ${live})"
  else
    echo "✘ ${table} : ${restored} lignes restaurées, production : ${live}" >&2
    FAILED=$((FAILED + 1))
  fi
done
revision=$(psql_admin -d restore_check -tAc 'SELECT version_num FROM alembic_version')
echo "✔ révision du schéma restauré : ${revision}"
if ((FAILED)); then echo "✘ test de restauration en échec (${FAILED} écart(s))" >&2; exit 1; fi
echo "✔ sauvegarde utilisable"
