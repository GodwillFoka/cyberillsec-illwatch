#!/usr/bin/env bash
# ============================================================================
# SENTRY — Sauvegarde PostgreSQL (M7 Production Hardening)
#
#   scripts/backup.sh [DOSSIER]        # défaut : ./backups, 14 sauvegardes conservées
#   KEEP=30 scripts/backup.sh /srv/sentry-backups
#   PGURL=postgresql://user:mdp@hote:5432/sentry scripts/backup.sh   # base hors Compose
#
# Format « custom » de pg_dump (compressé, restauration sélective), vérifié par
# pg_restore --list, empreinte SHA-256 à côté, rotation des plus anciennes.
# Le journal d'audit et la chronologie des incidents sont sauvegardés comme le reste :
# leurs déclencheurs d'immuabilité n'empêchent ni la lecture ni la restauration.
# ============================================================================
set -euo pipefail

DEST="${1:-backups}"
KEEP="${KEEP:-14}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
FILE="${DEST}/sentry-${STAMP}.dump"

mkdir -p "${DEST}"
chmod 700 "${DEST}"          # les sauvegardes contiennent les comptes et le renseignement
umask 077

if [[ -z "${PGURL:-}" ]] && docker compose ps -q postgres 2>/dev/null | grep -q .; then
  echo "▶ pg_dump via le conteneur Compose « postgres »"
  docker compose exec -T postgres pg_dump -U sentry -d sentry -Fc > "${FILE}"
  verify() { docker compose exec -T postgres pg_restore --list < "$1" > /dev/null; }
else
  : "${PGURL:?Base introuvable : démarrez docker compose ou exportez PGURL=postgresql://…}"
  echo "▶ pg_dump direct"
  pg_dump "${PGURL}" -Fc -f "${FILE}"
  verify() { pg_restore --list "$1" > /dev/null; }
fi

verify "${FILE}"
sha256sum "${FILE}" > "${FILE}.sha256"
echo "✔ ${FILE} ($(du -h "${FILE}" | cut -f1)), vérifiée"

# Rotation : on garde les KEEP plus récentes.
mapfile -t OLD < <(ls -1t "${DEST}"/sentry-*.dump 2>/dev/null | tail -n +"$((KEEP + 1))")
for old in "${OLD[@]}"; do
  rm -f -- "${old}" "${old}.sha256"
  echo "  rotation : ${old} supprimée"
done
