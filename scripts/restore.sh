#!/usr/bin/env bash
# ============================================================================
# SENTRY — Restauration d'une sauvegarde (M7 Production Hardening)
#
#   scripts/restore.sh backups/sentry-20261003T020000Z.dump
#   PGURL=postgresql://user:mdp@hote:5432/sentry scripts/restore.sh FICHIER
#
# REMPLACE le contenu de la base cible. Arrêter l'API et le worker avant :
#   docker compose --profile full stop api worker
# Puis, après restauration : sentry db current && curl -fsS localhost:8000/ready
# ============================================================================
set -euo pipefail

FILE="${1:?Usage : scripts/restore.sh FICHIER.dump}"
[[ -f "${FILE}" ]] || { echo "Fichier introuvable : ${FILE}" >&2; exit 1; }
if [[ -f "${FILE}.sha256" ]]; then
  sha256sum --check --quiet "${FILE}.sha256"
  echo "✔ empreinte SHA-256 vérifiée"
fi

read -r -p "Remplacer le contenu de la base par ${FILE} ? Taper RESTAURER : " answer
[[ "${answer}" == "RESTAURER" ]] || { echo "Abandon."; exit 1; }

OPTS=(--clean --if-exists --no-owner --exit-on-error --single-transaction)
if [[ -z "${PGURL:-}" ]] && docker compose ps -q postgres 2>/dev/null | grep -q .; then
  docker compose exec -T postgres pg_restore -U sentry -d sentry "${OPTS[@]}" < "${FILE}"
else
  : "${PGURL:?Base introuvable : démarrez docker compose ou exportez PGURL=postgresql://…}"
  pg_restore -d "${PGURL}" "${OPTS[@]}" "${FILE}"
fi
echo "✔ restauration terminée — vérifier : sentry db current && sentry status"
