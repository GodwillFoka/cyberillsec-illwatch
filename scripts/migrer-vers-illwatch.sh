#!/usr/bin/env bash
# ============================================================================
# ILLWATCH — Migration d'un poste SENTRY vers ILLWATCH (renommage du 08/10/2026)
#
# À lancer UNE fois, depuis la racine du dépôt, après `git pull` du code renommé,
# venv activé, API et collectes arrêtées :
#
#   ./scripts/migrer-vers-illwatch.sh            # migration
#   ./scripts/migrer-vers-illwatch.sh --retour   # retour arrière (avant toute reprise d'activité)
#
# Étapes :
#   1. pg_dump de l'ancienne base (conteneur sentry-postgres, base et rôle « sentry »)
#   2. arrêt des anciens conteneurs ; leur volume est CONSERVÉ (retour arrière possible)
#   3. sauvegarde puis réécriture du .env (SENTRY_* → ILLWATCH_*, sentry → illwatch)
#   4. nouveaux conteneurs illwatch-postgres / illwatch-redis (volume neuf)
#   5. pg_restore dans la base « illwatch », droits du rôle illwatch_app réappliqués
#   6. réinstallation du paquet (sentry-cti → illwatch), comptages comparés
#
# Rien n'est supprimé : l'ancien volume, l'ancien .env et le dump restent sur le disque.
# ============================================================================
set -euo pipefail

WORK="${HOME}/illwatch-migration"
DUMP="${WORK}/sentry.dump"
OLD_PG="sentry-postgres"
OLD_REDIS="sentry-redis"
NEW_PG="illwatch-postgres"
TABLES="users threat_feeds indicators indicator_sources cves cve_priority_history cve_alerts incidents incident_events hunting_sessions hunting_matches audit_events collector_state"

step() { printf '\n\033[1;36m▶ %s\033[0m\n' "$1"; }
ok()   { printf '\033[1;32m✔ %s\033[0m\n' "$1"; }
die()  { printf '\033[1;31m✘ %s\033[0m\n' "$1" >&2; exit 1; }

counts() {  # counts <conteneur> <rôle> <base>
  local sql="" t
  for t in ${TABLES}; do sql+="SELECT '${t}', count(*) FROM ${t} UNION ALL "; done
  docker exec "$1" psql -U "$2" -d "$3" -tAF' ' -c "${sql% UNION ALL }"
}

[[ -f pyproject.toml && -d illwatch ]] || die "Lancer depuis la racine du dépôt, après git pull du code renommé."

# ---------------------------------------------------------------------------
# Retour arrière
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "--retour" ]]; then
  step "Retour arrière vers SENTRY"
  [[ -f "${WORK}/env.sentry" ]] || die "Sauvegarde ${WORK}/env.sentry introuvable."
  docker stop illwatch-api illwatch-worker illwatch-redis "${NEW_PG}" 2>/dev/null || true
  cp "${WORK}/env.sentry" .env
  docker start "${OLD_PG}" "${OLD_REDIS}"
  ok "Anciens conteneurs redémarrés, .env restauré."
  echo "Reste à faire : git checkout f878deb && pip install -c constraints.txt -e \".[dev]\""
  exit 0
fi

# ---------------------------------------------------------------------------
# Contrôles préalables
# ---------------------------------------------------------------------------
step "Contrôles préalables"
[[ -n "${VIRTUAL_ENV:-}" ]] || die "Activez le venv du projet (source .venv/bin/activate)."
docker inspect "${OLD_PG}" >/dev/null 2>&1 || die "Conteneur ${OLD_PG} introuvable : rien à migrer."
if docker inspect "${NEW_PG}" >/dev/null 2>&1; then
  die "${NEW_PG} existe déjà : migration déjà faite ? (docker rm -f ${NEW_PG} pour recommencer)"
fi
if pgrep -f "uvicorn sentry|sentry feeds|sentry cves|sentry hunt" >/dev/null; then
  pgrep -af "uvicorn sentry|sentry feeds|sentry cves|sentry hunt" || true
  die "Des processus SENTRY tournent encore : arrêtez-les (pkill -f 'uvicorn sentry' …)."
fi
[[ -f .env ]] || die ".env introuvable."
docker start "${OLD_PG}" >/dev/null
for _ in $(seq 1 30); do docker exec "${OLD_PG}" pg_isready -U sentry -d sentry -q && break; sleep 1; done
ok "prêt"

# ---------------------------------------------------------------------------
step "1/6 Sauvegarde de l'ancienne base"
mkdir -p "${WORK}"; chmod 700 "${WORK}"; umask 077
counts "${OLD_PG}" sentry sentry | tee "${WORK}/comptages-avant.txt"
docker exec "${OLD_PG}" pg_dump -U sentry -d sentry -Fc --no-owner --no-privileges > "${DUMP}"
docker exec -i "${OLD_PG}" pg_restore --list < "${DUMP}" > /dev/null
sha256sum "${DUMP}" > "${DUMP}.sha256"
ok "${DUMP} ($(du -h "${DUMP}" | cut -f1)), vérifié"

# ---------------------------------------------------------------------------
step "2/6 Arrêt des anciens conteneurs (volume conservé)"
docker stop sentry-api sentry-worker "${OLD_REDIS}" "${OLD_PG}" 2>/dev/null || true
ok "arrêtés"

# ---------------------------------------------------------------------------
step "3/6 Réécriture du .env"
cp -p .env "${WORK}/env.sentry"
sed -i \
  -e 's/SENTRY_/ILLWATCH_/g' \
  -e 's/sentry_app/illwatch_app/g' \
  -e 's/sentry-app-dev/illwatch-app-dev/g' \
  -e 's/sentry-dev-redis/illwatch-dev-redis/g' \
  -e 's#//sentry:sentry@#//illwatch:illwatch@#g' \
  -e 's#\(:[0-9]\{2,5\}\)/sentry\b#\1/illwatch#g' \
  .env
if grep -n -i sentry .env; then
  echo "⚠ Occurrences restantes ci-dessus : à vérifier à la main (valeurs personnalisées)."
fi
ok ".env réécrit (ancien : ${WORK}/env.sentry)"

# ---------------------------------------------------------------------------
step "4/6 Nouveaux conteneurs PostgreSQL et Redis"
docker compose up -d postgres redis
for _ in $(seq 1 60); do docker exec "${NEW_PG}" pg_isready -U illwatch -d illwatch -q && break; sleep 1; done
sleep 3  # le script d'initialisation (rôle illwatch_app) s'exécute au premier démarrage
ok "illwatch-postgres et illwatch-redis démarrés"

# ---------------------------------------------------------------------------
step "5/6 Restauration dans la base illwatch"
docker exec -i "${NEW_PG}" pg_restore -U illwatch -d illwatch --no-owner --no-privileges \
  --single-transaction --exit-on-error < "${DUMP}"
ok "restaurée"

# ---------------------------------------------------------------------------
step "6/6 Paquet, droits et contrôle"
pip uninstall -y sentry-cti >/dev/null 2>&1 || true
pip install -q -c constraints.txt -e ".[dev]"
hash -r
illwatch db app-role illwatch_app
counts "${NEW_PG}" illwatch illwatch | tee "${WORK}/comptages-apres.txt"
if diff -u "${WORK}/comptages-avant.txt" "${WORK}/comptages-apres.txt"; then
  ok "Comptages identiques sur ${TABLES// /, }"
else
  die "Comptages différents : NE PAS reprendre l'activité ; retour arrière : $0 --retour"
fi
illwatch status || true

printf '\n\033[1;32m✔ Migration terminée.\033[0m\n'
cat <<EOF
Relancer l'API :      uvicorn illwatch.app.main:app --port 8000 &
Scénario SOC :        python scripts/scenario_soc.py
Ancien volume conservé : supprimable après quelques jours d'usage normal
  (docker rm ${OLD_PG} ${OLD_REDIS} && docker volume ls | grep sentry_)
EOF
