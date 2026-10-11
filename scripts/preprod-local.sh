#!/usr/bin/env bash
# ============================================================================
# ILL Watch — Préproduction locale : la pile de production sur ce poste, en HTTPS
#
#   ./scripts/preprod-local.sh up       # construit l'image, démarre, crée le compte admin
#   ./scripts/preprod-local.sh check    # contrôles : HTTPS, en-têtes, API, SSE via Caddy,
#                                       #   rôle applicatif, worker, sauvegarde/restauration
#   ./scripts/preprod-local.sh demo     # données de démonstration FICTIVES (base vide) ; le
#                                       #   worker est arrêté pour ne jamais les mélanger à une
#                                       #   collecte réelle (mode « démonstration », mémorisé)
#   ./scripts/preprod-local.sh logs     # journaux (Ctrl+C pour quitter)
#   ./scripts/preprod-local.sh down     # arrête (données conservées)
#   ./scripts/preprod-local.sh purge    # arrête et SUPPRIME les données de préproduction
#
# Adresse : https://illwatch.localhost:8443  (certificat de l'autorité interne de Caddy :
# accepter l'avertissement du navigateur, ou importer la racine affichée par `check`).
# « illwatch.localhost » plutôt que « localhost » : l'en-tête HSTS de la préproduction ne doit
# pas s'appliquer à http://localhost:8000 (pile de développement).
#
# Démonstration dès le départ (CI, captures) : PREPROD_MODE=demo ./scripts/preprod-local.sh up
# démarre sans worker, puis `demo` charge les données sur une base restée vide.
#
# Isolation : projet Compose « illwatch-preprod », conteneurs et volumes à part. La pile de
# développement et ses données ne sont jamais touchées. Secrets générés dans .env.preprod
# (droits 600, ignoré par Git) ; mot de passe du compte admin affiché une seule fois par `up`.
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

ENV_FILE=".env.preprod"
DOMAIN="illwatch.localhost"
BASE="https://${DOMAIN}:8443"
export COMPOSE_FILE="docker-compose.yml:docker-compose.prod.yml:docker-compose.preprod.yml"
export COMPOSE_PROFILES="full"
export COMPOSE_PROJECT_NAME="illwatch-preprod"

ok() { printf '\033[32m✔\033[0m %s\n' "$*"; }
ko() { printf '\033[31m✘\033[0m %s\n' "$*" >&2; FAILED=$((FAILED + 1)); }
step() { printf '\n\033[1m▶ %s\033[0m\n' "$*"; }
die() { printf '\033[31m✘ %s\033[0m\n' "$*" >&2; exit 1; }
FAILED=0

# curl vers la préproduction : *.localhost résolu en boucle locale, autorité interne acceptée.
pcurl() { curl --silent --show-error --insecure --resolve "${DOMAIN}:8443:127.0.0.1" "$@"; }

need() {
  command -v docker >/dev/null || die "docker absent : sudo apt install docker.io docker-compose"
  docker compose version >/dev/null 2>&1 || die "docker compose (v2) absent"
  command -v curl >/dev/null || die "curl absent"
  command -v openssl >/dev/null || die "openssl absent"
}

secrets() {
  if [[ ! -f "${ENV_FILE}" ]]; then
    umask 077
    cat > "${ENV_FILE}" <<EOF
# Préproduction locale ILL Watch — généré le $(date -u +%FT%TZ). Ne pas versionner.
ILLWATCH_DOMAIN=${DOMAIN}
SECRET_KEY=$(openssl rand -hex 32)
POSTGRES_PASSWORD=$(openssl rand -hex 24)
POSTGRES_APP_PASSWORD=$(openssl rand -hex 24)
REDIS_PASSWORD=$(openssl rand -hex 24)
ADMIN_PASSWORD=$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-20)
EOF
    chmod 600 "${ENV_FILE}"
    ok "secrets générés dans ${ENV_FILE} (600)"
  fi
  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a
  # L'API et le worker lisent aussi .env (clés NVD, OTX…) ; vide s'il n'existe pas.
  [[ -f .env ]] || : > .env
}

wait_ready() {
  local i
  for i in $(seq 1 90); do
    if pcurl -o /dev/null -w '%{http_code}' "${BASE}/ready" 2>/dev/null | grep -q 200; then
      return 0
    fi
    sleep 2
  done
  docker compose ps
  docker compose logs --tail 60 api migrate caddy || true
  die "l'API ne répond pas « prête » derrière Caddy après 3 minutes"
}

token() {
  pcurl -X POST "${BASE}/api/v1/auth/token" \
    -d "username=admin" --data-urlencode "password=${ADMIN_PASSWORD}" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'
}

cmd_up() {
  need
  secrets
  step "Construction de l'image et démarrage (projet ${COMPOSE_PROJECT_NAME})"
  if [[ "${PREPROD_MODE:-}" == "demo" ]]; then
    docker compose up -d --build --scale worker=0
    ok "mode démonstration : worker non démarré (aucune collecte réelle)"
  else
    docker compose up -d --build
  fi
  wait_ready
  ok "API prête derrière Caddy : ${BASE}"
  step "Sources de référence et compte administrateur"
  docker compose exec -T api illwatch seed >/dev/null
  if docker compose exec -T api illwatch users create --username admin \
      --email admin@preprod.illwatch.test --role admin --password "${ADMIN_PASSWORD}" >/dev/null 2>&1; then
    ok "compte admin créé"
    if [[ -z "${CI:-}" ]]; then
      printf '   identifiant : admin\n   mot de passe : %s   (aussi dans %s)\n' "${ADMIN_PASSWORD}" "${ENV_FILE}"
    fi
  else
    ok "compte admin déjà présent (mot de passe dans ${ENV_FILE})"
  fi
  printf '\nOuvrir %s (accepter le certificat local), puis :\n' "${BASE}"
  printf '  %s check   # contrôles complets\n' "$0"
  printf '  %s demo    # données fictives, OU laisser le worker collecter les vraies sources\n' "$0"
}

cmd_demo() {
  need
  secrets
  # Jamais de collecte réelle à côté de données fictives.
  docker compose stop worker >/dev/null 2>&1 || true
  docker compose exec -T -e DEMO_PASSWORD="${ADMIN_PASSWORD}" api illwatch demo load --users
  grep -q '^PREPROD_MODE=' "${ENV_FILE}" || echo 'PREPROD_MODE=demo' >> "${ENV_FILE}"
  ok "démonstration chargée (comptes analyst et viewer : même mot de passe que admin)"
  ok "worker arrêté (mode démonstration) ; pour la collecte réelle : purge, puis up"
}

cmd_check() {
  need
  secrets
  wait_ready

  step "HTTPS et redirection"
  [[ "$(pcurl -o /dev/null -w '%{http_code}' "${BASE}/health")" == 200 ]] && ok "HTTPS /health 200" || ko "HTTPS /health"
  local redirect
  redirect=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' --resolve "${DOMAIN}:8080:127.0.0.1" "http://${DOMAIN}:8080/") || true
  [[ "${redirect}" == 30[18]\ https://* ]] && ok "HTTP redirigé vers HTTPS (${redirect})" || ko "redirection HTTP → HTTPS : ${redirect}"
  local ca="/tmp/illwatch-preprod-ca.$$.crt"
  if docker compose exec -T caddy cat /data/caddy/pki/authorities/local/root.crt > "${ca}" 2>/dev/null \
     && curl -sS -o /dev/null --cacert "${ca}" --resolve "${DOMAIN}:8443:127.0.0.1" "${BASE}/health"; then
    ok "certificat vérifié contre l'autorité interne de Caddy (TLS sans --insecure)"
  else
    ko "certificat non vérifiable contre l'autorité de Caddy"
  fi
  rm -f "${ca}"

  step "En-têtes de sécurité (page et API)"
  local page api
  page=$(pcurl -D - -o /dev/null "${BASE}/")
  api=$(pcurl -D - -o /dev/null "${BASE}/health")
  grep -qi '^strict-transport-security: max-age=' <<<"${page}" && ok "HSTS" || ko "HSTS absent"
  grep -qi "^content-security-policy:.*script-src 'self'" <<<"${page}" && ok "CSP de l'interface" || ko "CSP absente sur /"
  grep -qi '^x-content-type-options: nosniff' <<<"${api}" && ok "nosniff" || ko "X-Content-Type-Options absent"
  grep -qi '^server:' <<<"${page}${api}" && ko "en-tête Server divulgué" || ok "aucun en-tête Server"
  grep -qi '^x-request-id:' <<<"${api}" && ok "identifiant de requête" || ko "X-Request-ID absent"

  step "Interface et documentation"
  pcurl "${BASE}/" | grep -q '<div id="root">' && ok "interface servie à la racine" || ko "interface absente"
  [[ "$(pcurl -o /dev/null -w '%{http_code}' "${BASE}/docs")" == 404 ]] && ok "/docs masqué en production" || ko "/docs exposé"

  step "Authentification et API"
  local tok
  tok=$(token) || { ko "connexion admin refusée"; tok=""; }
  if [[ -n "${tok}" ]]; then
    ok "connexion admin"
    for path in users/me dashboard/summary feeds/health indicators cves incidents hunting/rules; do
      code=$(pcurl -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${tok}" "${BASE}/api/v1/${path}")
      [[ "${code}" == 200 ]] && ok "GET /api/v1/${path}" || ko "GET /api/v1/${path} → ${code}"
    done
    [[ "$(pcurl -o /dev/null -w '%{http_code}' "${BASE}/api/v1/indicators")" == 401 ]] && ok "API refusée sans jeton (401)" || ko "API accessible sans jeton"
  fi

  step "Temps réel (SSE) à travers Caddy"
  if [[ -n "${tok}" ]]; then
    local stream="/tmp/illwatch-preprod-sse.$$"
    ( pcurl -N --max-time 25 -H "Authorization: Bearer ${tok}" "${BASE}/api/v1/stream" > "${stream}" 2>/dev/null || true ) &
    local reader=$!
    sleep 3
    pcurl -o /dev/null -X POST -H "Authorization: Bearer ${tok}" -H 'Content-Type: application/json' \
      -d '{"title":"Contrôle SSE préproduction","description":"Créé par preprod-local.sh check","severity":"LOW"}' \
      "${BASE}/api/v1/incidents"
    sleep 5
    kill "${reader}" 2>/dev/null || true
    wait "${reader}" 2>/dev/null || true
    if grep -q 'incident.created' "${stream}"; then
      ok "événement reçu en direct à travers Caddy (pas de tampon, pas de compression)"
    else
      ko "aucun événement reçu sur le flux SSE (contenu : $(head -c 200 "${stream}" | tr '\n' ' '))"
    fi
    rm -f "${stream}"
  fi

  step "Base : rôle applicatif sans droit de structure"
  # Modification de structure dans une transaction annulée : seul le propriétaire le peut.
  local probe
  probe=$(docker compose exec -T postgres psql -U illwatch_app -d illwatch -v ON_ERROR_STOP=1 \
    -c 'BEGIN; ALTER TABLE users ADD COLUMN preprod_probe int; ROLLBACK;' 2>&1 || true)
  if grep -qiE 'must be owner|permission denied|doit être le propriétaire|droit refusé' <<<"${probe}"; then
    ok "ALTER TABLE refusé au rôle applicatif"
  else
    ko "rôle applicatif : refus attendu, obtenu « $(head -c 160 <<<"${probe}" | tr '\n' ' ') »"
  fi

  step "Worker de collecte"
  if [[ "${PREPROD_MODE:-}" == "demo" ]]; then
    ok "worker arrêté volontairement (mode démonstration)"
  elif docker compose ps --status running --services | grep -qx worker; then
    ok "worker en marche"
  else
    ko "worker arrêté : $(docker compose ps worker --format '{{.Status}}')"
  fi

  step "Sauvegarde puis restauration dans une base jetable"
  local dump="/tmp/illwatch-preprod-$$.dump"
  docker compose exec -T postgres pg_dump -U illwatch -d illwatch -Fc > "${dump}"
  if docker compose exec -T postgres pg_restore --list < "${dump}" >/dev/null; then
    ok "sauvegarde lisible ($(du -h "${dump}" | cut -f1))"
  else
    ko "sauvegarde illisible"
  fi
  docker compose exec -T postgres psql -U illwatch -d postgres -q -c 'DROP DATABASE IF EXISTS restore_check;' -c 'CREATE DATABASE restore_check;' >/dev/null
  if docker compose exec -T postgres pg_restore -U illwatch -d restore_check --no-owner --exit-on-error < "${dump}" 2>/dev/null; then
    local original restored
    original=$(docker compose exec -T postgres psql -U illwatch -d illwatch -tAc 'SELECT count(*) FROM incidents')
    restored=$(docker compose exec -T postgres psql -U illwatch -d restore_check -tAc 'SELECT count(*) FROM incidents')
    [[ "${original}" == "${restored}" ]] && ok "restauration fidèle (${restored} incidents)" || ko "restauration : ${original} ≠ ${restored}"
  else
    ko "restauration en échec"
  fi
  docker compose exec -T postgres psql -U illwatch -d postgres -q -c 'DROP DATABASE IF EXISTS restore_check;' >/dev/null
  rm -f "${dump}"

  echo
  if [[ ${FAILED} -eq 0 ]]; then
    printf '\033[1;32m✔ Préproduction locale conforme.\033[0m %s\n' "${BASE}"
  else
    printf '\033[1;31m✘ %d contrôle(s) en échec.\033[0m\n' "${FAILED}"
    exit 1
  fi
}

case "${1:-}" in
  up) cmd_up ;;
  check) cmd_check ;;
  demo) cmd_demo ;;
  logs) need; secrets; docker compose logs -f --tail 100 ;;
  down) need; secrets; docker compose down; ok "préproduction arrêtée (données conservées)" ;;
  purge)
    need; secrets
    read -r -p "Supprimer TOUTES les données de préproduction ? Taper PURGER : " answer
    [[ "${answer}" == "PURGER" ]] || die "abandon"
    docker compose down --volumes
    # Volumes de la préproduction nommés explicitement : ceux du développement ne sont jamais visés.
    docker volume rm illwatch_preprod_pgdata illwatch_preprod_redisdata >/dev/null 2>&1 || true
    rm -f "${ENV_FILE}"
    ok "préproduction supprimée (la pile de développement est intacte)"
    ;;
  *) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
