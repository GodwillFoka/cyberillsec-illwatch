#!/usr/bin/env bash
# ============================================================================
# ILLWATCH — Passage aux volumes à nom fixe (08/10/2026)
#
# Jusqu'ici, Docker Compose préfixait conteneurs et volumes par le nom du DOSSIER
# (cyberillsec-sentry_illwatch_pgdata) : renommer le dossier aurait démarré une base vide.
# docker-compose.yml fixe désormais le projet (`name: illwatch`) et les volumes
# (`illwatch_pgdata`, `illwatch_redisdata`). Ce script copie les données une fois, puis le
# dossier peut porter n'importe quel nom.
#
#   ./scripts/deplacer-volumes-illwatch.sh
#
# Les anciens volumes sont CONSERVÉS ; à supprimer à la main après vérification.
# ============================================================================
set -euo pipefail

PG="illwatch-postgres"
OLD_PG_VOL="${OLD_PG_VOL:-cyberillsec-sentry_illwatch_pgdata}"
OLD_REDIS_VOL="${OLD_REDIS_VOL:-cyberillsec-sentry_illwatch_redisdata}"
IMAGE="postgres:16-alpine"   # déjà présente : sert d'outil de copie

ok()  { printf '\033[1;32m✔ %s\033[0m\n' "$1"; }
die() { printf '\033[1;31m✘ %s\033[0m\n' "$1" >&2; exit 1; }
count() { docker exec "${PG}" psql -U illwatch -d illwatch -tAc "SELECT (SELECT count(*) FROM indicators) || ' IOC, ' || (SELECT count(*) FROM cves) || ' CVE'"; }

grep -q '^name: illwatch' docker-compose.yml || die "docker-compose.yml sans « name: illwatch » : faites d'abord git pull."
docker volume inspect "${OLD_PG_VOL}" >/dev/null 2>&1 || die "Volume ${OLD_PG_VOL} introuvable (déjà déplacé ?)."
if docker volume inspect illwatch_pgdata >/dev/null 2>&1; then
  die "Le volume illwatch_pgdata existe déjà : déplacement déjà fait."
fi
if pgrep -f "uvicorn illwatch|illwatch feeds" >/dev/null; then
  die "API ou collecte ILLWATCH en cours : arrêtez-les (pkill -f 'uvicorn illwatch')."
fi

docker start "${PG}" >/dev/null
for _ in $(seq 1 30); do docker exec "${PG}" pg_isready -U illwatch -d illwatch -q && break; sleep 1; done
AVANT="$(count)"
echo "Avant : ${AVANT}"

# Les conteneurs appartiennent à l'ancien projet Compose : on les retire (pas les volumes).
docker rm -f illwatch-api illwatch-worker illwatch-redis "${PG}" >/dev/null 2>&1 || true

for pair in "${OLD_PG_VOL}:illwatch_pgdata" "${OLD_REDIS_VOL}:illwatch_redisdata"; do
  from="${pair%%:*}"; to="${pair##*:}"
  docker volume inspect "${from}" >/dev/null 2>&1 || { echo "(${from} absent, ignoré)"; continue; }
  docker volume create "${to}" >/dev/null
  docker run --rm -v "${from}:/from:ro" -v "${to}:/to" "${IMAGE}" sh -c 'cp -a /from/. /to/'
  ok "${from} → ${to}"
done

docker compose up -d postgres redis
for _ in $(seq 1 60); do docker exec "${PG}" pg_isready -U illwatch -d illwatch -q && break; sleep 1; done
APRES="$(count)"
echo "Après : ${APRES}"
[[ "${AVANT}" == "${APRES}" ]] || die "Comptages différents : les anciens volumes sont intacts, ne supprimez rien."
ok "Données déplacées. Le dossier peut maintenant être renommé."
echo "Anciens volumes (à supprimer plus tard) : docker volume rm ${OLD_PG_VOL} ${OLD_REDIS_VOL}"
