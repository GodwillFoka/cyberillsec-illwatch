#!/usr/bin/env bash
# ============================================================================
# ILL Watch — Déploiement sur un VPS (clôture de M7 : « … up sur un VPS UE, SSL Labs ≥ A »)
#
# Sur un serveur Debian 12/13 ou Ubuntu 24.04 neuf, en root (ou sudo), avec un nom DNS
# (enregistrement A, et AAAA si IPv6) qui pointe déjà sur ce serveur :
#
#   sudo ./scripts/deploy-vps.sh install illwatch.exemple.eu godwill@exemple.eu
#   sudo ./scripts/deploy-vps.sh check   illwatch.exemple.eu
#   sudo ./scripts/deploy-vps.sh update
#
# install : Docker (dépôt officiel), pare-feu (22, 80, 443), code dans /opt/illwatch, secrets
#           générés dans /opt/illwatch/.env (600), pile de production (Caddy + Let's Encrypt,
#           API, worker, PostgreSQL, Redis), compte administrateur, sauvegarde quotidienne.
# check   : DNS, HTTPS et certificat, redirection HTTP, TLS 1.0/1.1 refusés, en-têtes,
#           /ready, /docs masqué, API fermée sans jeton.
# update  : sauvegarde, nouvelle version du code, reconstruction, migrations, contrôle.
#
# Aucun secret n'est affiché, sauf le mot de passe administrateur, une seule fois.
# ============================================================================
set -euo pipefail

DIR=/opt/illwatch
REPO=https://github.com/GodwillFoka/cyberillsec-illwatch.git
export COMPOSE_FILE="docker-compose.yml:docker-compose.prod.yml"
export COMPOSE_PROFILES="full"
export COMPOSE_PROJECT_NAME="illwatch"
FAILED=0

ok() { printf '\033[32m✔\033[0m %s\n' "$*"; }
ko() { printf '\033[31m✘\033[0m %s\n' "$*" >&2; FAILED=$((FAILED + 1)); }
step() { printf '\n\033[1m▶ %s\033[0m\n' "$*"; }
die() { printf '\033[31m✘ %s\033[0m\n' "$*" >&2; exit 1; }

need_root() { [[ $EUID -eq 0 ]] || die "à lancer en root (sudo)."; }

install_docker() {
  if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
    ok "Docker déjà installé ($(docker --version | cut -d, -f1))"
    return
  fi
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID}" in debian | ubuntu) ;; *) die "système ${ID} non prévu (Debian ou Ubuntu)." ;; esac
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/${ID}/gpg" -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/${ID} ${VERSION_CODENAME} stable" >/etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
  ok "Docker installé ($(docker --version | cut -d, -f1))"
}

firewall() {
  apt-get install -y -qq ufw >/dev/null
  ufw allow OpenSSH >/dev/null
  ufw allow 80/tcp >/dev/null
  ufw allow 443/tcp >/dev/null
  ufw allow 443/udp >/dev/null # HTTP/3
  ufw --force enable >/dev/null
  ok "pare-feu : 22, 80, 443 ouverts ; le reste fermé"
}

secret() { openssl rand -hex "$1"; }

write_env() {
  local domain=$1
  if [[ -f "${DIR}/.env" ]]; then
    ok ".env existant conservé (secrets inchangés)"
  else
    umask 077
    cat >"${DIR}/.env" <<EOF
SECRET_KEY=$(secret 32)
POSTGRES_PASSWORD=$(secret 24)
POSTGRES_APP_PASSWORD=$(secret 24)
REDIS_PASSWORD=$(secret 24)
ILLWATCH_DOMAIN=${domain}
EOF
    chmod 600 "${DIR}/.env"
    ok "secrets générés dans ${DIR}/.env (600)"
  fi
}

dns_check() {
  local domain=$1 resolved public
  resolved=$(getent ahostsv4 "${domain}" | awk 'NR==1{print $1}')
  public=$(curl -fsS -4 --max-time 10 https://api.ipify.org || true)
  if [[ -z "${resolved}" ]]; then
    ko "DNS : ${domain} ne résout pas (enregistrement A à créer chez le registraire)"
  elif [[ -n "${public}" && "${resolved}" != "${public}" ]]; then
    ko "DNS : ${domain} → ${resolved}, mais ce serveur sort en ${public}"
  else
    ok "DNS : ${domain} → ${resolved}"
  fi
}

backups() {
  mkdir -p /srv/illwatch-backups
  cat >/etc/cron.d/illwatch-backup <<EOF
# Sauvegarde quotidienne de la base ILL Watch (14 jours conservés).
17 2 * * * root cd ${DIR} && ./scripts/backup.sh /srv/illwatch-backups >>/var/log/illwatch-backup.log 2>&1
EOF
  ok "sauvegarde quotidienne à 02 h 17 dans /srv/illwatch-backups"
}

cmd_install() {
  need_root
  local domain=${1:-} email=${2:-}
  [[ -n "${domain}" ]] || die "usage : $0 install <domaine> [e-mail du compte admin]"
  step "Système"
  install_docker
  firewall
  step "Code"
  apt-get install -y -qq git >/dev/null
  if [[ -d "${DIR}/.git" ]]; then git -C "${DIR}" pull --ff-only -q; else git clone -q "${REPO}" "${DIR}"; fi
  ok "code dans ${DIR} ($(git -C "${DIR}" log -1 --format=%h))"
  cd "${DIR}"
  write_env "${domain}"
  step "DNS"
  dns_check "${domain}"
  step "Démarrage (construction de l'image : quelques minutes)"
  docker compose up -d --build
  docker compose ps
  step "Compte administrateur"
  local password
  password=$(secret 12)
  if docker compose exec -T api illwatch users create --username admin --role admin \
    --email "${email:-admin@${domain}}" --password "${password}" >/dev/null 2>&1; then
    ok "compte « admin » créé — mot de passe (à ranger dans KeePassXC, affiché une seule fois) :"
    printf '    %s\n' "${password}"
  else
    ok "compte « admin » déjà présent (mot de passe inchangé)"
  fi
  docker compose exec -T api illwatch seed >/dev/null && ok "sources de référence déclarées"
  backups
  step "Contrôles"
  cmd_check "${domain}"
}

cmd_check() {
  local domain=${1:-}
  [[ -n "${domain}" ]] || domain=$(grep -E '^ILLWATCH_DOMAIN=' "${DIR}/.env" | cut -d= -f2)
  local base="https://${domain}"
  dns_check "${domain}"
  [[ "$(curl -s -o /dev/null -w '%{http_code}' "${base}/ready")" == 200 ]] \
    && ok "HTTPS ${base}/ready 200 (certificat valide)" || ko "HTTPS /ready (certificat ou service)"
  issuer=$(echo | openssl s_client -connect "${domain}:443" -servername "${domain}" 2>/dev/null \
    | openssl x509 -noout -issuer 2>/dev/null || true)
  [[ "${issuer}" == *"Let's Encrypt"* || "${issuer}" == *"ZeroSSL"* ]] \
    && ok "certificat public : ${issuer#issuer=}" || ko "certificat : ${issuer:-illisible}"
  redirect=$(curl -s -o /dev/null -w '%{http_code}' "http://${domain}/")
  [[ "${redirect}" == 308 || "${redirect}" == 301 ]] && ok "HTTP → HTTPS (${redirect})" || ko "pas de redirection HTTP (${redirect})"
  for proto in tls1 tls1_1; do
    if echo | openssl s_client -connect "${domain}:443" -servername "${domain}" "-${proto}" >/dev/null 2>&1; then
      ko "${proto} accepté (doit être refusé)"
    else
      ok "${proto} refusé"
    fi
  done
  echo | openssl s_client -connect "${domain}:443" -servername "${domain}" -tls1_3 >/dev/null 2>&1 \
    && ok "TLS 1.3 accepté" || ko "TLS 1.3 refusé"
  headers=$(curl -sS -D - -o /dev/null "${base}/")
  for header in strict-transport-security x-content-type-options content-security-policy referrer-policy; do
    grep -qi "^${header}:" <<<"${headers}" && ok "en-tête ${header}" || ko "en-tête ${header} absent"
  done
  grep -qi '^server:' <<<"${headers}" && ko "en-tête Server exposé" || ok "en-tête Server masqué"
  [[ "$(curl -s -o /dev/null -w '%{http_code}' "${base}/docs")" == 404 ]] && ok "/docs masqué" || ko "/docs exposé"
  [[ "$(curl -s -o /dev/null -w '%{http_code}' "${base}/api/v1/indicators")" == 401 ]] \
    && ok "API refusée sans jeton (401)" || ko "API accessible sans jeton"
  printf '\nNote SSL Labs : https://www.ssllabs.com/ssltest/analyze.html?d=%s (ou workflow « Clôture M7 »).\n' "${domain}"
  if ((FAILED)); then die "${FAILED} contrôle(s) en échec."; fi
  ok "tous les contrôles passent"
}

cmd_update() {
  need_root
  cd "${DIR}"
  step "Sauvegarde avant mise à jour"
  ./scripts/backup.sh /srv/illwatch-backups
  step "Code et image"
  git pull --ff-only -q
  docker compose up -d --build
  step "Contrôles"
  cmd_check ""
}

case "${1:-}" in
  install) shift; cmd_install "$@" ;;
  check) shift; cmd_check "$@" ;;
  update) cmd_update ;;
  *) sed -n '2,20p' "$0"; exit 2 ;;
esac
