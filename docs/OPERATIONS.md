# SENTRY — Guide d'exploitation

**Public :** la personne qui installe, surveille, sauvegarde et met à jour une instance.
**Référence :** M7 Production Hardening (ADR-011, ADR-012, ADR-013). Testé sur Kali Linux (rolling) et Debian 12.

## 1. Composants

| Composant | Rôle | Commande |
|---|---|---|
| API | REST `/api/v1`, sondes `/health` et `/ready` | `uvicorn sentry.app.main:app` (image : `CMD` par défaut) |
| Worker | collecte des flux, synchro CVE, chasse planifiée | `sentry feeds worker` |
| PostgreSQL 16 | données, chronologies, journal d'audit | service `postgres` |
| Redis 7 | verrous du worker, limitation des connexions | service `redis` |

Démarrage complet : `docker compose --profile full up -d`. Développement : `docker compose up -d`
(base et Redis seuls, ports liés à `127.0.0.1`).

## 1 bis. Comptes de service (M7 lot 2)

| Rôle | Variable | Droits |
|---|---|---|
| PostgreSQL propriétaire (`sentry`) | `MIGRATION_DATABASE_URL` | structure : migrations uniquement |
| PostgreSQL applicatif (`sentry_app`) | `DATABASE_URL`, `DATABASE_APP_ROLE` | données ; `SELECT, INSERT` seulement sur `incident_events` et `audit_events` |
| Redis | `REDIS_URL` (`redis://:MOT_DE_PASSE@…`), `REDIS_PASSWORD` (serveur Compose) | — |

Volume Compose neuf : le rôle `sentry_app` est créé au premier démarrage
(`scripts/db/init-app-role.sh`, mot de passe `POSTGRES_APP_PASSWORD`). Volume existant, une fois :

```bash
SENTRY_APP_DB_PASSWORD='…' sentry db app-role sentry_app --create   # avec MIGRATION_DATABASE_URL
sentry db upgrade                                                   # réapplique les droits
```

Symptôme d'un volume antérieur à M7 : `sentry db init` applique les migrations puis signale
« Droits du rôle applicatif non posés : Le rôle sentry_app n'existe pas », et toute commande
échoue ensuite sur `password authentication failed for user "sentry_app"` (PostgreSQL répond
ainsi aussi pour un rôle inexistant). Le mot de passe saisi avec `--create` doit être celui de
`DATABASE_URL` et de `POSTGRES_APP_PASSWORD`.

Un mot de passe contenant `:`, `@`, `/` ou `%` s'encode dans l'URL : `%3A`, `%40`, `%2F`, `%25`.

## 2. Sondes

| Sonde | Usage | Réponse |
|---|---|---|
| `GET /health` | vivacité (HEALTHCHECK Docker) | toujours 200 ; `database: unreachable` si la base tombe |
| `GET /ready` | disponibilité (répartiteur, déploiement) | 200 si base joignable **et** schéma à la head Alembic ; 503 sinon |

`/ready` en 503 avec `"schema": "fail"` après un déploiement = migration oubliée :
`sentry db upgrade`.

## 3. Journaux

Une ligne JSON par évènement sur la sortie d'erreur, lisible par `jq`, journald, Loki, Elastic :

| Journal | Contenu |
|---|---|
| `sentry.http` | `http.request` : méthode, chemin, statut, durée, client, `request_id` |
| `sentry.audit` | `audit` : action, issue, acteur, cible, IP, `request_id` |
| `sentry.security` | blocages de connexion, repli du limiteur en mémoire |
| `sentry.collector`, `sentry.cve`, `sentry.hunting` | collecte, synchro, chasse |

Le `request_id` (en-tête `X-Request-ID`) relie la réponse reçue par un client, sa ligne d'accès
et sa ligne d'audit. Jamais journalisés : en-têtes, corps, mots de passe, jetons, clés d'API.

```bash
docker compose logs api | jq -c 'select(.logger=="sentry.audit" and .outcome!="SUCCESS")'
```

## 3 bis. Sessions et clés (M7 lot 2)

| Besoin | Commande |
|---|---|
| Couper l'accès d'un compte tout de suite | `sentry users disable alice` (statut relu à chaque requête, sessions révoquées) |
| Vol de session suspecté | `sentry users revoke-sessions alice` |
| Réactiver | `sentry users enable alice` |
| Mot de passe oublié ou compromis | `sentry users set-password alice` (saisie masquée, politique ≥ 12 caractères, sessions révoquées, `user.password_reset` au journal d'audit) |
| Changer la clé de signature sans déconnecter | `SECRET_KEY_PREVIOUS=<ancienne>`, `SECRET_KEY=$(openssl rand -hex 32)`, redémarrer l'API ; retirer `SECRET_KEY_PREVIOUS` 15 min plus tard |

Côté client : `POST /api/v1/auth/token` renvoie `access_token` (15 min) et `refresh_token`
(7 j) ; `POST /api/v1/auth/refresh` en échange un nouveau couple ; `POST /api/v1/auth/logout`
révoque la session. Un `refresh_token` déjà utilisé qui revient révoque toute la session et
apparaît dans l'audit (`auth.refresh` DENIED, `reuse_detected`).

## 3 ter. Vulnérabilités sans accès à l'API NVD

Réseau filtré ou déploiement isolé : importer les flux annuels NVD 2.0 (miroir
`fkie-cad/nvd-json-data-feeds`, ou pages de l'API sauvegardées) :

```bash
sentry cves sync --only kev                             # catalogue KEV (ou KEV_CATALOG_URL miroir)
sentry cves import CVE-20*.json.xz --only-known         # complète le CVSS des CVE suivies
```

Lecture en flux : ~220 Mo de mémoire pour les 24 flux annuels du catalogue KEV (59 s).
**Sans EPSS, aucune CVE n'atteint P0** (score plafonné à 75) : EPSS reste à synchroniser.

## 4. Journal d'audit

```bash
sentry audit list                                  # 30 dernières actions
sentry audit list --action auth. --outcome FAILURE --since 24
curl -H "Authorization: Bearer $JETON" "http://localhost:8000/api/v1/audit?action=data.export"
```

En ajout seul : `UPDATE`, `DELETE` et `TRUNCATE` sont refusés par la base. À surveiller :
rafales d'`auth.login` FAILURE (force brute), `authz.denied` (compte qui sonde ses droits),
`data.export` inhabituels (exfiltration).

## 5. Sauvegarde et restauration

```bash
scripts/backup.sh                       # ./backups, 14 conservées, vérifiées, SHA-256
KEEP=30 scripts/backup.sh /srv/sentry-backups
```

Planification quotidienne (crontab de l'utilisateur qui lance Compose) :

```cron
17 2 * * * cd /opt/cyberillsec-sentry && scripts/backup.sh /srv/sentry-backups >> /var/log/sentry-backup.log 2>&1
```

Restauration (remplace la base ; arrêter API et worker avant) :

```bash
docker compose --profile full stop api worker
scripts/restore.sh /srv/sentry-backups/sentry-20261003T021700Z.dump
docker compose --profile full start api worker && curl -fsS localhost:8000/ready
```

Une sauvegarde non restaurée n'est pas une sauvegarde : tester la restauration une fois par
mois sur une base jetable (`PGURL=postgresql://…/sentry_restore scripts/restore.sh …`).

## 6. Déploiement de production (TLS, M7 lot 3)

Prérequis : Docker Compose **v2.24 ou plus** (`docker compose version`), un nom DNS public
pointant sur l'hôte et les ports 80/443 ouverts (Let's Encrypt), ou `SENTRY_DOMAIN=localhost`
pour un essai avec l'autorité interne de Caddy.

`.env` de production (aucune valeur de développement n'est acceptée) :

```bash
SECRET_KEY=$(openssl rand -hex 32)
POSTGRES_PASSWORD=$(openssl rand -hex 24)        # propriétaire des tables (migrations)
POSTGRES_APP_PASSWORD=$(openssl rand -hex 24)    # rôle applicatif
REDIS_PASSWORD=$(openssl rand -hex 24)
SENTRY_DOMAIN=sentry.exemple.eu
```

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile full up -d --build
docker compose -f docker-compose.yml -f docker-compose.prod.yml ps   # migrate : Exited (0)
curl -fsS https://sentry.exemple.eu/ready
```

### Depuis l'image publiée (GitHub Container Registry)

Chaque tag `vX.Y.Z` publie `ghcr.io/godwillfoka/cyberillsec-sentry:X.Y.Z` (et `:latest`) ;
chaque fusion sur `main` publie `:edge`. Le serveur n'a alors besoin ni du code ni d'une
construction locale, seulement des deux fichiers Compose, du `Caddyfile` et du `.env` :

```bash
export SENTRY_IMAGE=ghcr.io/godwillfoka/cyberillsec-sentry:latest
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile full pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile full up -d --no-build
```

Mise à jour : changer la version de `SENTRY_IMAGE`, `pull`, puis `up -d --no-build` ; le
conteneur `migrate` applique les nouvelles migrations avant le redémarrage de l'API.

Ce que fait l'overlay : `migrate` applique les migrations avec le propriétaire puis s'arrête ;
l'API et le worker démarrent ensuite en rôle applicatif, sans le mot de passe du propriétaire ;
seul Caddy publie des ports ; uvicorn n'accepte `X-Forwarded-For` que de Caddy (`172.30.0.10`).
Vérifié dans le bac à sable : TLS 1.3, HTTP/2, `X-Forwarded-For` usurpé par le client ignoré
(l'audit enregistre l'adresse réelle).

Hors Compose (proxy existant) :

- Servir l'API en HTTPS uniquement (Caddy, Traefik ou nginx) ; `ENVIRONMENT=production` active
  HSTS et masque `/docs`.
- Déclarer l'adresse du proxy : `FORWARDED_ALLOW_IPS=<IP ou réseau du proxy>`. Sans cela, toutes
  les requêtes semblent venir du proxy : la limitation par IP bloquerait tout le monde après
  20 échecs cumulés, et l'audit perdrait l'adresse réelle.
- Ne jamais publier les ports PostgreSQL (5433) et Redis (6379) : ils sont liés à `127.0.0.1`.

## 6 bis. Entretien automatique

Le worker exécute une fois par jour : purge des jetons de rafraîchissement expirés ou révoqués
depuis plus de 30 jours (`worker.housekeeping`), contrôle de fraîcheur d'EPSS (`cve.epss_stale`
au-delà de 48 h). `sentry status` affiche le même avertissement : sans EPSS récent, aucune CVE
ne peut atteindre P0.

## 7. Mise à jour

```bash
git pull --ff-only
pip install -c constraints.txt -e ".[dev]"     # ou : docker compose build
scripts/backup.sh                              # avant toute migration
sentry db upgrade && curl -fsS localhost:8000/ready
```

Ajout d'une dépendance : modifier `pyproject.toml`, puis régénérer les contraintes :

```bash
uv pip compile pyproject.toml --extra dev --universal --python-version 3.12 \
  -o constraints.txt --no-header
```

## 7 bis. Fichier de configuration

SENTRY lit `.env` dans le répertoire courant. `SENTRY_ENV_FILE=/etc/sentry/env` désigne un
autre fichier ; `SENTRY_ENV_FILE=` (vide) n'en lit aucun : seules les variables
d'environnement comptent. Une variable vide (`DOCS_ENABLED=`) vaut « non définie » et prend
sa valeur par défaut.

La suite de tests et `scripts/ci-local.sh` ne lisent jamais `.env` : celui d'un poste de
développement définit `MIGRATION_DATABASE_URL` vers la base de travail, et les tests de
migration (montée, descente) y auraient été envoyés. Une `MIGRATION_DATABASE_URL` exportée
dans le shell doit viser une base dont le nom finit par `_test`, sinon la suite refuse de
démarrer.

## 7 ter. Collecte OTX : reprise et remise à zéro

Une collecte OTX limitée par `OTX_MAX_PAGES` ou interrompue par une erreur réseau garde les
pages lues et ne fait pas avancer son curseur : la collecte suivante reprend à la première
page non lue. Pour rattraper un gros historique, relancer `sentry feeds fetch "<nom du flux>"`
jusqu'à disparition de l'avertissement. Pour tout relire depuis le début :

```bash
docker compose exec -T postgres psql -U sentry -d sentry \
  -c "DELETE FROM collector_state WHERE name LIKE 'otx:%';" \
  -c "UPDATE threat_feeds SET last_successful_run = NULL WHERE feed_type = 'OTX';"
```

## 7 quater. Changement de règle de priorité (ADR-014)

Après une mise à jour qui modifie la règle de priorité des CVE (plancher KEV, ADR-014) :

```bash
sentry cves rescore     # reclasse toutes les CVE, sans alerte ; motifs historisés
```

## 8. Spécificités Kali Linux

- Le paquet système `python3-sqlalchemy` peut être plus ancien que celui de la CI : toujours
  travailler dans le `.venv` du projet, installé avec `-c constraints.txt`.
- Docker : `sudo systemctl enable --now docker` et `sudo usermod -aG docker $USER` (reconnexion).
- Kali active parfois des services réseau d'audit : vérifier qu'aucun autre service n'écoute
  sur 5433, 6379 ou 8000 (`ss -ltnp`).
