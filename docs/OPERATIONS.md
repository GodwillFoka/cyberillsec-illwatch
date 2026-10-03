# SENTRY — Guide d'exploitation

**Public :** la personne qui installe, surveille, sauvegarde et met à jour une instance.
**Référence :** M7 Production Hardening (ADR-011). Testé sur Kali Linux (rolling) et Debian 12.

## 1. Composants

| Composant | Rôle | Commande |
|---|---|---|
| API | REST `/api/v1`, sondes `/health` et `/ready` | `uvicorn sentry.app.main:app` (image : `CMD` par défaut) |
| Worker | collecte des flux, synchro CVE, chasse planifiée | `sentry feeds worker` |
| PostgreSQL 16 | données, chronologies, journal d'audit | service `postgres` |
| Redis 7 | verrous du worker, limitation des connexions | service `redis` |

Démarrage complet : `docker compose --profile full up -d`. Développement : `docker compose up -d`
(base et Redis seuls, ports liés à `127.0.0.1`).

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

## 6. Exposition derrière un reverse proxy

- Servir l'API en HTTPS uniquement (Caddy, Traefik ou nginx) ; `ENVIRONMENT=production` active
  HSTS et masque `/docs`.
- Déclarer l'adresse du proxy : `FORWARDED_ALLOW_IPS=<IP ou réseau du proxy>`. Sans cela, toutes
  les requêtes semblent venir du proxy : la limitation par IP bloquerait tout le monde après
  20 échecs cumulés, et l'audit perdrait l'adresse réelle.
- Ne jamais publier les ports PostgreSQL (5433) et Redis (6379) : ils sont liés à `127.0.0.1`.

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

## 8. Spécificités Kali Linux

- Le paquet système `python3-sqlalchemy` peut être plus ancien que celui de la CI : toujours
  travailler dans le `.venv` du projet, installé avec `-c constraints.txt`.
- Docker : `sudo systemctl enable --now docker` et `sudo usermod -aG docker $USER` (reconnexion).
- Kali active parfois des services réseau d'audit : vérifier qu'aucun autre service n'écoute
  sur 5433, 6379 ou 8000 (`ss -ltnp`).
