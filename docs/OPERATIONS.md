# ILLWATCH : Guide d'exploitation

Installer ILLWATCH prend une heure. Le faire tourner sereinement pendant des années demande
d'autres réflexes : surveiller, sauvegarder, mettre à jour, savoir quoi faire quand quelque chose
coince. Ce guide rassemble ces réflexes. Il s'appuie sur le jalon M7 de durcissement de
production (ADR-011, ADR-012, ADR-013) et a été éprouvé sur Kali Linux (rolling) et Debian 12.

## Sommaire

1. [Les composants](#1-les-composants)
2. [Les comptes de service](#2-les-comptes-de-service)
3. [Les sondes](#3-les-sondes)
4. [Les journaux](#4-les-journaux)
5. [Sessions et clés](#5-sessions-et-cles)
6. [Le journal d'audit](#6-le-journal-daudit)
7. [Sauvegarde et restauration](#7-sauvegarde-et-restauration)
8. [Déployer en production](#8-deployer-en-production)
9. [La préproduction locale](#9-la-preproduction-locale)
10. [Mettre à jour](#10-mettre-a-jour)
11. [L'entretien automatique](#11-lentretien-automatique)
12. [Les fonctions de la plateforme côté exploitation](#12-les-fonctions-de-la-plateforme-cote-exploitation)
13. [Observabilité](#13-observabilite)
14. [Cas particuliers](#14-cas-particuliers)

---

## 1. Les composants

Quatre pièces font tourner une instance :

| Composant | Rôle | Commande |
|---|---|---|
| API | REST `/api/v1`, sondes `/health` et `/ready` | `uvicorn illwatch.app.main:app` (image : `CMD` par défaut) |
| Worker | collecte des flux, synchro CVE, chasse planifiée | `illwatch feeds worker` |
| PostgreSQL 16 | données, chronologies, journal d'audit | service `postgres` |
| Redis 7 | verrous du worker, limitation des connexions | service `redis` |

Pour tout démarrer : `docker compose --profile full up -d`. En développement,
`docker compose up -d` ne lance que la base et Redis, avec des ports liés à `127.0.0.1`.

## 2. Les comptes de service

Depuis le lot 2 de M7, l'application ne se connecte plus avec les pleins pouvoirs. Chaque
composant a le compte dont il a besoin, et pas plus :

| Rôle | Variable | Droits |
|---|---|---|
| PostgreSQL propriétaire (`illwatch`) | `MIGRATION_DATABASE_URL` | structure : migrations uniquement |
| PostgreSQL applicatif (`illwatch_app`) | `DATABASE_URL`, `DATABASE_APP_ROLE` | données ; `SELECT, INSERT` seulement sur `incident_events` et `audit_events` |
| Redis | `REDIS_URL` (`redis://:MOT_DE_PASSE@…`), `REDIS_PASSWORD` (serveur Compose) | - |

Sur un volume Compose neuf, le rôle `illwatch_app` est créé au premier démarrage
(`scripts/db/init-app-role.sh`, mot de passe `POSTGRES_APP_PASSWORD`). Sur un volume existant,
il faut le créer une fois :

```bash
ILLWATCH_APP_DB_PASSWORD='…' illwatch db app-role illwatch_app --create   # avec MIGRATION_DATABASE_URL
illwatch db upgrade                                                   # réapplique les droits
```

**Comment reconnaître un volume antérieur à M7 ?** `illwatch db init` applique les migrations,
puis signale « Droits du rôle applicatif non posés : Le rôle illwatch_app n'existe pas ». Toute
commande échoue ensuite sur `password authentication failed for user "illwatch_app"` : c'est
trompeur, mais PostgreSQL répond ainsi même pour un rôle qui n'existe pas. Le mot de passe saisi
avec `--create` doit être le même que dans `DATABASE_URL` et `POSTGRES_APP_PASSWORD`.

Un mot de passe contenant `:`, `@`, `/` ou `%` doit être encodé dans l'URL : `%3A`, `%40`, `%2F`,
`%25`.

## 3. Les sondes

Deux sondes répondent à deux questions différentes : « le processus est-il vivant ? » et
« peut-il servir des requêtes ? ».

| Sonde | Usage | Réponse |
|---|---|---|
| `GET /health` | vivacité (HEALTHCHECK Docker) | toujours 200 ; `database: unreachable` si la base tombe |
| `GET /ready` | disponibilité (répartiteur, déploiement) | 200 si base joignable **et** schéma à la head Alembic ; 503 sinon |

Après un déploiement, un `/ready` en 503 avec `"schema": "fail"` signifie presque toujours une
migration oubliée : `illwatch db upgrade`.

## 4. Les journaux

Chaque évènement produit une ligne JSON sur la sortie d'erreur, que lisent sans effort `jq`,
journald, Loki ou Elastic :

| Journal | Contenu |
|---|---|
| `illwatch.http` | `http.request` : méthode, chemin, statut, durée, client, `request_id` |
| `illwatch.audit` | `audit` : action, issue, acteur, cible, IP, `request_id` |
| `illwatch.security` | blocages de connexion, repli du limiteur en mémoire |
| `illwatch.collector`, `illwatch.cve`, `illwatch.hunting` | collecte, synchro, chasse |

Le `request_id` (en-tête `X-Request-ID`) est votre fil d'Ariane : il relie la réponse reçue par
un client, sa ligne d'accès et sa ligne d'audit. Certaines choses ne sont en revanche **jamais**
journalisées : en-têtes, corps de requête, mots de passe, jetons, clés d'API.

Par exemple, pour voir toutes les actions auditées qui n'ont pas réussi :

```bash
docker compose logs api | jq -c 'select(.logger=="illwatch.audit" and .outcome!="SUCCESS")'
```

## 5. Sessions et clés

Les situations où il faut agir vite sur un compte, et la commande qui va avec :

| Besoin | Commande |
|---|---|
| Couper l'accès d'un compte tout de suite | `illwatch users disable alice` (statut relu à chaque requête, sessions révoquées) |
| Vol de session suspecté | `illwatch users revoke-sessions alice` |
| Réactiver | `illwatch users enable alice` |
| Mot de passe oublié ou compromis | `illwatch users set-password alice` (saisie masquée, 12 caractères au moins, sessions révoquées, `user.password_reset` au journal d'audit) |
| Changer la clé de signature sans déconnecter personne | `SECRET_KEY_PREVIOUS=<ancienne>`, `SECRET_KEY=$(openssl rand -hex 32)`, redémarrer l'API ; retirer `SECRET_KEY_PREVIOUS` 15 min plus tard |

Côté client, le cycle est le suivant : `POST /api/v1/auth/token` renvoie un `access_token`
(15 min) et un `refresh_token` (7 j) ; `POST /api/v1/auth/refresh` échange ce dernier contre un
nouveau couple ; `POST /api/v1/auth/logout` révoque la session. Si un `refresh_token` déjà
utilisé se présente à nouveau, c'est le signe d'un vol : toute la session est révoquée, et
l'audit le note (`auth.refresh` DENIED, `reuse_detected`).

## 6. Le journal d'audit

```bash
illwatch audit list                                  # 30 dernières actions
illwatch audit list --action auth. --outcome FAILURE --since 24
curl -H "Authorization: Bearer $JETON" "http://localhost:8000/api/v1/audit?action=data.export"
```

Le journal est en ajout seul : la base elle-même refuse `UPDATE`, `DELETE` et `TRUNCATE`. Trois
motifs méritent qu'on s'y arrête : des rafales d'`auth.login` FAILURE (tentative de force
brute), des `authz.denied` (un compte qui sonde ses droits), des `data.export` inhabituels (une
possible exfiltration).

## 7. Sauvegarde et restauration

```bash
scripts/backup.sh                       # ./backups, 14 conservées, vérifiées, SHA-256
KEEP=30 scripts/backup.sh /srv/illwatch-backups
```

Planifiez-la chaque jour, dans la crontab de l'utilisateur qui lance Compose :

```cron
17 2 * * * cd /opt/cyberillsec-illwatch && scripts/backup.sh /srv/illwatch-backups >> /var/log/illwatch-backup.log 2>&1
```

La restauration remplace la base : arrêtez d'abord l'API et le worker.

```bash
docker compose --profile full stop api worker
scripts/restore.sh /srv/illwatch-backups/illwatch-20261003T021700Z.dump
docker compose --profile full start api worker && curl -fsS localhost:8000/ready
```

Une sauvegarde qu'on n'a jamais restaurée n'est qu'un espoir. Testez la restauration une fois
par mois sur une base jetable (`PGURL=postgresql://…/illwatch_restore scripts/restore.sh …`).

## 8. Déployer en production

### 8.1 Avec Docker Compose et Caddy

Il vous faut Docker Compose **v2.24 ou plus** (`docker compose version`), un nom DNS public qui
pointe vers l'hôte, et les ports 80 et 443 ouverts pour Let's Encrypt. Pour un simple essai,
`ILLWATCH_DOMAIN=localhost` utilise l'autorité interne de Caddy.

Le `.env` de production refuse toute valeur de développement. Générez de vrais secrets :

```bash
SECRET_KEY=$(openssl rand -hex 32)
POSTGRES_PASSWORD=$(openssl rand -hex 24)        # propriétaire des tables (migrations)
POSTGRES_APP_PASSWORD=$(openssl rand -hex 24)    # rôle applicatif
REDIS_PASSWORD=$(openssl rand -hex 24)
ILLWATCH_DOMAIN=illwatch.exemple.eu
```

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile full up -d --build
docker compose -f docker-compose.yml -f docker-compose.prod.yml ps   # migrate : Exited (0)
curl -fsS https://illwatch.exemple.eu/ready
```

Voici ce que fait la surcouche de production : le conteneur `migrate` applique les migrations
avec le compte propriétaire, puis s'arrête ; l'API et le worker démarrent ensuite avec le rôle
applicatif, sans jamais connaître le mot de passe du propriétaire ; seul Caddy publie des ports ;
uvicorn n'accepte `X-Forwarded-For` que de Caddy (`172.30.0.10`). Vérifié dans le bac à sable :
TLS 1.3, HTTP/2, et un `X-Forwarded-For` usurpé par le client est ignoré (l'audit enregistre
l'adresse réelle).

### 8.2 Depuis l'image publiée

Chaque tag `vX.Y.Z` publie `ghcr.io/godwillfoka/cyberillsec-illwatch:X.Y.Z` (et `:latest`), et
chaque fusion sur `main` publie `:edge`. Le serveur n'a alors besoin ni du code ni d'une
construction locale : les deux fichiers Compose, le `Caddyfile` et le `.env` suffisent.

```bash
export ILLWATCH_IMAGE=ghcr.io/godwillfoka/cyberillsec-illwatch:latest
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile full pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile full up -d --no-build
```

Pour mettre à jour : changez la version dans `ILLWATCH_IMAGE`, faites un `pull`, puis
`up -d --no-build`. Le conteneur `migrate` applique les nouvelles migrations avant que l'API
redémarre.

### 8.3 Derrière un proxy existant

Si vous avez déjà Traefik, nginx ou un autre Caddy :

- servez l'API en HTTPS uniquement ; `ENVIRONMENT=production` active HSTS et masque `/docs` ;
- déclarez l'adresse du proxy : `FORWARDED_ALLOW_IPS=<IP ou réseau du proxy>`. Sans cela, toutes
  les requêtes sembleraient venir du proxy : la limitation par IP bloquerait tout le monde après
  20 échecs cumulés, et l'audit perdrait l'adresse réelle ;
- ne publiez jamais les ports PostgreSQL (5433) et Redis (6379) : ils restent liés à
  `127.0.0.1`.

### 8.4 Un VPS européen, pas à pas (clôture de M7)

1. **Le serveur** : un VPS hébergé dans l'Union européenne (Hetzner, OVHcloud, Scaleway…),
   sous Debian 12/13 ou Ubuntu 24.04, avec **2 vCPU, 4 Go de RAM et 40 Go** au moins (la base
   réelle dépasse 500 000 IOC). Accès SSH par clé uniquement.
2. **Le nom de domaine** : chez votre registraire, un enregistrement **A** (et **AAAA** si le VPS
   a une IPv6) `illwatch.votre-domaine.eu` vers l'adresse du VPS. Attendez la propagation
   (`dig +short illwatch.votre-domaine.eu`).
3. **L'installation**, sur le VPS :

   ```bash
   curl -fsSLO https://raw.githubusercontent.com/GodwillFoka/cyberillsec-illwatch/main/scripts/deploy-vps.sh
   sudo bash deploy-vps.sh install illwatch.votre-domaine.eu vous@exemple.eu
   ```

   Le script installe Docker et le pare-feu (22/80/443), place le code dans `/opt/illwatch`,
   génère les secrets (`.env`, 600), obtient le certificat Let's Encrypt, crée le compte `admin`,
   planifie la sauvegarde quotidienne, puis contrôle le tout. Le mot de passe d'`admin` ne
   s'affiche **qu'une seule fois** : rangez-le tout de suite dans votre gestionnaire de mots de
   passe.
4. **Le contrôle** : `sudo bash /opt/illwatch/scripts/deploy-vps.sh check` vérifie le DNS, le
   certificat, la redirection, le refus de TLS 1.0/1.1, les en-têtes, `/ready` et la fermeture
   de l'API.
5. **La preuve de clôture** : inscrivez le domaine dans `deploy/vps-domaine.txt` (une ligne) et
   poussez sur `main`. Le workflow « Clôture M7 » mesure alors la note TLS (testssl.sh, grille
   SSL Labs : **A attendu**) et les en-têtes, puis recommence chaque lundi.
6. **Les mises à jour** : `sudo bash /opt/illwatch/scripts/deploy-vps.sh update` enchaîne
   sauvegarde, code, image, migrations et contrôles.

## 9. La préproduction locale

Avant de toucher à un serveur, répétez sur votre poste. La pile de **production** complète (image
finale, migrations éphémères, rôle applicatif, Redis protégé, Caddy en HTTPS) tourne à côté de
la pile de développement, sans la toucher :

```bash
./scripts/preprod-local.sh up      # construit, démarre, crée le compte admin (mot de passe affiché)
./scripts/preprod-local.sh check   # HTTPS, en-têtes, API, temps réel via Caddy, droits, worker,
                                   # sauvegarde puis restauration dans une base jetable
./scripts/preprod-local.sh demo    # données FICTIVES (sinon : laisser le worker collecter)
./scripts/preprod-local.sh down    # arrêt, données conservées ; `purge` pour tout supprimer
```

Rendez-vous sur **https://illwatch.localhost:8443** (certificat de l'autorité interne de Caddy, à
accepter dans le navigateur). Le projet Compose `illwatch-preprod` a ses propres conteneurs et
volumes. Une précaution : son réseau reprend le sous-réseau fixe de la production
(172.30.0.0/24), donc ne la lancez pas en même temps qu'une pile de production locale. Caddy
n'écoute que sur 127.0.0.1 (8443, 8080).

Deux usages possibles, à ne jamais mélanger : la **collecte réelle** (`up`, le worker collecte
les sources) ou la **démonstration** (`demo` sur une base vide : données fictives, worker
arrêté). Pour revenir à la collecte réelle après une démonstration, `purge` puis `up`. En CI,
`PREPROD_MODE=demo` s'applique dès le démarrage. Les secrets sont générés dans `.env.preprod`
(600, ignoré par Git). Le même scénario tourne en CI à chaque modification (workflow
« Préproduction »), avec des captures de chaque écran publiées sur la branche `captures`.

Le VPS reprend exactement cette pile, avec un vrai `ILLWATCH_DOMAIN` : seuls changent le nom de
domaine, le certificat (Let's Encrypt) et l'ouverture des ports 80 et 443.

## 10. Mettre à jour

```bash
git pull --ff-only
pip install -c constraints.txt -e ".[dev]"     # ou : docker compose build
scripts/backup.sh                              # avant toute migration
illwatch db upgrade && curl -fsS localhost:8000/ready
```

Utilisez toujours `illwatch db upgrade`, jamais `alembic upgrade head` seul. Seule la commande
ILLWATCH donne au rôle applicatif ses droits sur les nouvelles tables ; sans eux, l'API et le
worker tombent sur `permission denied for table …`. Nous l'avons appris à nos dépens lors de
l'incident du 08/10. Si cela vous arrive, le rattrapage est simple :
`illwatch db app-role illwatch_app`.

Pour ajouter une dépendance, modifiez `pyproject.toml`, puis régénérez les contraintes :

```bash
uv pip compile pyproject.toml --extra dev --universal --python-version 3.12 \
  -o constraints.txt --no-header
```

Après une mise à jour qui change la règle de priorité des CVE (plancher KEV, ADR-014),
reclassez toutes les CVE :

```bash
illwatch cves rescore     # reclasse toutes les CVE, sans alerte ; motifs historisés
```

## 11. L'entretien automatique

Une fois par jour, le worker fait le ménage sans qu'on le lui demande : il purge les jetons de
rafraîchissement expirés ou révoqués depuis plus de 30 jours, ainsi que le journal des collectes
au-delà de 90 jours (`worker.housekeeping`, champs `purged` et `runs_purged`). Il contrôle aussi
la fraîcheur d'EPSS (`cve.epss_stale` au-delà de 48 h). `illwatch status` affiche le même
avertissement, et il compte : sans EPSS récent, aucune CVE ne peut atteindre P0.

## 12. Les fonctions de la plateforme côté exploitation

### 12.1 Interface web

L'image Docker embarque l'interface compilée (`/app/web`), servie à la racine du site
(`https://hote/`), tandis que l'API reste sous `/api/v1`. Hors Docker, `frontend/dist/` est
servi s'il existe : **`./scripts/build-web.sh`** le construit (schéma OpenAPI, `npm ci`, types
générés, construction), puis il faut redémarrer uvicorn. Attention à un piège : après un
`git pull` qui touche l'API, `npm run build` seul échoue (`TS2339 … does not exist`), parce que
les types viennent de l'ancien schéma. `WEB_DIR` permet de désigner un autre dossier. Sans
interface compilée, seule l'API répond. Pour le développement, voir `frontend/README.md`.

### 12.2 Enrichissement des adresses IP (ADR-019)

La fiche d'une IP affiche son pays et son système autonome, lus dans la base **DB-IP Lite**
importée sur votre machine : consulter une adresse ne déclenche aucune requête sortante.

```bash
illwatch enrich update      # télécharge et importe la base du mois (pays + AS, ≈ 11 Mo)
illwatch enrich status      # bases importées, nombre de plages, date d'import
illwatch enrich ip 8.8.8.8  # vérification : pays et opérateur d'une adresse
```

Une mise à jour par mois suffit (DB-IP publie en début de mois). Après le premier import manuel,
le worker prend le relais : il retélécharge toute base de plus de 32 jours
(`ENRICHMENT_AUTO_UPDATE`, activé par défaut ; mettez `false` pour planifier vous-même
`illwatch enrich update`). Sur un poste sans Internet, téléchargez
`dbip-country-lite-AAAA-MM.csv.gz` et `dbip-asn-lite-AAAA-MM.csv.gz` sur
https://db-ip.com/db/lite.php, puis lancez `illwatch enrich import FICHIER --dataset country|asn`.
Un fichier refusé (vide, mauvais format, plus de 1 % de lignes invalides) laisse l'ancienne base
en place. Chaque import est journalisé (`enrichment.import`). La licence CC BY 4.0 impose
l'attribution « IP Geolocation by DB-IP », affichée avec le résultat.

### 12.3 Inventaire et corrélation (M8, ADR-020)

La corrélation relie le renseignement à **vos** actifs ; tant que l'inventaire est vide, elle
n'a rien à dire.

```bash
illwatch assets add "Pare-feu siège" --product FortiOS --vendor Fortinet \
    --criticality CRITICAL --address 198.51.100.10 --domain vpn.example.com
illwatch assets import inventaire.csv   # en-tête : nom;produit;editeur;version;criticite;adresses;domaines
illwatch assets list
illwatch correlate run                  # une passe maintenant (le worker : toutes les heures)
illwatch correlate list                 # évènements ouverts, les plus graves d'abord
illwatch correlate evaluate             # mesure sur le jeu figé (aucune écriture en base)
illwatch cves refresh-affected          # relit les plages vulnérables NVD (ADR-021) ; 6 s/CVE sans clé NVD
```

- **Produit** : écrivez-le tel qu'il apparaît dans les avis de sécurité (« FortiOS »,
  « Exchange Server », « Confluence ») ; il est cherché en mot entier dans les CVE. Trop court
  ou trop générique (« Windows »), il ramène du bruit : précisez (« Windows Server 2019 »).
- **Adresses et domaines** : seulement ce qui est exposé sur Internet ; un domaine couvre ses
  sous-domaines.
- **Réglages** (`.env`) : `CORRELATION_INTERVAL_SECONDS` (3600 ; 0 désactive),
  `CORRELATION_MIN_CONFIDENCE` (40 = « moyenne »), `ENRICHMENT_AUTO_UPDATE` (true).
- **Écrans** : **Inventaire** (déclarer, modifier ; suppression réservée à l'administrateur) et
  **Corrélations** (acquitter, ouvrir l'incident qui reprend la CVE ou l'IOC).

La méthode la plus simple reste le modèle Excel, décrite dans le
[Guide d'installation, section 5](GUIDE_INSTALLATION.md#5-declarer-votre-inventaire-methode-excel).

### 12.4 Opérations SOC (M9, ADR-022)

```bash
illwatch incidents escalate <ID> --reason "IOC confirmé, investigation L2"   # L1 → L2 → L3
illwatch soc metrics --days 30          # MTTA, MTTR, délais cibles, dépassements, niveaux
illwatch soc exclude 203.0.113.7 --reason "Résolveur public de l'entreprise" [--days 90]
illwatch soc exclusions                 # liste d'exclusion en vigueur
```

- **Faux positif** : il se déclare depuis la fiche d'un IOC, la page d'un incident (IOC associé)
  ou un évènement corrélé. L'IOC exclu reste en base mais n'est plus actif (ni compté, ni
  chassé, ni corrélé) ; seul un administrateur peut retirer une exclusion (fiche de l'IOC).
- **Chasse depuis l'incident** : le bouton « Chasser depuis l'incident » rattache la session à
  l'incident et la résume dans sa chronologie.
- **Délais cibles** (prise en charge / résolution) : critique 1 h / 24 h, élevée 4 h / 72 h,
  moyenne 24 h / 7 j, faible 72 h / 30 j. Ils se suivent dans l'écran **Pilotage** (7 ou 30
  jours).

### 12.5 MITRE ATT&CK (M10, ADR-023)

```bash
illwatch attack import                  # référentiel Enterprise publié par MITRE (~40 Mo)
illwatch attack import --file enterprise-attack.json   # hors ligne
illwatch attack status
illwatch attack show T1190              # une technique et les groupes ou logiciels qui l'emploient
```

Réimportez à chaque nouvelle version d'ATT&CK (deux par an). Les détections affichent alors leur
technique et, quand la source le nomme, l'acteur cité. ATT&CK® © The MITRE Corporation.

### 12.6 Campagnes (M10, ADR-024)

```bash
illwatch campaigns create "Distribution QakBot" --actor S0650
illwatch campaigns attach "Distribution QakBot" --contains "Qakbot"   # IOC décrits par…
illwatch campaigns list
```

### 12.7 Partage STIX 2.1 et TAXII 2.1 (M10, ADR-025)

```bash
illwatch users create --username siem-partenaire --role viewer --email … --password …
illwatch stix export -o illwatch-stix.json             # bundle ponctuel
illwatch taxii discover https://<domaine>/taxii2/      # vérification avec notre propre client
```

Côté consommateur (OpenCTI, MISP, `taxii2-client`) : découverte `https://<domaine>/taxii2/`,
API root `…/taxii2/illwatch/`, authentification **Basic** avec le compte LECTEUR dédié. Prévoyez
un compte par consommateur : vous pourrez ainsi en couper un sans toucher aux autres. Les IOC
exclus (faux positifs) ne sont jamais partagés, et les échecs d'authentification apparaissent
dans le journal (`taxii.auth`).

## 13. Observabilité

```bash
curl -s http://127.0.0.1:8000/metrics | grep '^illwatch_'      # sur le poste ou le VPS
./scripts/preprod-local.sh observability                       # Prometheus + Grafana locaux
sudo ./scripts/restore-test.sh /srv/illwatch-backups           # test de restauration à la main
```

Sur le VPS, Prometheus (9090) et Grafana (3000) n'écoutent qu'en local : passez par un tunnel SSH
(voir [Environnements](ENVIRONNEMENTS.md)). Deux tableaux vous attendent : « ILLWATCH : Service »
et « ILLWATCH : Collecte et SOC ». Pendant les 7 jours de staging, gardez un œil sur deux
alertes : `IllwatchFeedStale` (une source sans succès depuis 3 intervalles) et
`IllwatchNoCollection` (le worker est arrêté).

### Statut du pipeline GitLab depuis GitHub

Le workflow GitHub « GitLab » (`.github/workflows/gitlab-statut.yml`) lit toutes les heures, et
à chaque push sur `main`, le dernier pipeline GitLab de `main`. Il le publie dans le check
« Statut GitLab » : l'état de chaque travail et, en annotations, la fin du journal des travaux
en échec.

Si le projet GitLab est privé, créez un jeton personnel GitLab (User settings → Access tokens)
avec la **seule portée `read_api`** et une date d'expiration, puis enregistrez-le dans GitHub →
Settings → Secrets and variables → Actions → *New repository secret*, sous le nom
`GITLAB_TOKEN`. Ce jeton ne doit transiter nulle part ailleurs : ni conversation, ni commit, ni
`.env`.

## 14. Cas particuliers

### 14.1 Vulnérabilités sans accès à l'API NVD

Réseau filtré ou déploiement isolé ? Importez les flux annuels NVD 2.0 (miroir
`fkie-cad/nvd-json-data-feeds`, ou pages de l'API sauvegardées) :

```bash
illwatch cves sync --only kev                             # catalogue KEV (ou KEV_CATALOG_URL miroir)
illwatch cves import CVE-20*.json.xz --only-known         # complète le CVSS des CVE suivies
```

La lecture se fait en flux : environ 220 Mo de mémoire pour les 24 flux annuels du catalogue
KEV (59 s). Gardez en tête qu'**aucune CVE n'atteint P0 sans EPSS** (le score plafonne alors à
75) : EPSS reste à synchroniser.

### 14.2 Fichier de configuration

ILLWATCH lit `.env` dans le répertoire courant. `ILLWATCH_ENV_FILE=/etc/illwatch/env` désigne un
autre fichier ; `ILLWATCH_ENV_FILE=` (vide) n'en lit aucun, et seules les variables
d'environnement comptent. Une variable vide (`DOCS_ENABLED=`) est traitée comme « non définie »
et prend sa valeur par défaut.

La suite de tests et `scripts/ci-local.sh` ne lisent jamais `.env`, et c'est volontaire : celui
d'un poste de développement pointe `MIGRATION_DATABASE_URL` vers la base de travail, et les tests
de migration (montée, descente) s'y seraient exécutés. Une `MIGRATION_DATABASE_URL` exportée dans
le shell doit viser une base dont le nom finit par `_test`, faute de quoi la suite refuse de
démarrer.

### 14.3 Collecte OTX : reprise et remise à zéro

Une collecte OTX limitée par `OTX_MAX_PAGES` ou interrompue par une erreur réseau garde les pages
lues mais n'avance pas son curseur : la collecte suivante reprend à la première page non lue.
Pour rattraper un gros historique, relancez `illwatch feeds fetch "<nom du flux>"` jusqu'à ce que
l'avertissement disparaisse. Pour tout relire depuis le début :

```bash
docker compose exec -T postgres psql -U illwatch -d illwatch \
  -c "DELETE FROM collector_state WHERE name LIKE 'otx:%';" \
  -c "UPDATE threat_feeds SET last_successful_run = NULL WHERE feed_type = 'OTX';"
```

### 14.4 Analyse d'image : le risque résiduel accepté

L'analyse GitLab Container Scanning du 07/10/2026 (`python:3.12-slim`, Debian 13.7, commit
`ad69dc6`) a relevé **0 Critical**, 52 High, 81 Medium, 105 Low et 2 Unknown, toutes dans des
paquets système Debian, **aucune avec un correctif publié**, et aucune dans une dépendance
Python.

| Famille (CVE distinctes) | Décision | Justification |
|---|---|---|
| curl, libcurl (4) | **retirées** : curl supprimé de l'image | ne servait qu'au contrôle de santé, désormais en Python |
| util-linux : mount, login, libblkid… (4) | acceptées | socle Debian ; outils jamais invoqués par ILLWATCH |
| ncurses, libsystemd/libudev, libacl, perl-base (4) | acceptées | socle Debian, non exposés au réseau |

Après le retrait de curl (pipeline `56ab581`) : 0 Critical, 44 High, 58 Medium, 61 Low,
2 Unknown, soit 165 au total contre 240. L'analyse de code SAST (Semgrep) n'a relevé aucun
constat.

Les mesures compensatoires : processus non privilégié (`USER illwatch`, UID 10001), aucun port
exposé hors Caddy en production, image reconstruite à chaque push sur `main` (base
`python:3.12-slim` à jour). La décision est revue à chaque analyse : une vulnérabilité
**Critical** ou un correctif Debian publié impose une reconstruction immédiate.

### 14.5 Renommage de SENTRY en ILLWATCH (octobre 2026)

La coupure est nette : seules les variables `ILLWATCH_*` sont lues, la commande `sentry` a
disparu, et la base s'appelle `illwatch`. Sur un poste qui faisait tourner SENTRY :

```bash
pkill -f "uvicorn sentry" ; pkill -f "sentry feeds"     # API et collectes arrêtées
git remote set-url origin https://github.com/GodwillFoka/cyberillsec-illwatch.git
git pull
source .venv/bin/activate
./scripts/migrer-vers-illwatch.sh
```

Le script prend soin de vos données : il sauvegarde l'ancienne base
(`~/illwatch-migration/sentry.dump`), réécrit le `.env` (en gardant une copie de l'ancien à côté),
démarre `illwatch-postgres` sur un volume neuf, restaure, réapplique les droits de
`illwatch_app` et **compare les comptages table par table**. L'ancien volume n'est pas
supprimé : tant que l'activité n'a pas repris sous ILLWATCH,
`./scripts/migrer-vers-illwatch.sh --retour` remet SENTRY en service.

Les fonctions de base `sentry_refuse_rewrite` et `sentry_refuse_timeline_rewrite` gardent leur
ancien nom : elles sont créées par des migrations déjà appliquées, et on ne réécrit pas
l'histoire.

**Le nom du dossier.** Depuis le 08/10, `docker-compose.yml` fixe le nom du projet (`illwatch`)
et des volumes (`illwatch_pgdata`, `illwatch_redisdata`) : le dossier du dépôt peut donc porter
n'importe quel nom. Un poste migré avant cette date copie ses données une fois avec
`./scripts/deplacer-volumes-illwatch.sh` (comptages comparés, anciens volumes conservés), puis
renomme le dossier et recrée son venv, qui contient des chemins absolus.

### 14.6 Spécificités de Kali Linux

- Le paquet système `python3-sqlalchemy` peut être plus ancien que celui de la CI : travaillez
  toujours dans le `.venv` du projet, installé avec `-c constraints.txt`.
- Docker : `sudo systemctl enable --now docker` et `sudo usermod -aG docker $USER`, puis
  reconnectez-vous.
- Kali active parfois des services réseau d'audit : vérifiez qu'aucun autre service n'écoute sur
  5433, 6379 ou 8000 (`ss -ltnp`).
