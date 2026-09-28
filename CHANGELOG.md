# Changelog

Toutes les évolutions notables de SENTRY sont consignées ici.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et le versionnage
respecte [Semantic Versioning](https://semver.org/lang/fr/).

## [Non publié]

### Ajouté
- `sentry status` : avancement mesuré en base (schéma, santé des sources, IOC actifs/expirés
  par type, critères du jalon M2 cochés ou non).
- Pipeline : tests exécutés sous Python 3.12 et 3.14.
- **T2.3 — Collecteur de flux (UC-01)** : récupération HTTP sécurisée (revalidation de l'URL,
  résolution DNS avec refus de toute adresse interne, redirections revalidées une à une, taille
  plafonnée par `FEED_MAX_BYTES`), backoff exponentiel sur erreurs réseau et 5xx, report au cycle
  suivant sur HTTP 429. Analyseurs CSV (en-têtes commentés abuse.ch), JSON et STIX 2.1. Chaque
  flux est isolé : un échec passe le flux en `DEGRADED` sans bloquer les autres (RSK-02).
- **T2.7 — CLI `sentry feeds`** : `list`, `add`, `fetch <nom|id>`, `fetch-all [--force]`. Code de
  sortie non nul si une collecte échoue (planification cron / timer systemd).
- **T2.2 — CRUD des sources de flux (RF-04)** : `GET/POST /api/v1/feeds`,
  `GET/PATCH/DELETE /api/v1/feeds/{id}`. Lecture pour tous les rôles authentifiés, écriture
  réservée aux `ADMIN`. Liste paginée (`limit` ≤ 200, `offset`) et filtrable (`is_active`,
  `status`, `feed_type`), triée par nom.
- Service `sentry/modules/threat_feeds/service.py`, partagé par l'API et la future CLI (T2.7) :
  noms uniques sans tenir compte de la casse (409), URL de flux validée contre le SSRF (HTTPS
  uniquement, pas d'identifiants, pas d'IP interne ni de nom local, formes numériques ambiguës
  refusées), retour à `PENDING` quand l'URL ou le format change.

- **IOC (RF-07, RF-08, ADR-005)** : `POST /api/v1/indicators` (ingestion d'un lot de 1 000 IOC
  au plus, rôles `ADMIN` et `ANALYST`), `GET /api/v1/indicators` (filtres `type`, `severity`,
  `min_severity`, `feed_id`, `active`, `value`) et `GET /api/v1/indicators/{id}`. Déduplication
  par `INSERT … ON CONFLICT DO UPDATE` : `hit_count`, `first_seen`/`last_seen`, sévérité maximale
  et `expires_at` mis à jour selon l'ADR-005. RNF-PERF-02 vérifié (1 000 IOC < 5 s).
- Normalisation des IOC étendue : formes désamorcées (`hxxps://`, `[.]`), point final DNS,
  schéma et hôte d'URL en minuscules, port par défaut et fragment retirés, IP canonisées.
- Tests d'intégrité du schéma : contraintes CHECK, `expires_at`, `ON DELETE SET NULL`, et
  comparaison des CHECK entre modèle et base (non couverte par `alembic check`).

### Corrigé
- **SSRF** : la détection d'adresses internes reposait sur `is_private`, qui ignore
  100.64.0.0/10 (CGNAT, métadonnées Alibaba Cloud en 100.100.100.200) et les adresses IPv4
  embarquées dans de l'IPv6 (NAT64 `64:ff9b::/96`, 6to4). Seules les adresses publiques
  (`is_global`) sont désormais admises.
- Détail des erreurs de collecte (`last_error`) réservé aux ADMIN : il peut citer une adresse
  interne refusée.
- `fetch-all` validait tous les flux en une seule transaction : un arrêt en cours de cycle perdait
  tout. Validation après chaque flux.
- Erreurs de protocole HTTP (connexion coupée) désormais retentées ; contenu corrompu signalé
  proprement au lieu d'une « erreur inattendue ».
- Liste des rejets d'ingestion bornée à 100 exemples (compteur exact conservé) : mémoire bornée
  face à un flux corrompu.
- Lecture d'un flux ou d'un IOC : rechargement systématique depuis la base (plantage possible sur
  un objet modifié plus tôt dans la même session).
- **Flux URLhaus inutilisable** : abuse.ch exige désormais une clé (`Auth-Key`) dans l'URL de
  téléchargement ; l'ancienne URL semée par `sentry seed` échouait. La base stocke un gabarit
  (`…/exports/{ABUSECH_AUTH_KEY}/recent.csv`), la clé est lue dans `.env` au moment de la requête
  et masquée dans tous les messages d'erreur. `sentry seed` corrige l'ancienne URL.
- Échantillon Feodo aligné sur le format réel (en-tête CSV entre guillemets, non commenté).
- **Protection des données de travail** : la documentation faisait lancer `pytest` sur la base
  de travail, alors que les tests de migration en suppriment tout le schéma. La suite refuse
  désormais toute base PostgreSQL dont le nom ne finit pas par `_test`, et repart d'un schéma
  neuf à chaque session (une base de tests restée sur un ancien schéma faisait échouer la suite).
- **Pipeline GitLab** : il ne tournait que sur `main`, les tags et les merge requests ; un push
  de branche de fonctionnalité n'était jamais testé. Ajout des pipelines de branche (sans
  doublon avec les merge requests) et d'un job `migrations` (montée, `alembic check`, descente,
  remontée sur base vierge).
- Script `scripts/ci-local.sh` : réplique locale du pipeline, à lancer avant chaque push.
- Migration `a4973a3782e3` : import inutilisé retiré (aucun effet sur le schéma).
- **Modèle désynchronisé de la migration `a4973a3782e3`** : `Indicator.expires_at` et les quatre
  contraintes CHECK n'étaient déclarés que dans la migration. `alembic check` signalait
  « removed column 'indicators.expires_at' » et un test de M1 échouait sur `main`.
- Couverture de tests sous-estimée : `coverage` ne suivait pas les greenlets de SQLAlchemy async
  (`concurrency = ["greenlet", "thread"]`).

## [0.1.0] — 2026-09-24

Jalon M1 : squelette opérationnel validé (clôture de la phase 1 Foundation).

### Ajouté
- Squelette applicatif complet conforme au §6.2 du Cahier des Charges (MOD-01).
- Configuration Pydantic immuable validée au démarrage (RF-01).
- Moteur asynchrone SQLAlchemy 2.0 et sessions injectées par dépendance FastAPI.
- Modèles relationnels `users`, `threat_feeds`, `indicators`, `cves`, `incidents`,
  `incident_events` conformes au §4.4 (RF-02).
- Moteur de Score de Risque Composite déterministe avec décomposition auditable (RF-14).
- Machine d'état des incidents à 6 étapes avec garde-fous de transition (RF-18).
- Détection et normalisation des IOC — IPv4/IPv6, domaines, URL, hashs, e-mails (RF-07, RF-08).
- CLI `sentry` : `version`, `config`, `db check`, `db init` (RF-03).
- Endpoint `/health` avec diagnostic de connexion base de données.
- Orchestration Docker Compose PostgreSQL 16 + Redis 7.2 et image applicative non privilégiée.
- Pipeline CI GitLab en quatre étapes : qualité (ruff, mypy strict), tests (PostgreSQL et Redis
  réels, seuil de couverture 80 %), build de l'image Docker, et analyses de sécurité natives
  (SAST, détection de secrets, scan de dépendances).
- Gabarits de merge request et d'issues GitLab, configuration Renovate.
- Conversion Markdown versionnable du Cahier des Charges et du Product Vision Document.
- Authentification (MOD-01, ADR-003) : hachage Argon2id, jetons JWT, `POST /api/v1/auth/token`,
  `GET /api/v1/users/me`, dépendances `get_current_user` et `require_roles`.
- CLI (RF-03) : `sentry db upgrade | downgrade | current`, `sentry seed` (flux publics abuse.ch,
  idempotent), `sentry users create`.
- Tests de bout en bout sur PostgreSQL réel : migrations montée/descente, absence de dérive entre
  modèles et migrations (`alembic check`), parcours CLI complet.
- ADR-003 (authentification en phase 1) et ADR-004 (recalage du planning, proposé).

### Corrigé
- **Sécurité** : le validateur de `SECRET_KEY` n'appliquait aucun contrôle. En production, SENTRY
  refuse désormais de démarrer avec la clé par défaut, une clé de moins de 32 caractères ou
  `DEBUG=true`.
- Les tests tournaient toujours sur SQLite, y compris en CI où PostgreSQL était démarré pour rien :
  la base de test suit maintenant `DATABASE_URL`, avec isolation transactionnelle par test.
- `sentry db init` affichait une consigne au lieu d'appliquer les migrations.
- L'image Docker applique les migrations au démarrage avant de lancer l'API (critère M1).
- `alembic.ini` : `version_path_separator` remplacé par `path_separator` (déprécié).
- Tri des imports : le dossier local `alembic/` ne masque plus le paquet tiers pour `ruff`.
- Port PostgreSQL hôte : `docker-compose.yml` expose 5433 ; `.env.example`, la valeur par défaut
  de `DATABASE_URL` et la documentation pointaient encore vers 5432.

### Modifié
- **Dépôt migré de GitHub vers GitLab**, qui devient la plateforme unique du projet
  (voir `docs/adr/ADR-002-hebergement-gitlab.md`). Suppression de `.github/`, des workflows
  GitHub Actions et de Dependabot ; mise à jour de toutes les références dans la documentation.
