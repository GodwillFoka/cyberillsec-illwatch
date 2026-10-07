# Changelog

Toutes les évolutions notables de SENTRY sont consignées ici.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et le versionnage
respecte [Semantic Versioning](https://semver.org/lang/fr/).

## [Non publié]

### Performances — gros volume (07/10)
Mesuré sur 480 669 IOC (poste Kali) : export des IOC en 89 s, tableau de bord en 2 à 4 s.
- **Export** : pagination par clé (`WHERE id > dernière clé`) au lieu d'`OFFSET`, dont le
  coût était quadratique ; lecture des seules colonnes exportées ; envoi par paquets de 500
  lignes au lieu d'une écriture réseau par ligne.
- **Tableau de bord** : deux lectures de la table des IOC au lieu de cinq (agrégats filtrés).

### Corrigé — rattrapage OTX de nuit (07/10)
- Une URL au port invalide (`http://hote:99999/`) levait une `ValueError` brute qui faisait
  échouer **tout le lot** d'IOC ; la collecte relisait alors les mêmes pages à l'infini
  (24 passages sans progrès). La valeur est désormais rejetée seule, comme toute valeur
  malformée.
- « Reprise à la page N » n'est plus annoncé quand l'ingestion échoue : l'avancement n'étant
  pas enregistré, le message était trompeur.

### Corrigé — collecte OTX (06/10, soirée)
Constaté lors de la première collecte réelle d'un compte OTX abonné à plus de 1 000 pulses :
- **Fin du « tout ou rien »** : une erreur réseau après la première page (ex. `ReadTimeout`
  après 17 min) annulait toute la collecte ; les pages déjà lues sont désormais ingérées et
  la collecte est signalée « interrompue ».
- **Curseur gelé tant que la fenêtre n'est pas épuisée** : une collecte tronquée
  (`OTX_MAX_PAGES`) avançait `modified_since` à l'heure de fin, et les pulses au-delà de la
  dernière page lue n'étaient plus jamais demandés. La collecte suivante reprend maintenant à
  la première page non lue (avancement dans `collector_state`, entrée `otx:<id du flux>`).
- `sentry cves sync` annonçait « NVD sans clé » même avec `NVD_API_KEY` : le rythme affiché
  suit désormais la configuration.

### Corrigé — clone neuf sur Kali (06/10)
Un clone neuf suivi du démarrage rapide du README a révélé des défauts invisibles en CI, où
aucun `.env` n'existe :
- **Tests et CI locale isolés du `.env`** : `MIGRATION_DATABASE_URL` du `.env` de poste
  envoyait les migrations des tests vers la base de travail, et l'étape 2b de
  `scripts/ci-local.sh` (`alembic downgrade base`) l'aurait vidée. Les tests et `ci-local.sh`
  ne lisent plus aucun fichier (`SENTRY_ENV_FILE=`), et la suite refuse une
  `MIGRATION_DATABASE_URL` qui ne vise pas une base `_test`.
- `.env.example` copié tel quel ne démarrait pas (`DOCS_ENABLED=`, `HSTS_ENABLED=` vides
  refusés) : une variable vide prend désormais sa valeur par défaut (`env_ignore_empty`).
- `sentry db init` sur un volume antérieur à M7 affichait « Échec de la migration » alors que
  les migrations étaient passées ; le message nomme désormais la commande à lancer
  (`sentry db app-role sentry_app --create`).
- Scénario SOC : arrêt explicite (code 2, action à mener) sur API injoignable, comptes absents
  ou base vide, au lieu d'une trace `IndexError` ou `HTTPStatusError`.
- `sentry status` : le critère M3 « Alerting actif » vérifie seulement la ligne de base ;
  renommé « Alerting : ligne de base établie ».

### Ajouté
- `SENTRY_ENV_FILE` : choisit le fichier de configuration lu au démarrage (vide : aucun).
- `sentry users set-password` : réinitialisation d'un mot de passe (politique appliquée,
  sessions révoquées, `user.password_reset` au journal d'audit) ; il fallait jusqu'ici une
  requête SQL manuelle.
- CI GitHub : étape « clone neuf » qui copie `.env.example` en `.env` avant les tests.

### Ajouté — Miroir GitHub et distribution (06/10, ADR-015)
- CI GitHub Actions miroir de `.gitlab-ci.yml` : ruff, mypy, pytest 3.12/3.14 sur PostgreSQL 16
  et Redis 7, migrations aller-retour, image Docker, fichiers Compose, pip-audit et bandit.
- **Validation réelle** hebdomadaire (`validation-reelle.yml`) : instance complète alimentée par
  les vraies sources (flux IOC, KEV, NVD, EPSS, Tor), tests `live`, scénario SOC d'acceptation
  et `sentry status` publiés dans le résumé du job — ferme la dette D3 de l'audit du 03/10.
- **Documentation publiée** sur GitHub Pages (MkDocs Material, charte SENTRY) :
  https://godwillfoka.github.io/cyberillsec-sentry/ — `mkdocs.yml`, `scripts/docs_prepare.py`.
- **Image Docker** sur `ghcr.io/godwillfoka/cyberillsec-sentry` (`:edge` depuis `main`,
  `:X.Y.Z` et `:latest` sur tag) et **release GitHub** dont les notes viennent de ce fichier.
- `docker-compose.prod.yml` : `SENTRY_IMAGE` permet de déployer l'image publiée (`--no-build`).
- Gabarits d'issues et de pull request GitHub ; Dependabot pour les actions et l'image de base.

### Corrigé — checkup du 06/10
- Version déclarée à deux endroits (`sentry/__init__.py` et `config.py`) : source unique.
- Badges du README pointant vers des pipelines GitLab privés (images cassées hors GitLab).
- Actions GitHub en Node 20 (dépréciées) remplacées par leurs versions Node 24 ; runners
  épinglés sur `ubuntu-24.04` (bascule de `ubuntu-latest` vers Ubuntu 26 le 19/10/2026).
- `CORS_ORIGINS` absent de `.env.example` alors qu'il est requis en production derrière un
  navigateur.
- Image Docker sans métadonnées OCI (source, licence) : ajoutées.

### Modifié
- `main` intègre `release/v0.1.1` et M7 (lots 1 à 3) ; version de développement `0.2.0.dev0`.

### Ajouté — M7 Production Hardening, lot 3 (ADR-013)
- `docker-compose.prod.yml` : Caddy (TLS Let's Encrypt, HTTP/2-3) seul service exposé,
  conteneur `migrate` éphémère (rôle propriétaire), API et worker en rôle applicatif,
  secrets obligatoires, `X-Forwarded-For` accepté de Caddy seul.
- CI : image poussée sous son SHA et analysée (Container Scanning) ; validation des deux
  fichiers Compose (`compose-config`).
- Worker : entretien quotidien (purge des sessions périmées, alerte `cve.epss_stale`) ;
  `sentry status` signale un EPSS de plus de 48 h.
- Production refusée avec un mot de passe de base absent ou de développement.
- ADR-014 (à trancher) : dépendance du score à EPSS et plancher KEV.

### Corrigé (réexécution du 04/10)
- Une migration lancée dans le processus (`sentry db upgrade`, tests) rendait muets les
  journaux `sentry.*`, dont l'audit (`fileConfig` d'Alembic).
- Les tests ne pouvaient pas passer d'une branche à l'autre sur la même base de test (schéma
  vidé par `drop_all` partiel) ; le schéma recréé n'accorde plus que `USAGE` à `PUBLIC`.
- Scénario de la baseline : contrôle SSRF non probant et compte bloqué entre deux exécutions.


### Ajouté — M7 Production Hardening, lot 2 (ADR-012)
- Rôle PostgreSQL applicatif sans droit de structure (`sentry db app-role`), droits
  réappliqués après chaque migration ; migrations via `MIGRATION_DATABASE_URL`.
- Jetons de rafraîchissement opaques et rotatifs, lignée révoquée au rejeu ;
  `POST /api/v1/auth/refresh`, `POST /api/v1/auth/logout` ; jeton d'accès ramené à 15 min.
- `sentry users disable|enable|revoke-sessions`.
- Rotation de `SECRET_KEY` sans déconnexion (`kid`, `SECRET_KEY_PREVIOUS`).
- Redis protégé par mot de passe (Compose), exigé en production.
- `sentry cves import` : CVE NVD 2.0 depuis des fichiers (.json, .gz, .xz), lus en flux,
  pour les déploiements sans accès à l'API NVD.

### Corrigé
- Alembic échouait avec un mot de passe encodé dans l'URL de base (« % » interprété par
  ConfigParser) : `sentry db upgrade` et `/ready` en erreur.
- `sentry config` affichait les mots de passe des URL de base et de Redis.
- Les URL de source refusées par l'anti-SSRF dès la validation (422) n'étaient pas auditées.
- Le scénario SOC ne pouvait pas être rejoué dans les 15 minutes (compte bloqué).
- Image Docker : la directive `# syntax` exigeait Docker Hub pour construire ; journal
  d'accès d'uvicorn doublé.


### Ajouté — M7 Production Hardening, lot 1 (ADR-011)
- Journal d'audit `audit_events` en ajout seul : connexions (réussies, échouées, bloquées),
  refus d'accès, administration des sources, soumission d'IOC, acquittement, chasse, exports,
  création de compte. `GET /api/v1/audit` (ADMIN), `sentry audit list`.
- Middleware de sécurité : `X-Request-ID`, `nosniff`, `X-Frame-Options`, CSP et `no-store` sur
  l'API, HSTS en production, journal d'accès JSON ; erreurs 500 en JSON sans détail interne.
- Sonde `/ready` (base, schéma à la head Alembic, Redis) ; `HEAD` sur `/health` et `/ready`.
- `docs/OPERATIONS.md`, `scripts/backup.sh`, `scripts/restore.sh` (vérification, SHA-256,
  rotation) ; `constraints.txt` partagé par la CI, l'image et le poste.

### Modifié
- Limitation des connexions par couple compte × IP (5), par compte (50), par IP (20) : un
  tiers ne peut plus verrouiller le titulaire légitime en 5 essais.
- Production : `/docs` masqué par défaut (`DOCS_ENABLED`), `CORS_ORIGINS=*` refusé.
- Ports Compose liés à `127.0.0.1` ; uvicorn lancé avec `--proxy-headers --no-server-header`.

### Sécurité
- `TRUNCATE` refusé sur `incident_events` et `audit_events` (déclencheurs d'instruction) : la
  chronologie « immuable » pouvait être vidée d'une instruction (audit du 03/10/2026).


## [0.1.1] — 2026-10-03 — Baseline M1–M6 intégrée

### Corrigé
- `mypy --strict` échouait avec SQLAlchemy 2.0 (`Select` à deux paramètres de type, valide
  seulement en 2.1) : annotation `Executable`, valide sur les deux versions.

### Ajouté
- `scripts/scenario_soc.py` : test d'acceptation SOC de bout en bout contre une instance réelle
  (40 vérifications, latences mesurées).
- `Rapport/ETAT_GLOBAL_SENTRY_2026-10-03.md` : audit global de `main` (Git, CI, migrations,
  validation réelle M2–M6, sécurité, dette, risques).
- `docs/ROADMAP.md` : trajectoire M7 → M11 et critères de sortie.


### Ajouté — Phase 6 (v1.0 « Threat Hunting »)
- Moteur de règles déterministe, catalogue RULE-01 à RULE-06 (Tor, DNS dynamique, DGA,
  ransomware, CVE exploitables sur l'inventaire, IOC connu) ; chasse sur observables soumis ou sur
  la base ; sessions et correspondances enregistrées ; chasse planifiée par le worker.
- API `/api/v1/hunting/rules|sessions` ; CLI `sentry hunt rules|run|show`. ADR-009.

### Ajouté — Phase 5 (M5 « Dashboard & reporting »)
- `/api/v1/dashboard/summary|recent|export` ; `sentry dashboard show|export` ; MTTR ; exports
  CSV RFC 4180 / JSON RFC 8259 diffusés en flux, protégés contre l'injection CSV.

### Ajouté — Phase 4 (M4 « Gestion des incidents »)
- Service, API `/api/v1/incidents` et CLI `sentry incidents` ; chronologie immuable (ORM et
  déclencheur PostgreSQL) ; liens IOC/CVE ; incident ouvert depuis une alerte CVE. ADR-008.

### Ajouté — TAXII 2.1 réel et sources vérifiées
- Backend `taxii2-client` 2.3.0 durci (SSRF, redirections refusées, délai, taille, erreurs
  typées), Basic / Bearer / en-tête par hôte, `TAXII_CLIENT=library|builtin`. ADR-010.
- `sentry taxii discover`, `sentry feeds probe`, `sentry feeds enable|disable`.
- Seed vérifié : IPsum (sans clé), RedEye TAXII (jeton gratuit) ; DigitalSide injoignable → inactif.
- Tests réseau réels opt-in (`SENTRY_LIVE_TESTS=1`).

### Sécurité
- Limitation des tentatives de connexion (compte et adresse IP, Redis partagé, repli mémoire).
- `.dockerignore` : contexte de build sans `.env`, `.git` ni environnement virtuel.

### Corrigé
- Bundles Git (≈ 480 Ko) versionnés par erreur : retirés et ignorés.
- Numéros d'exigence RF-15 / RF-16 du moteur CVE.

### Ajouté — Phase 3 (M3 « Moteur CVE & alerting »)
- **NVD 2.0** : synchronisation initiale (catalogue KEV + CVE modifiées depuis
  `NVD_INITIAL_DAYS`) puis incrémentale (fenêtres `lastModStartDate` de 120 j, curseur en base),
  pagination, débit respecté (6 s sans clé, 0,6 s avec `NVD_API_KEY`). CVSS v3.1 → v3.0 → v4.0 ;
  exploit public déduit des références NVD ; CVE rejetées ignorées.
- **CISA KEV** (ransomware, échéance, action requise ; retraits appliqués) et **FIRST EPSS**
  (score + percentile, lots de 100).
- **Recalcul** du score composite et de la priorité à chaque changement ; historique
  `cve_priority_history` ; migration `5d7ee876e4ef`.
- **API** : `GET /api/v1/cves`, `GET /api/v1/cves/{id}` (décomposition du score, historique),
  `GET /api/v1/alerts`, `POST /api/v1/alerts/{id}/ack`.
- **Alertes** au franchissement de `RISK_ALERT_THRESHOLD` (ligne de base sans alerte à la
  première synchro), webhook `ALERT_WEBHOOK_URL`, 5 tentatives.
- **CLI** `sentry cves sync | list | show | alerts` ; le worker synchronise les CVE toutes les
  `CVE_SYNC_INTERVAL_SECONDS` ; `sentry status` affiche les critères M3.
- ADR-007.

### Ajouté — Clôture M2 (branche `feature/sprint3-m2`)
- **TAXII 2.1** (tâche 1.8) : format `TAXII`, pagination `more`/`next`, `added_after`,
  identifiants par hôte `TAXII_AUTH` (accès invité DigitalSide par défaut).
- `sentry seed` : sources publiques sans clé (C2IntelFeeds IP et domaines, DigitalSide URL et
  TAXII) ; 3 sources saines et ≥ 500 IOC atteignables sans inscription.

### Corrigé — Clôture M2
- CSV : la colonne IOC est choisie sur le contenu. C2IntelFeeds (`#ip,ioc`) était rejeté à
  100 % car la colonne `ioc` contient un libellé.

### Ajouté — Sprint 3 (M2 « Ingestion opérationnelle », branche `feature/sprint3-ingestion`)
- **Provenance multi-sources (ADR-006)** : table `indicator_sources` (migration `1f3dafc3008c`,
  reprise de l'existant). `GET /api/v1/indicators/{id}` renvoie `sources` (flux, dates et
  compteur par source) ; la liste expose `source_count` ; le filtre `feed_id` couvre toutes les
  sources. `sentry status` compte les IOC confirmés par au moins deux flux.
- **T2.9 — Connecteur AlienVault OTX** : format de flux `OTX`, pulses abonnés paginés,
  `modified_since` incrémental, plafond `OTX_MAX_PAGES`. Clé `OTX_API_KEY` en en-tête, envoyée
  uniquement à `otx.alienvault.com` (refus 422 à l'enregistrement d'un flux OTX ailleurs).
  Source OTX ajoutée à `sentry seed`.
- **T2.6 — Planificateur** : `sentry feeds worker` et service `worker` dans Docker Compose
  (profil `full`). Verrou Redis par flux, aussi utilisé par `fetch` et `fetch-all`.
- **Journal JSON** (UC-01 étape 8) : une ligne `feed.collected` par collecte (volumes, durée,
  erreur, avertissement, pic mémoire `peak_rss_mb`), `worker.cycle` par cycle.
- Fetcher : en-têtes d'authentification jamais transmis lors d'une redirection vers un autre hôte.
- Test de conformité des contraintes CHECK **après migration** (non couvert par `alembic check`).

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
