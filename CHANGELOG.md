# Changelog

Toutes les évolutions notables d'ILLWATCH (nommé SENTRY jusqu'au 08/10/2026) sont consignées ici.
Les entrées antérieures au renommage gardent l'ancien nom.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et le versionnage
respecte [Semantic Versioning](https://semver.org/lang/fr/).

## [Non publié]

### Ajouté — interface : écran Indicateurs (IOC)
- Recherche exacte normalisée (`evil[.]com` trouve `evil.com`), partageable (`?valeur=`) ;
  filtres type, sévérité minimale, source, validité ; pagination par 50.
- Fiche : copie de la valeur, statut, provenance par source (ADR-006), incidents associés,
  association à un incident ouvert (ADMIN, ANALYST).
- Soumission d'un lot collé (1 000 au plus, doublons retirés, rejets listés par le serveur).
- Export CSV de la base (consigné au journal d'audit `data.export`).
- API : `GET /incidents?indicator_id=…&cve_id=…` liste les incidents associés à un IOC ou à
  une CVE.
- Temps réel : une collecte relit la liste des IOC ; depuis un incident, chaque IOC mène à
  sa fiche.

### Ajouté — vérification
- `scripts/ci-local.sh` couvre tout le pipeline en une commande : contrôle préalable du réseau
  (DNS de github.com, pypi.org, registry.npmjs.org, avec le remède) et des outils, interface
  web (`npm ci`, audit, types générés, `tsc`, tests, construction), image Docker en option
  (`--docker`), `psql` facultatif (repli sur le conteneur), journal dans
  `/tmp/illwatch-ci-local.log`, durée de chaque étape.
- Workflow GitHub « Branches » : supprime la branche d'une PR fusionnée et balaie chaque
  semaine les branches entièrement contenues dans `main` (`main` et `release/*` exclues).

### Corrigé — audit global du 10/10 (revue indépendante)
- Test de chasse daté (aurait cassé la CI le 02/11/2026) : données relatives à l'horloge réelle.
- Bus temps réel : l'écoute Redis se reconnecte seule (1 → 30 s) et demande une relecture ;
  une publication impossible est livrée aux abonnés du processus ; Redis absent au démarrage
  n'oblige plus au bus local définitif.
- Sessions : les onglets d'une même session se coordonnent (diffusion des jetons, verrou de
  renouvellement) ; un onglet dupliqué ne révoque plus la session de l'autre.
- Collecte : `feeds fetch` valide avant de rendre le verrou ; le worker relit l'échéance d'un
  flux sous verrou (pas de double collecte avec une autre instance) ; fenêtre de retrait
  ramenée à 2 jours ; événements des commandes CLI publiés avant la sortie.
- Flux SSE borné à l'expiration réelle du jeton présenté.
- Interface : infobulle des graphiques compatible avec la politique `style-src 'self'` ; détail
  d'une CVE relu après une alerte ; sélection du triage annoncée (`aria-current`).
- Caddy : le flux SSE n'est plus compressé ni mis en tampon.
- CI : jobs `openapi` et `interface` sur GitLab (référence), image vérifiée servant
  l'interface ; `npm ci` obligatoire (Dockerfile, GitHub) ; Dependabot et Renovate suivent
  `frontend/`.
- Documentation : README, feuille de route, état d'avancement, ONBOARDING (`illwatch db
  upgrade`), architecture, design system, addendum à l'ADR-016.

### Ajouté — écran Incidents (10/10)
- Liste des incidents (ouverts ou tous, filtres statut et sévérité, les plus graves d'abord) et
  ouverture manuelle d'un incident (ADMIN, ANALYST).
- Page d'incident : cycle de vie NIST en six étapes, chronologie immuable, transitions
  permises par la machine d'état (résumé obligatoire à la clôture), commentaires et actions
  menées (déclarées par l'analyste, jamais présentées comme exécutées par ILLWATCH),
  assignation, CVE et IOC associés.
- Erreurs de validation de l'API (422) affichées en clair.

### Ajouté — écran Triage (10/10)
- File des alertes CVE triée par priorité puis ancienneté (« À traiter » ou « Toutes »),
  navigation au clavier, alerte choisie dans l'adresse (`/triage?alerte=…`).
- Panneau de détail en cinq sections : priorité, statut (score, émission, notification),
  vulnérabilité (CVSS, EPSS, KEV, action CISA, décomposition du score), historique de
  priorité, actions.
- Actions « Acquitter » et « Ouvrir l'incident » (ADMIN, ANALYST ; désactivées avec la raison
  pour VIEWER) ; après acquittement, la file passe à l'alerte suivante.

### Sécurité — dépendances de l'interface (10/10)
- `npm audit` (premier `npm install` sur Kali) : React Router 6 (redirections ouvertes, XSS,
  toute la branche 6) et ECharts < 6.1.0 (XSS). React Router est **retiré** au profit d'un
  routage interne de 60 lignes qui refuse toute adresse non interne ; ECharts passe en 6.1.0.
  Outils de développement : Vite 5.4.21 ; Vitest **retiré** (vulnérabilités critiques
  corrigées seulement en version 5) au profit du lanceur de tests intégré à Node
  (`node --test`, aucune dépendance). Restent signalées sur Vite 5 des failles du seul
  serveur de développement (corrigées en Vite 8, migration à planifier) : ne pas exposer
  `npm run dev` hors du poste (`--host` à proscrire).
- CI : `npm audit --omit=dev --audit-level=high` bloque désormais toute vulnérabilité élevée
  ou critique dans le code livré au navigateur.

### Ajouté — interface web, socle et vue d'ensemble (10/10)
- `frontend/` : React + TypeScript (Vite), TanStack Query, ECharts ; types générés depuis le
  schéma OpenAPI (`illwatch openapi`, `npm run gen:api`).
- Connexion avec renouvellement anticipé du jeton ; flux temps réel SSE avec pause, reprise,
  reconnexion progressive et relecture des seules données concernées.
- Vue d'ensemble (maquette v6) : file prioritaire des alertes, incident le plus grave,
  indicateurs, évolution 24 h / 7 j / 30 j, CVE par priorité, activité récente, santé des
  sources, IOC par type. Les autres écrans du lot 1 sont annoncés, sans contenu factice.
- Servie par FastAPI à la racine (`illwatch/app/web.py`) : politique de sécurité stricte
  (`script-src 'self'`), assets immuables, routage côté navigateur ; l'API garde ses 404 JSON.
- `GET /api/v1/dashboard/summary` typé (`SummaryRead`) pour la génération des types.
- Image Docker multi-étapes (Node pour compiler, aucun Node à l'exécution) ; job CI
  « Interface web » (types, tests, build).

### Modifié — retrait progressif des sources en panne (10/10)
- Une source en échec n'est plus retentée à chaque cycle du worker (constat Kali du 09/10 :
  DigitalSide injoignable sollicitée toutes les 3 minutes, 4 essais et 67 s à chaque fois).
  Après n échecs consécutifs, la tentative suivante attend 1, 2, 4, 8… minutes, jamais plus que
  l'intervalle normal de la source. Compté depuis `collection_runs` ; `fetch-all` l'ignore.

### Corrigé — journal des collectes (08/10)
- Une écriture refusée dans `collection_runs` (droits du rôle applicatif absents après un
  `alembic upgrade` lancé seul) faisait échouer tout le cycle du worker et laissait les verrous
  de collecte tenus jusqu'à expiration. Le journal est désormais écrit dans un point de
  sauvegarde : en cas d'échec, la collecte est conservée et `feed.run_not_recorded` est
  journalisé. Le verrou est toujours rendu.
- `alembic upgrade` lancé seul avertit que les droits du rôle applicatif restent à poser.

### Ajouté — interface web, lot 1 côté serveur (08/10)
- Journal des collectes : chaque collecte d'un flux laisse une ligne `collection_runs` (début,
  durée, nouveaux, mis à jour, rejetés, erreur, avertissement) ; conservation 90 jours, purge par
  l'entretien quotidien du worker. Migration `b8e3f61a2c47`.
- `GET /api/v1/feeds/health` : santé de toutes les sources (dernière tentative, dernier succès,
  volumes de la dernière collecte, collectes et échecs sur 7 jours).
- `GET /api/v1/feeds/{id}/runs?limit=` : historique des collectes d'une source (100 au plus).
- Lecture ouverte à tous les rôles ; le détail d'une erreur reste réservé aux administrateurs.
- `GET /api/v1/dashboard/timeseries?metric=iocs|alerts|incidents&window=24h|7d|30d` : comptage
  par heure ou par jour (UTC), réparti par sévérité ou priorité, tranches vides à zéro.
  Index `idx_indicators_first_seen` (migration `c5d0a7e94b13`) pour ne pas parcourir les
  500 000 IOC à chaque appel.
- `GET /api/v1/stream` : flux temps réel (Server-Sent Events) pour l'interface. Événements
  `alert.created`, `alert.acknowledged`, `incident.created`, `incident.updated`,
  `feed.collected`, `hunt.completed`, `resync`, `expired`. Filtrés par rôle, battement toutes
  les 15 s, durée bornée à celle du jeton d'accès, connexion PostgreSQL libérée pendant le flux.
- Bus d'événements `illwatch.modules.events` : canal Redis `illwatch:events` partagé entre l'API
  et le worker (repli en mémoire si Redis est injoignable). Les événements sont déduits des
  écritures en base et publiés **après le commit** uniquement.

### Décidé — interface web (08/10)
- ADR-016 accepté : interface React + TypeScript (Vite, TanStack Query, types générés depuis
  OpenAPI), temps réel par Server-Sent Events, servie par le même conteneur que l'API.
- Système de design v6 adopté (`docs/DESIGN_SYSTEM.md`) : indigo CYBERILLSEC, orange d'action,
  échelle de priorité unique P0–P3, Inter et JetBrains Mono.
- L'hébergement de préproduction (fin de M7) attend la première version de l'interface.

### Modifié — SENTRY devient ILLWATCH (08/10)
- Le nom « Sentry » étant déjà pris (plateforme de suivi d'erreurs), le projet est renommé
  **ILLWATCH**. Tout est renommé, sans compatibilité ascendante :
  - paquet Python `illwatch` (ex-`sentry-cti`), commande `illwatch`, journaux `illwatch.*` ;
  - variables `ILLWATCH_*` (ex-`SENTRY_*`, **plus lues**) ;
  - base, rôles et bases de test : `illwatch`, `illwatch_app`, `illwatch_test`… ;
  - conteneurs `illwatch-*`, volumes `illwatch_pgdata` / `illwatch_redisdata`, utilisateur
    de l'image `illwatch` ;
  - dépôts `cyberillsec-illwatch` (GitHub, GitLab), image `ghcr.io/godwillfoka/cyberillsec-illwatch` ;
  - logo : bouclier et radar conservés, mot ILLWATCH.
- Inchangés volontairement : les migrations Alembic déjà appliquées (fonctions
  `sentry_refuse_rewrite` et `sentry_refuse_timeline_rewrite`), les documents d'origine
  (`docs/pdf/`) et les rapports datés.
- `scripts/migrer-vers-illwatch.sh` : migration d'un poste existant (sauvegarde, `.env`
  réécrit, restauration, comptages comparés, retour arrière `--retour`). Voir OPERATIONS § 7 sexies.
- Projet Compose et volumes à nom fixe (`illwatch`, `illwatch_pgdata`, `illwatch_redisdata`) :
  renommer le dossier du dépôt ne démarre plus une base vide ; `scripts/deplacer-volumes-illwatch.sh`
  déplace les données d'un poste existant.
- Les anciens mots de passe de développement (`sentry`, `sentry-app-dev`, `sentry-dev-redis`)
  restent refusés en production.

### Sécurité — détection de secrets (07/10)
- Revue de tout l'historique Git avec gitleaks : 17 constats, **tous des faux positifs**
  (mots de passe factices de `tests/`, comptes jetables de la validation réelle) ; aucun `.env`,
  aucune clé privée jamais commité.
- `.gitleaks.toml` : exclusions justifiées ; un vrai jeton reste détecté (contrôle fait).
- CI GitHub : gitleaks sur tout l'historique à chaque push (version épinglée, somme vérifiée).

### Sécurité — image Docker (07/10)
- `curl` retiré de l'image : il ne servait qu'au `HEALTHCHECK` (désormais en Python) et portait
  8 des 52 vulnérabilités « High » relevées par Container Scanning (aucune corrigée par Debian).
  Les 44 autres, toutes dans le socle Debian 13.7 et sans correctif, sont acceptées et
  documentées (guide d'exploitation § 7 quinquies). Aucune Critical.
- CI GitHub : l'image est vérifiée sans curl et sa sonde de santé est exécutée.

### Modifié — priorité des CVE (ADR-014 accepté le 07/10)
- **Plancher KEV** : une CVE du catalogue CISA KEV est classée au moins **P1**, même si la
  formule la place en P2 ou P3 ; le score reste celui de la formule (ADR-001). Motif historisé
  `…+floor_kev`, exposé dans l'API (`breakdown.kev_floor`) et `sentry cves show`.
- `sentry cves rescore` : reclasse toutes les CVE après un changement de règle, sans alerte.
  **À lancer une fois après la mise à jour** (612 CVE KEV en P2/P3 sur la base de référence).
- Panne EPSS : la conservation de la dernière valeur connue est verrouillée par un test.

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
