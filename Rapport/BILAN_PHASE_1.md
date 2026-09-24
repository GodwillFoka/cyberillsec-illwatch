# 🛡️ SENTRY — Bilan de clôture de la phase 1 « Foundation »

**Version :** 0.1.0 · **Jalon :** M1 — Squelette opérationnel · **Date du bilan :** 24/09/2026
**Module :** MOD-01 Foundation & Configuration · **Référence :** Cahier des charges v1.0.0, §3.3, §5.2, §5.3
**Dépôt :** `gitlab.com/GodwillFoka/cyberillsec-sentry`, branche `main`, HEAD `e11831c`

---

## 1. Verdict

**La phase 1 est terminée sur le plan fonctionnel et technique.** Son périmètre planifié (T1.1 à
T1.8) est livré en entier, avec en plus l'authentification, qu'aucune tâche ne prévoyait alors que
le périmètre de MOD-01 l'inclut. Trois des quatre critères M1 sont vérifiés sur PostgreSQL 16 réel.

**Clôture formelle sous trois conditions**, toutes courtes :

1. Appliquer le correctif du port PostgreSQL (5432 → 5433, §9). Sans lui, un développeur qui suit le
   guide d'installation ne se connecte pas à la bonne base.
2. Exécuter le scénario Docker complet (critère M1 n° 1, non vérifiable depuis l'environnement
   d'analyse) et constater un pipeline GitLab vert.
3. Poser le tag `v0.1.0` : le commit `chore(release): close phase 1 foundation` n'est accompagné
   d'aucun tag, et le CHANGELOG annonçait encore 0.1.0 « à venir ».

---

## 2. Rappel : but et périmètre de la phase 1

**But.** Fournir un socle sur lequel les cinq modules métier se branchent sans jamais revenir sur
l'infrastructure : configuration validée, base versionnée, CLI d'exploitation, tests et CI qui
bloquent les régressions.

**Objectif mesurable (jalon M1, §5.2).** FastAPI démarre sous Docker ; PostgreSQL migre via Alembic
sans erreur ; `/health` retourne 200 avec la base connectée ; suite de tests à 100 %.

**Exigences couvertes.** RF-01 (configuration immuable), RF-02 (migrations automatisées), RF-03
(CLI d'initialisation, de seed et de diagnostic).

---

## 3. Critères d'acceptation M1

| Critère | Résultat | Preuve |
|---|---|---|
| FastAPI démarre sous Docker | ⚠️ **À constater** | Image non construite ici (pas de démon Docker). Démarrage équivalent vérifié : paquet installé en mode non éditable, `ENVIRONMENT=production`, migrations puis `uvicorn`. L'image applique désormais `sentry db upgrade` avant de lancer l'API. |
| PostgreSQL migre via Alembic sans erreur | ✅ | `test_migrations_montent_descendent_et_collent_aux_modeles` : `upgrade head` → `alembic check` (aucune dérive modèles/migrations) → `downgrade base` → `upgrade head`, sur PostgreSQL 16.13. |
| `/health` retourne 200, base connectée | ✅ | `{"status":"ok","version":"0.1.0","environment":"production","database":"connected"}` sur PostgreSQL réel ; `test_health_retourne_200_avec_db_connectee`. |
| Suite de tests à 100 % | ✅ | 95 / 95 sur PostgreSQL ; 93 réussis + 2 ignorés (tests réservés à PostgreSQL) sur SQLite. |

---

## 4. Livrables par tâche

| Tâche | Contenu planifié | Livré |
|---|---|---|
| T1.1 | Arborescence, `pyproject.toml`, squelette FastAPI | ✅ Architecture en couches (clients → contrôleurs → services → accès aux données → persistance), fabrique `create_app()`, OpenAPI sur `/docs`. |
| T1.2 | `database.py`, modèle `User`, migration initiale | ✅ Moteur SQLAlchemy 2.0 async, sessions injectées, **six** modèles (`users`, `threat_feeds`, `indicators`, `cves`, `incidents`, `incident_events`) et migration `c36227f04410`. |
| T1.3 | CLI `db init`, `db upgrade`, `version` | ✅ `version`, `config` (secrets masqués), `db init / upgrade / downgrade / current / check`, `seed`, `users create`. |
| T1.4 | Docker Compose PostgreSQL 16 + Redis 7 | ✅ Volumes persistants, *healthchecks*, image applicative non privilégiée (UID 10001), profil `full`. |
| T1.5–1.7 | Isolation des répertoires modules | ✅ `threat_feeds`, `cve_tracker`, `incidents`, `dashboard`, `threat_hunting`, plus `foundation` (comptes et seed). |
| T1.8 | Pytest asynchrone, premier test `/health` | ✅ Base de test pilotée par `DATABASE_URL`, isolation transactionnelle par test, marqueur `postgres`. |
| Hors plan | Authentification (ADR-003) | ✅ Argon2id, JWT HS256, `POST /api/v1/auth/token`, `GET /api/v1/users/me`, `require_roles`. |
| Hors plan | Logique métier anticipée | ✅ Score de risque composite (RF-14), machine d'état des incidents (RF-18), détection et normalisation des IOC (RF-07) — testés à 100 %, sans API ni persistance. |

---

## 5. Exigences non fonctionnelles

| Exigence | État en fin de phase 1 |
|---|---|
| RNF-SEC-01 — TLS, aucun secret dans le code | ⚠️ Aucun secret en dur ; SENTRY refuse de démarrer en production avec la clé par défaut, une clé de moins de 32 caractères ou `DEBUG=true`. Le TLS relève du déploiement (reverse proxy), pas encore en place. |
| RNF-SEC-02 — Entrées typées (Pydantic) | ✅ Configuration, réponses et formulaire d'authentification typés ; requêtes SQL exclusivement paramétrées via l'ORM. |
| RNF-MAIN-01 — `ruff` 100 %, couverture ≥ 80 % | ✅ `ruff` et `mypy --strict` sans erreur ; couverture 94 %. |
| RNF-MEM-01 — ≤ 256 Mo | 🟡 Mesure indicative : 133 Mo de RSS après chargement de l'application. Une mesure sous charge reste à faire en phase 2, quand les collecteurs tourneront. |
| RNF-PERF-01/02 | ➖ Hors périmètre de la phase 1 ; RNF-PERF-02 (1 000 IOC < 5 s) est un critère de la phase 2. |

---

## 6. Sécurité : ce que la phase 1 garantit

- **Configuration.** Validation au démarrage : aucune requête ne s'exécute avec une configuration
  invalide (règle de gestion MOD-01).
- **Mots de passe.** Argon2id salé (OWASP), longueur minimale de 12 caractères (NIST SP 800-63B).
  Vérification en temps quasi constant, que le compte existe ou non.
- **Jetons.** Algorithme figé au décodage : `alg: none`, clé étrangère, type de jeton inattendu et
  sujet non UUID sont refusés (tests dédiés). Le rôle est relu en base à chaque requête : un compte
  désactivé perd l'accès immédiatement.
- **Réponses d'erreur.** Même code et même message pour « compte inconnu » et « mauvais mot de
  passe » : un attaquant ne peut pas découvrir quels comptes existent.
- **Conteneur.** Exécution sans privilèges, *healthcheck* intégré.

---

## 7. Métriques qualité

| Indicateur | Valeur | Seuil |
|---|---|---|
| Tests passants | 95 / 95 (PostgreSQL 16) | 100 % |
| Couverture | 94,0 % (PostgreSQL) · 86,6 % (SQLite) | ≥ 80 % |
| `ruff check` / `ruff format` | 0 écart | 0 |
| `mypy --strict` | 0 erreur, 34 fichiers | 0 |
| Code applicatif / code de test | ≈ 1 515 / 914 lignes | — |
| Fichiers de test | 12 | — |
| Commits sur `main` | 11 | — |
| ADR | 4 (dont 1 proposé) | — |

---

## 8. Historique et gestion de version

Onze commits entre le 19/09 et le 23/09/2026. Trois constats :

- **Trois identités Git** pour la même personne (`contact@cyberill.com`, `fokagodwill@gmail.com`,
  adresse `noreply` GitHub). La traçabilité et les statistiques par auteur s'en trouvent faussées.
- **Deux fusions d'historiques** (« Merge local and GitLab histories », « Merge avec la version en
  local »), signe que la copie locale et le dépôt distant ont divergé pendant la migration depuis
  GitHub.
- **Conventions de message mixtes** : *Conventional Commits* (`feat(db):`, `fix(lint):`) et messages
  libres (« Synchronisation avec la mise à jour… »).

---

## 9. Anomalies détectées et corrigées pendant la phase

| # | Anomalie | Gravité | Correctif |
|---|---|---|---|
| 1 | Le validateur de `SECRET_KEY` renvoyait la valeur sans aucun contrôle : démarrage possible en production avec la clé d'exemple publique, donc jetons forgeables par n'importe qui | **Critique** | `model_validator` + 6 tests |
| 2 | Tests toujours exécutés sur SQLite, y compris en CI où PostgreSQL démarrait pour rien : le critère M1 « PostgreSQL migre » n'était vérifié nulle part | Majeure | Base de test pilotée par `DATABASE_URL` ; tests de migration et de CLI de bout en bout |
| 3 | `sentry db init` affichait une consigne au lieu d'appliquer les migrations | Majeure | Pilotage programmatique d'Alembic (`sentry/app/migrations.py`) |
| 4 | Aucune authentification malgré le périmètre MOD-01 | Majeure | ADR-003 |
| 5 | L'image Docker démarrait l'API sans migrer la base | Moyenne | `sentry db upgrade && exec uvicorn …` |
| 6 | `version_path_separator` déprécié dans `alembic.ini` | Mineure | `path_separator` |
| 7 | `ruff` prenait le dossier local `alembic/` pour le paquet tiers | Mineure | `known-third-party = ["alembic"]` |
| 8 | **Port PostgreSQL incohérent** : `docker-compose.yml` expose 5433 (commit `e11831c`) mais `.env.example`, la valeur par défaut de `DATABASE_URL` et le guide pointent vers 5432 | Majeure | Alignement sur 5433 — **à commiter** |

---

## 10. Analyse SWOAT de la phase 1

**Forces**
- Socle vérifié sur la vraie base cible : migrations montantes et descendantes, aucune dérive entre
  modèles et schéma.
- Qualité outillée et bloquante : typage strict, lint, couverture de 94 %, CI en quatre étapes
  (qualité, tests sur PostgreSQL et Redis réels, build, sécurité SAST/secrets/dépendances).
- Sécurité intégrée dès la fondation : configuration refusée si dangereuse, Argon2id, JWT durci.
- Avance réelle sur les phases 3 et 4 : scoring composite, machine d'état et validation des IOC
  sont écrits et testés.
- Traçabilité des décisions : 4 ADR, CHANGELOG, rapport hebdomadaire normé.

**Faiblesses**
- Critère Docker de M1 pas encore constaté ; pipeline GitLab non observé.
- Redis et `tenacity` déclarés mais inutilisés ; pas de journalisation structurée, alors que UC-01
  (étape 8) l'exige.
- Colonnes de statut stockées en texte libre (`type`, `severity`, `status`) sans contrainte `CHECK` :
  la base accepte des valeurs hors énumération.
- Pas de limitation des tentatives de connexion, ni de révocation de jeton.
- Historique Git bruité (identités multiples, fusions) ; planning d'origine dépassé de sept
  semaines.

**Opportunités**
- La contrainte `UNIQUE (type, value)`, désormais testée sur PostgreSQL, permet d'écrire la
  déduplication de la phase 2 en un seul `INSERT … ON CONFLICT DO UPDATE` groupé : c'est la voie
  directe vers RNF-PERF-02.
- Les flux abuse.ch (URLhaus, Feodo Tracker) sont publics, gratuits et sans clé : ils permettent
  d'atteindre les 500 IOC réels de M2 avant même que le connecteur OTX soit prêt.
- NIS 2 et DORA rendent la veille active obligatoire, et l'authentification par rôles prépare le
  multi-tenant et le SSO de l'après-v1.0.

**Aspirations**
- Faire de SENTRY l'alternative européenne open source de référence en CTI légère : le socle actuel
  (MIT, < 256 Mo, hébergement UE) est cohérent avec ce positionnement.
- Garder la discipline « aucune route sans test, aucune décision sans ADR » sur les 43 tâches
  restantes.

**Menaces**
- Accès réseau : `gitlab.com` est bloqué pour les sessions d'assistance IA de l'organisation, ce qui
  ralentit les revues et empêche de lire les pipelines.
- Dépendance aux API publiques gratuites (limites de débit NVD, changement de format ou fermeture
  d'un flux) : c'est le risque RSK-01, dont la phase 2 est la première exposée.
- Dérive du périmètre (RSK-04) : l'authentification a été ajoutée hors plan ; c'était justifié, mais
  le réflexe doit rester l'exception.

---

## 11. Améliorations à apporter

**Avant d'ouvrir la phase 2 (bloquant)**
1. Commiter l'alignement du port 5433 (§9, n° 8) et le CHANGELOG 0.1.0.
2. `cp .env.example .env`, puis `docker compose --profile full up -d --build` et
   `curl localhost:8000/health` : constater `"database":"connected"`.
3. Pipeline GitLab vert, puis tag `v0.1.0`.
4. Trancher l'ADR-004 (recalage du planning).

**Pendant la phase 2 (intégré aux tâches)**
5. Contraintes `CHECK` sur `indicators.type`, `indicators.severity` et `threat_feeds.status`, dans
   la migration de la phase 2.
6. Journalisation structurée JSON (nombre d'IOC traités, durée, flux, erreurs), exigée par UC-01.
7. Colonne `expires_at` sur les indicateurs pour le vieillissement (RSK-03), avant que le volume
   n'explose.
8. Brancher Redis (verrou de collecte, cache des réponses) et `tenacity` (backoff), prévus par
   RSK-01 et RSK-02.

**Avant toute exposition publique**
9. Limitation des tentatives sur `/auth/token`, HTTPS par reverse proxy, journal d'audit des
   connexions.

**Hygiène de projet**
10. Une seule identité Git (`git config --global user.email contact@cyberill.com`), *Conventional
    Commits* systématiques, branche `main` protégée (merge uniquement par merge request au pipeline
    vert).

---

## 12. Prochaine étape : phase 2 « Threat Feeds & moteur IOC » (MOD-02)

### But
Transformer SENTRY d'un socle vide en **plateforme qui collecte réellement du renseignement** :
aller chercher les indicateurs de compromission sur des sources externes, les normaliser et les
stocker une seule fois, quel que soit le nombre de sources qui les signalent.

### Objectif recherché
Qu'un analyste puisse, sans aucune manipulation manuelle, disposer d'une base d'IOC réels, à jour et
dédupliqués, alimentée en continu par plusieurs flux. C'est la matière première des phases 5 (le
dashboard compte les menaces des dernières 24 h et des 7 derniers jours) et 6 (le hunting compare
des motifs à ces IOC). Sans phase 2, les modules suivants tournent à vide.

### Attendus — jalon M2
| Critère M2 (§5.2) | Mesure de validation |
|---|---|
| Collecteur OTX et flux STIX connectés | Une collecte `sentry feeds fetch` réussie sur chacun, `status = HEALTHY` |
| Déduplication fonctionnelle | `SELECT type, value, count(*) FROM indicators GROUP BY 1,2 HAVING count(*) > 1` → 0 ligne ; un IOC revu incrémente `hit_count` et met à jour `last_seen` |
| ≥ 500 indicateurs réels en base | `SELECT count(*) FROM indicators` ≥ 500, issus de flux réels et non de données de test |
| RNF-PERF-02 | Test : 1 000 IOC ingérés en moins de 5 s sur PostgreSQL |
| Résilience (UC-01, 2a et 3a) | Tests avec réseau simulé : 3 tentatives avec backoff, puis `DEGRADED` ; en cas de `429`, respect de `Retry-After` ; un flux en panne ne bloque ni les autres ni l'API |

### Exigences couvertes
RF-04 (CRUD des flux), RF-05 (collecte asynchrone), RF-06 (JSON, CSV, STIX 2.1), RF-07 (extraction
des IOC), RF-08 (déduplication), RF-09 (worker périodique), RF-10 (connecteur OTX).

### Plan de travail (dates selon l'ADR-004, à confirmer)
| Ordre | Tâche | Contenu | Pourquoi dans cet ordre |
|---|---|---|---|
| 1 | T2.1 / T2.4 | Migration : contraintes `CHECK`, `expires_at` | Le schéma se fige avant d'écrire dessus |
| 2 | T2.2 | CRUD `/api/v1/feeds`, protégé par `get_current_user`, écriture réservée aux `ADMIN` | Donne le point d'entrée de configuration |
| 3 | T2.5 | Upsert groupé `ON CONFLICT DO UPDATE`, test de 1 000 IOC en moins de 5 s | Cœur de M2 et de RNF-PERF-02 |
| 4 | T2.3 | Client httpx + parseurs CSV (abuse.ch), JSON, STIX 2.1 | Réutilise `normalize_indicator` déjà testé |
| 5 | T2.6 | Worker périodique, verrou Redis, isolation des pannes par flux | UC-01 complet |
| 6 | T2.7 | CLI `sentry feeds list / add / fetch / fetch-all` | Exploitation et validation de M2 |
| 7 | T2.9 / T2.10 | Connecteur OTX, flux STIX/TAXII | Dépend de la clé OTX (à créer dès J1) |
| 8 | T2.8 | Tests réseau simulés (`respx`), tolérance aux pannes | Verrouille le comportement de UC-01 |

**Fenêtre proposée :** du 25/09 au 08/10/2026, jalon M2 le 08/10/2026.

### Risques principaux de la phase 2
- **RSK-02, flux indisponible.** Chaque collecte dans sa propre tâche avec son propre délai
  d'expiration ; l'échec n'est enregistré que sur ce flux.
- **RSK-03, explosion du volume.** Vieillissement (`expires_at`) et index en place dès la migration
  de la phase 2.
- **Clé OTX.** Action externe à lancer dès le premier jour : sans elle, le critère « collecteur OTX
  connecté » est bloqué.

### Définition de « terminé » pour la phase 2
Tous les critères M2 mesurés comme ci-dessus, pipeline vert, couverture ≥ 80 %, CHANGELOG 0.2.0,
bilan de phase rédigé et tag `v0.2.0` posé.
