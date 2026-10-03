# 🛡️ SENTRY — Plan directeur : état, tâches par étape, attentes et perspectives

**Date :** 27/09/2026, mis à jour le 28/09/2026 · **Version courante :** `0.1.0` (M1) ·
**Branches de travail :** `feature/threat-feeds-indicators` (à fusionner), puis
`feature/sprint3-ingestion`

> **Mise à jour du 28/09.** Sprint 3 codé : voir `Rapport/BILAN_SPRINT_3.md` et
> `Rapport/RAPPORT_GLOBAL.md`. État des tâches de l'étape 1 ci-dessous.

Ce document sert de fil conducteur jusqu'à la v1.0. Chaque grande étape se termine par un
**rapport de fin d'étape** dans `Rapport/`, à partir du gabarit de la section 4. Une étape n'est
close que si tous ses critères d'acceptation sont constatés, pas seulement codés.

---

## 1. Rapport de l'étape en cours — Sprint 2 « Threat Feeds : du CRUD à la collecte »

### 1.1 Résumé

Le socle MOD-02 est construit et testé : sources de flux (CRUD sécurisé), ingestion dédupliquée
des IOC, collecte automatique CSV / JSON / STIX 2.1, CLI d'exploitation. Le pipeline est vert en
local (qualité, 238 tests sur PostgreSQL 16, migrations). **Rien de tout cela n'est encore dans
le dépôt GitLab** : la branche locale est bloquée dans une fusion, et le bundle livré n'a pas été
appliqué. C'est le premier point à régler.

### 1.2 Livré

| Tâche | Exigence | Contenu |
|---|---|---|
| T2.1 / T2.4 | RF-04, RF-07 | Modèles alignés sur la migration `a4973a3782e3` ; contraintes CHECK dans le modèle |
| T2.2 | RF-04 | `/api/v1/feeds` : lecture pour tous, écriture ADMIN, validation SSRF, pagination, filtres |
| T2.3 | RF-05, RF-06 | Collecteur sécurisé (DNS vérifié, redirections revalidées, taille bornée, backoff, 429) ; analyseurs CSV, JSON, STIX 2.1 |
| T2.5 | RF-08, RNF-PERF-02 | Ingestion `INSERT … ON CONFLICT` : 1 000 IOC < 5 s ; sémantique fixée par l'ADR-005 |
| T2.7 | RF-03 | `sentry feeds list / add / fetch / fetch-all` |
| T2.8 | RSK-02 | Tests de pannes, 5xx, 429, redirections, DNS rebinding, isolation par flux |
| — | Qualité | Pipelines de branche GitLab, job `migrations`, `scripts/ci-local.sh`, garde-fou base `_test` |
| — | Secrets | Clé abuse.ch hors base (gabarit `{ABUSECH_AUTH_KEY}`), masquée dans les erreurs |

### 1.3 Métriques

| Indicateur | Début sprint (`0ec2a6e`) | Fin sprint (`ead1bda`) |
|---|---|---|
| Tests PostgreSQL | 95 | **238** |
| Couverture | 94 % | **95 %** |
| Routes API | 3 | **11** |
| Commandes CLI | 9 | **13** |
| ADR | 4 | **5** |
| `ruff` / `mypy --strict` / `alembic check` | ✅ | ✅ |

### 1.4 Défauts trouvés et corrigés pendant le sprint

| Défaut | Gravité | État |
|---|---|---|
| Modèle `expires_at` absent alors que la migration l'ajoutait | Majeure | ✅ |
| Tests pointables sur la base de travail (schéma détruit) | **Critique** | ✅ garde-fou `_test` |
| Pipeline GitLab muet sur les branches | Majeure | ✅ |
| URLhaus exige une clé depuis 2025 : URL semée obsolète | Majeure | ✅ gabarit + `.env` |
| Création concurrente d'un flux → transaction avortée | Moyenne | ✅ point de sauvegarde |
| Couverture sous-estimée (greenlets non suivis) | Mineure | ✅ |

### 1.5 Défauts connus, non bloquants

| Défaut | Risque | Traitement prévu |
|---|---|---|
| Entre notre résolution DNS et celle de httpx, un DNS malveillant peut changer de réponse | SSRF résiduel, faible | Épingler l'IP (étape 6, avant multi-tenant) |
| `last_error` visible par VIEWER peut citer une IP interne refusée | Fuite d'information, faible | Restreindre `last_error` aux ADMIN (étape 1) |
| Une seule source par IOC (`feed_id`) | Provenance perdue dès 2 flux | `indicator_sources` (étape 1) |
| Pas de limitation des tentatives de connexion | Force brute | Avant toute exposition publique (étape 4) |

---

## 2. Tâches à faire, par grande étape

Légende : **P0** bloquant · **P1** nécessaire au jalon · **P2** souhaitable.

### Étape 0 — Remettre le dépôt en état (½ journée) · *immédiat*

**But.** Repartir d'un historique propre et d'un pipeline GitLab vert avant tout nouveau code.

| # | Tâche | Prio | Critère de fin |
|---|---|---|---|
| 0.1 | Fermer Vim / Git GUI, supprimer `.git/HEAD.lock` si aucun `git` ne tourne, `git merge --abort` | P0 | `git status` propre |
| 0.2 | Appliquer le bundle `sprint3` (`git pull --ff-only …bundle feature/threat-feeds-indicators`) | P0 | `git log` montre `ead1bda` |
| 0.3 | `./scripts/ci-local.sh --docker` | P0 | « Pipeline local vert » |
| 0.4 | Pousser, ouvrir la merge request, pipeline GitLab vert, fusion dans `main` | P0 | MR fusionnée, pipeline vert |
| 0.5 | Supprimer `origin/feature/feeds-crud` (commit `7e15807` sans code) | P1 | branche absente |
| 0.6 | Une seule identité Git ; protéger `main` (fusion uniquement par MR) | P1 | réglage GitLab actif |
| 0.7 | Décider l'ADR-004 (planning) et l'ADR-005 (cycle de vie des IOC) | P1 | statut « accepté » ou amendé |

**Rapport de fin :** court, dans le bilan hebdomadaire du jeudi (`Rapport/02_01-10-2026.md`).

### Étape 1 — Sprint 3 : M2 « Ingestion opérationnelle » · cible **08/10/2026**

**But.** Des IOC réels, de plusieurs sources, collectés sans intervention.
**Objectif mesurable.** ≥ 500 IOC réels issus d'au moins 3 sources dont OTX ; collecte
automatique toutes les 15 min ; provenance multi-sources.

| # | Tâche | Prio | Critère de fin |
|---|---|---|---|
| 1.1 | Créer les comptes abuse.ch (Auth-Key) et AlienVault OTX (clé API) | P0 | clés dans `.env` |
| 1.2 | `sentry seed && sentry feeds fetch-all` sur données réelles | P0 | `SELECT count(*) FROM indicators` ≥ 500 |
| 1.3 | Table `indicator_sources` (IOC ↔ flux, first/last_seen par source) + migration | P0 | un IOC vu par 2 flux liste les 2 |
| 1.4 | T2.9 Connecteur OTX (pulses abonnés, pagination, clé en en-tête, jamais en base) | P0 | collecte OTX `HEALTHY` |
| 1.5 | T2.6 Planificateur intégré + verrou Redis par flux | P1 | 2 instances ne collectent jamais le même flux ensemble |
| 1.6 | Journal JSON structuré par collecte (UC-01 étape 8) | P1 | une ligne JSON par collecte |
| 1.7 | `last_error` réservé aux ADMIN dans l'API | P1 | test RBAC |
| 1.8 | T2.10 TAXII 2.1 (collection publique) | P2 | une collection collectée |
| 1.9 | Mesure mémoire sous collecte (RNF-MEM-01 ≤ 256 Mo) | P1 | mesure consignée |

**État au 28/09 :** 1.3 ✅ · 1.4 ✅ (code ; constat avec votre clé) · 1.5 ✅ · 1.6 ✅ ·
1.7 ✅ (`202c6aa`) · 1.9 🟡 (91 Mo sur 20 000 IOC synthétiques ; à refaire sur OTX réel) ·
1.1, 1.2 et 1.8 : à votre main (clés, collecte réelle, choix d'une source STIX).

**Attentes (critères M2 du Cahier des charges).** Collecteur OTX et flux STIX connectés ;
déduplication fonctionnelle ; ≥ 500 IOC réels.
**Rapport de fin :** `Rapport/BILAN_PHASE_2.md` + tag `v0.2.0`.

### Étape 2 — Phase 3 : M3 « Moteur CVE & alerting » · cible **22/10/2026**

**But.** Savoir en quelques secondes quelle vulnérabilité patcher d'abord.
**Acquis :** score composite RF-14 et grille P0–P3 déjà codés et testés.

| # | Tâche | Prio | Critère de fin |
|---|---|---|---|
| 2.1 | Collecteur NVD 2.0 (pagination, 50 req/30 s avec clé, reprise incrémentale par `lastModified`) | P0 | synchro initiale + incrémentale |
| 2.2 | Import CISA KEV (`is_kev`) et EPSS FIRST quotidien | P0 | champs renseignés, score recalculé |
| 2.3 | Recalcul du score à chaque changement d'entrée ; historisation des changements de priorité | P0 | test : KEV ajouté → P0 |
| 2.4 | `/api/v1/cves` (recherche, filtres priorité/score/KEV) et `/cves/{id}` avec décomposition du score | P0 | P95 < 250 ms (RNF-PERF-01) |
| 2.5 | Alerting : CVE franchissant `RISK_ALERT_THRESHOLD` → alerte (journal + webhook) | P1 | alerte déclenchée en test |
| 2.6 | CLI `sentry cves list / search / alert` | P1 | parcours CLI testé |
| 2.7 | Cache Redis des réponses NVD (RSK-01) | P1 | 2ᵉ synchro sans appel redondant |

**Attentes M3.** NVD synchronisée, EPSS intégré, score vérifié par tests, alerte sur CVE critique.
**Rapport de fin :** `Rapport/BILAN_PHASE_3.md` + `v0.3.0`.

### Étape 3 — Phase 4 : M4 « Gestion des incidents » · cible **05/11/2026**

**But.** Suivre un incident de la détection à la clôture, avec une chronologie opposable.
**Acquis :** machine d'état NIST à 6 étapes codée et testée.

| # | Tâche | Prio | Critère de fin |
|---|---|---|---|
| 3.1 | `/api/v1/incidents` (création, transitions validées par la machine d'état) | P0 | transitions interdites → 409 |
| 3.2 | Chronologie immuable garantie **par la base** (trigger refusant UPDATE/DELETE) | P0 | test PostgreSQL |
| 3.3 | Liaisons incidents ↔ IOC / CVE (tables de liaison) | P0 | liaison bidirectionnelle testée |
| 3.4 | Clôture exigeant un résumé post-mortem | P0 | déjà en logique, exposé en API |
| 3.5 | CLI `sentry incidents list / create / close` | P1 | parcours testé |
| 3.6 | Gestion des faux positifs d'IOC (liste d'exclusion), liée aux incidents | P1 | un IOC exclu n'apparaît plus comme actif |

**Rapport de fin :** `Rapport/BILAN_PHASE_4.md` + `v0.4.0`.

### Étape 4 — Phase 5 : M5 « Dashboard & reporting » · cible **12/11/2026**

**But.** Une vue SOC qui répond à « que dois-je traiter maintenant ? ».

| # | Tâche | Prio | Critère de fin |
|---|---|---|---|
| 4.1 | `/api/v1/dashboard/summary` : IOC actifs, CVE P0/P1, incidents ouverts, santé des flux | P0 | métriques exactes (tests sur jeu connu) |
| 4.2 | Menaces des dernières 24 h ; historique 7 jours glissants | P0 | séries correctes |
| 4.3 | `sentry dashboard show` (console Rich) | P1 | rendu testé |
| 4.4 | Exports JSON / CSV | P1 | formats validés |
| 4.5 | Durcissement avant exposition : limitation `/auth/token`, HTTPS, en-têtes de sécurité | P0 | tests + revue |
| 4.6 | Environnement de préproduction (VPS UE) + collecte continue 7 jours | P1 | données réelles sur 7 jours |

**Rapport de fin :** `Rapport/BILAN_PHASE_5.md` + `v0.5.0`.

### Étape 5 — Phase 6 : v1.0 « Threat Hunting » · cible **19/11/2026**

| # | Tâche | Prio | Critère de fin |
|---|---|---|---|
| 5.1 | Moteur de règles par motifs (RF-25) | P0 | règles évaluées sur les IOC |
| 5.2 | 5 règles opérationnelles (RF-26) | P0 | 5 règles testées |
| 5.3 | `/api/v1/hunt/rules`, `/hunt/run`, résultats persistés (RF-27, RF-28) | P0 | session enregistrée |
| 5.4 | CLI `sentry hunt run / list-rules / results` | P1 | parcours testé |
| 5.5 | Documentation utilisateur, guide de déploiement, notes de version | P0 | relus |
| 5.6 | Audit de sécurité final (dépendances, SAST, revue des ADR) | P0 | aucun finding haut |

**Attentes v1.0.** 6 modules intégrés, couverture ≥ 80 %, documentation à jour, tag `v1.0.0`.
**Rapport de fin :** `Rapport/BILAN_V1.md`.

### Étape 6 — Après la v1.0

| Axe | Contenu | Condition préalable |
|---|---|---|
| Sécurité | Épinglage de l'IP de sortie (SSRF résiduel), SSO/OIDC | avant multi-tenant |
| Produit | Multi-tenant, assistant IA (LLM + RAG sur les IOC/CVE) | v1.0 stable en production |
| Plateforme | Cyberill TI Cloud (offre hébergée UE) | premiers utilisateurs réels |
| Communauté | Contributions externes, connecteurs MISP/OpenCTI | documentation contributeur |

---

## 3. Attentes et perspectives du projet

### 3.1 Ce que la v1.0 doit prouver

1. **Utilité mesurable** : décider de la priorité d'une CVE en secondes, grâce au score composite
   fondé sur l'exploitation réelle (KEV, EPSS) plutôt que sur la seule sévérité CVSS.
2. **Légèreté réelle** : moins de 256 Mo en régime nominal, là où les alternatives open source
   demandent des clusters de 16 Go. C'est l'argument différenciant ; il doit être **mesuré**, pas
   affirmé (tâche 1.9, puis à chaque phase).
3. **Fiabilité** : collecte autonome sur 7 jours sans intervention en préproduction.

### 3.2 Perspectives

- **Réglementaires** : NIS 2 et DORA imposent une veille active et une notification sous 24 à
  72 h. Les modules 3 (CVE) et 4 (incidents, chronologie immuable) répondent directement à ces
  obligations : c'est l'axe de valeur à mettre en avant auprès des PME, ETI et collectivités.
- **Marché** : les plateformes commerciales (40 à 150 k€/an) laissent un espace réel pour une
  offre open source hébergée en UE. Le passage à Cyberill TI Cloud ne se justifie qu'avec des
  utilisateurs pilotes : en recruter 2 ou 3 dès la préproduction (étape 4).
- **Techniques** : l'architecture en couches tient. Les principaux points d'attention sont la
  dépendance aux API gratuites (abuse.ch a déjà changé ses conditions en 2025 ; NVD limite le
  débit) et la provenance multi-sources, indispensable avant d'ajouter des sources.

### 3.3 Risques de pilotage, dits franchement

| Risque | Constat | Parade |
|---|---|---|
| Capacité | Le Cahier des charges chiffre la v1.0 à 51 h. Le seul socle P1 + P2 a déjà dépassé cette enveloppe. | Recalage honnête à M2 à partir de la vélocité mesurée |
| Hygiène Git | 5 incidents Git en une semaine (fusions, commit sans code, migration sans modèle, fusion bloquée) | MR obligatoires, `ci-local.sh` avant chaque push, une seule copie de travail |
| Dérive du périmètre | Branding, dossiers de marque, docs parallèles | Geler le périmètre v1.0 (RSK-04) ; le reste en backlog |
| Accès outillage | `gitlab.com` bloqué pour les sessions d'assistance IA | Demande de déblocage à relancer ; en attendant, bundles Git |

---

## 4. Gabarit du rapport de fin d'étape

Chaque rapport de fin d'étape reprend ces rubriques, dans cet ordre :

1. **Verdict** — l'étape est-elle close ? Sinon, ce qui manque exactement.
2. **But et objectif mesurable** rappelés.
3. **Critères d'acceptation** — tableau critère / résultat / preuve (commande, test, capture).
4. **Livrables** par tâche.
5. **Métriques** — tests, couverture, performance, mémoire, avant/après.
6. **Défauts** trouvés, corrigés, et connus non bloquants.
7. **Analyse SWOAT** de l'étape.
8. **Décisions** prises (ADR) et en attente.
9. **Étape suivante** — but, attentes, risques.
