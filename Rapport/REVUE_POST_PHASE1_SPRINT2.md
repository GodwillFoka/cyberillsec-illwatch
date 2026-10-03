# 🛡️ SENTRY — Revue post-phase 1 et plan du sprint suivant

**Date :** 27/09/2026 · **Branche :** `feature/threat-feeds-indicators` · **Base :** `main` @ `3f9196f`
**Jalon visé :** M2 — Ingestion opérationnelle

---

## 1. Chronologie Git du projet

| Date | Commit | Auteur (identité Git) | Événement |
|---|---|---|---|
| 19/09 | `6bd6980` | Godwill FOKA `contact@cyberill.com` | Squelette SENTRY conforme au Cahier des charges v1.0.0 |
| 19/09 | `01410ea` | idem | Migration GitHub → GitLab (ADR-002) |
| 19/09 | `266700a` → `9f2f1d3` | 2 identités | Commit initial GitLab, puis **deux fusions d'historiques** local/distant |
| 23/09 | `5e0fe5c` → `c70ce34` | `fokagodwill@gmail.com` | Migration initiale `c36227f04410` et corrections de lint |
| 23/09 | `46fbc01` | `…@users.noreply.github.com` | Clôture technique P1 : auth, CLI RF-03, tests PostgreSQL |
| 23/09 | `e11831c` | `fokagodwill@gmail.com` | Port PostgreSQL hôte 5432 → 5433 |
| 24/09 | `ae7ea0a` | `…noreply…` | Alignement du port dans la config ; **tag `v0.1.0` (M1)** |
| 24/09 | `7e15807` | `…noreply…` | ⚠️ Poussé sur `origin/feature/feeds-crud` : **ne contient aucun code**, seulement un lien de sous-module vers un dépôt imbriqué `cyberillsec-sentry/` |
| 26/09 | `d848343` | `fokagodwill@gmail.com` | Migration `a4973a3782e3` (CHECK + `expires_at`) **sans le modèle** |
| 26/09 | `f0aa045`, `3f9196f` | idem | Fusion directe dans `main` puis correction de lint → `alembic check` rouge sur `main` |
| 27/09 | `0ec2a6e` | idem | `Indicator.expires_at` ajouté au modèle → `alembic check` repasse |
| 27/09 | — | — | ⚠️ Fusion de `origin/feature/feeds-crud` **entamée et bloquée** (`MERGE_HEAD`, `HEAD.lock`) |
| 27/09 | `36a5c69` → `15a9693` | Claude (Cowork) | Présente série : modèle complet, T2.2, IOC, CI, collecteur T2.3 + CLI T2.7 |

**Lecture.** Le code progresse bien. L'hygiène Git, elle, coûte cher : trois identités d'auteur,
deux fusions d'historiques, un commit poussé sans code, une migration commitée sans son modèle,
une fusion directe dans `main`, et une fusion locale restée bloquée. Chacun de ces incidents a
consommé une session de diagnostic.

## 2. Validation de l'état P1 → P2

### Phase 1 — Foundation : ✅ close (`v0.1.0`)

Configuration validée au démarrage, authentification JWT/Argon2id, CLI RF-03, migrations
vérifiées sur PostgreSQL, Docker, CI en 4 étapes. Aucune régression constatée depuis.

### Phase 2 — Threat Feeds : état après la présente série

| Tâche | Exigence | État | Preuve |
|---|---|---|---|
| T2.1 / T2.4 Modèles `ThreatFeed`, `Indicator` + migration | RF-04, RF-07 | ✅ | `alembic check` propre ; CHECK comparées modèle ↔ base |
| T2.2 CRUD `/api/v1/feeds` | RF-04 | ✅ | 30 tests API, RBAC, SSRF |
| T2.3 Client HTTP + parseurs JSON/CSV/STIX | RF-05, RF-06 | ✅ | 34 tests, aucun accès réseau réel |
| T2.5 Insertion groupée + déduplication | RF-08, RNF-PERF-02 | ✅ | 1 000 IOC < 5 s sur PostgreSQL |
| T2.6 Worker périodique | RF-09 | 🟡 | `sentry feeds fetch-all` planifiable par cron ; pas encore de worker intégré |
| T2.7 CLI `sentry feeds` | RF-03 | ✅ | test de bout en bout sur PostgreSQL |
| T2.8 Tests réseau simulés | RSK-02 | ✅ | pannes, 5xx, 429, redirections, DNS rebinding |
| T2.9 Connecteur AlienVault OTX | RF-10 | ❌ | nécessite la clé API OTX |
| T2.10 Flux STIX/TAXII | RF-06 | 🟡 | STIX 2.1 par URL ✅ ; protocole TAXII 2.1 ❌ |

### Critères M2

| Critère | État |
|---|---|
| Collecteur OTX connecté | ❌ bloqué par la clé API |
| Flux STIX connecté | 🟡 analyseur prêt, aucun flux STIX réel enregistré |
| Déduplication fonctionnelle | ✅ garantie par la base, testée |
| ≥ 500 indicateurs réels en base | ⏳ à constater : `sentry seed && sentry feeds fetch-all` sur votre machine (URLhaus seul dépasse largement 500) |

### Qualité

| Indicateur | Valeur |
|---|---|
| Tests | 230 passés sur PostgreSQL 16 · 222 + 6 ignorés sur SQLite |
| Couverture | 95 % (PostgreSQL) |
| `ruff`, `ruff format`, `mypy --strict` | 0 écart |
| `alembic check` | aucune dérive |

## 3. Défauts corrigés dans cette série

| # | Défaut | Gravité | Correctif |
|---|---|---|---|
| 1 | Doc : lancer `pytest` sur la base de travail, alors que les tests de migration en détruisent le schéma | **Critique** (perte de données) | Garde-fou : base de test obligatoirement `…_test` |
| 2 | Pipeline GitLab non déclenché sur les pushes de branches | Majeure | Règles `workflow` branch + MR |
| 3 | Aucun job ne vérifiait migrations ↔ modèle en CI de façon explicite | Majeure | Job `migrations` |
| 4 | Base de tests restée sur un ancien schéma → échecs trompeurs | Moyenne | Schéma recréé à chaque session |
| 5 | Contraintes CHECK absentes du modèle (tests SQLite permissifs) | Moyenne | CHECK déclarées dans le modèle |
| 6 | Import inutilisé dans la migration, doc et feuille de route périmées | Mineure | Nettoyage |

## 4. Prochain sprint — « Sprint 3 : de la collecte à la donnée exploitable »

**But.** Atteindre M2 sur des données réelles, puis rendre la collecte autonome.

**Objectif mesurable.** ≥ 500 IOC réels issus d'au moins 3 sources (dont OTX), collecte toutes
les 15 minutes sans intervention, provenance multi-sources de chaque IOC.

| Ordre | Tâche | Pourquoi maintenant | Critère de fin |
|---|---|---|---|
| 1 | Réparer le dépôt (§5) et fusionner cette branche par merge request | Tout le reste en dépend | Pipeline GitLab vert sur la MR |
| 2 | Constater M2 « 500 IOC » avec URLhaus + Feodo | Premier jalon mesurable | `SELECT count(*) FROM indicators` ≥ 500 |
| 3 | Table `indicator_sources` (provenance multi-flux) | Avant OTX : sinon la 2ᵉ source d'un IOC est perdue (ADR-005) | Un IOC vu par 2 flux liste les 2 |
| 4 | T2.9 Connecteur AlienVault OTX (pulses abonnés, pagination) | Critère M2 | Collecte OTX `HEALTHY` |
| 5 | T2.6 Worker : planificateur intégré + verrou Redis | Collecte autonome, pas de double collecte | Deux instances ne collectent jamais le même flux en même temps |
| 6 | Journalisation structurée JSON des collectes | UC-01 étape 8 | Une ligne JSON par collecte |
| 7 | T2.10 TAXII 2.1 | Dernier format du Cahier des charges | Collection TAXII publique collectée |

**Hors sprint (backlog v1.1)** : épinglage de l'IP résolue dans la connexion (SSRF résiduel),
gestion des faux positifs, durées de validité par flux.

## 5. Actions immédiates sur le dépôt local

1. Terminer la fusion bloquée **sans la valider** : `origin/feature/feeds-crud` (`7e15807`) ne
   contient qu'un lien de sous-module et polluerait l'arbre.
2. Supprimer la branche distante `feature/feeds-crud` une fois vérifiée.
3. Unifier l'identité Git : `git config --global user.email contact@cyberill.com` (ou une seule
   autre adresse, mais une seule).
4. Ne plus jamais fusionner directement dans `main` : merge request + pipeline vert.
