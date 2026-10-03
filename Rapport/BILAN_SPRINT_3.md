# 🛡️ SENTRY — Bilan du Sprint 3 : M2 « Ingestion opérationnelle »

**Date :** 28/09/2026 · **Branche :** `feature/sprint3-ingestion` (base `202c6aa`)
**Rédaction :** Claude (Cowork), pour Godwill FOKA

---

## 1. Verdict

**Code du sprint : livré et vert. Jalon M2 : non atteint.**

Tout ce qui se programme pour M2 est fait (tâches 1.3 à 1.7, 1.9 partielle). Ce qui manque ne se
programme pas : le jalon exige des IOC **réels**, collectés avec **vos** clés, et une source STIX
opérationnelle. `sentry status` le constate en base ; tant qu'il affiche ✘, M2 n'est pas clos.

## 2. But et objectif mesurable (rappel)

Des IOC réels, de plusieurs sources, collectés sans intervention.
≥ 500 IOC réels issus d'au moins 3 sources dont OTX ; collecte automatique ; provenance
multi-sources.

## 3. Critères d'acceptation

| Critère M2 | Résultat | Preuve |
|---|---|---|
| Collecteur OTX connecté | 🟡 code prêt, non constaté | `tests/test_otx.py` (12 tests) ; constat : `sentry status` après `fetch` OTX avec clé |
| Flux STIX connecté | 🟡 analyseur prêt, aucune source réelle | `tests/test_feed_parsers.py` ; source STIX publique à choisir (tâche 1.8) |
| Déduplication fonctionnelle | ✅ | ADR-005 + `tests/test_indicators_service.py` |
| Provenance multi-sources | ✅ | `tests/test_indicator_sources.py`, migration `1f3dafc3008c` |
| Collecte sans intervention | ✅ code | `sentry feeds worker`, `tests/test_collect_scheduling.py` |
| 2 instances ne collectent jamais le même flux ensemble | ✅ | `test_verrou_redis_partage_entre_instances`, `test_flux_verrouille_ailleurs_saute` |
| Une ligne JSON par collecte | ✅ | `test_chaque_collecte_journalisee` |
| `last_error` réservé aux ADMIN | ✅ (livré en `202c6aa`) | `test_detail_d_erreur_reserve_aux_administrateurs` |
| ≥ 500 IOC réels | ❌ à constater | `sentry status` → « IOC issus de flux » |

## 4. Livrables par tâche

| # | Tâche | Contenu |
|---|---|---|
| 1.3 | Provenance | Table `indicator_sources` (clé IOC × flux, dates et compteur par source), upsert groupé `RETURNING`, reprise de l'existant par la migration, `sources` et `source_count` dans l'API, filtre `feed_id` étendu à toutes les sources |
| 1.4 | Connecteur OTX (T2.9) | `sentry/modules/threat_feeds/otx.py` : pagination, `modified_since` (marge 15 min), types OTX → types SENTRY, pulses inactifs ignorés, plafond `OTX_MAX_PAGES` signalé |
| 1.4 | Sécurité de la clé OTX | Flux OTX limité à `otx.alienvault.com` (service + API 422), liens `next` revérifiés, en-têtes jamais transmis sur redirection inter-hôtes, clé masquée dans les erreurs |
| 1.5 | Planificateur (T2.6) | `sentry feeds worker`, arrêt propre SIGTERM/Ctrl+C, survit aux pannes passagères ; verrou Redis `SET NX EX` + libération Lua par jeton ; repli local si Redis absent ; service `worker` Docker Compose |
| 1.6 | Journal JSON | `sentry/shared/logging.py` ; événements `feed.collected`, `feed.skipped_locked`, `worker.cycle`, `lock.redis_unavailable` |
| 1.9 | Mémoire | `peak_rss_mb` dans chaque ligne de journal ; mesure synthétique ci-dessous |
| — | Qualité | Test de conformité des CHECK **après migration** : comble le trou de `alembic check`, qui n'aurait pas vu l'ajout de `OTX` |
| — | Docs | ADR-006, CHANGELOG, README, `.env.example` |

## 5. Métriques

| Indicateur | `202c6aa` | Sprint 3 |
|---|---|---|
| Tests (PostgreSQL 16) | 256 | **289** (0 échec, 0 ignoré) |
| Couverture | 95 % | **95,7 %** |
| Python 3.12 / 3.14 | ✅ / ✅ | ✅ / ✅ |
| `ruff` / `mypy --strict` / `alembic check` | ✅ | ✅ |
| Migrations | 2 | **3** (montée, descente, remontée vérifiées) |
| Commandes CLI | 14 | **15** |
| ADR | 5 | **6** |

**Mémoire et débit (tâche 1.9, mesure synthétique, poste de développement, PostgreSQL local) :**
collecte d'un CSV de 20 000 URL (1,3 Mo) : **pic RSS 91 Mo** (cible RNF-MEM-01 ≤ 256 Mo),
11,2 s en première ingestion, 13,8 s en ré-ingestion (≈ 1 500 à 1 800 IOC/s). Confiance
moyenne : mesure unique, hors conteneur, sans l'API en parallèle. À refaire sur la vraie
collecte OTX (valeur `peak_rss_mb` du journal).

## 6. Défauts

**Corrigé côté poste de travail.** Les 15 échecs de votre `pytest` (`ResponseValidationError`,
`FeedReadAdmin`) venaient d'une modification locale non commitée de `sentry/app/api/v1/feeds.py`
sur la branche `security/feed-last-error` (partie de `2b0bfaf`) : les routes déclaraient
`FeedReadAdmin` (qui exige `last_error`) mais renvoyaient `FeedRead` (qui ne l'a pas). Ce travail
est déjà fait, testé, dans `202c6aa` (schéma unique + masquage pour les non-ADMIN). La procédure
abandonne la modification locale et récupère `202c6aa`.

**Connus, non bloquants :**

| Défaut | Risque | Traitement |
|---|---|---|
| OTX tronqué à `OTX_MAX_PAGES` : le curseur avance, les pages restantes sont manquées | Perte de pulses anciens à la 1re collecte d'un compte très abonné | Monter `OTX_MAX_PAGES` pour la 1re collecte ; avertissement journalisé |
| Collecte > 15 min : le verrou expire, un 2e worker peut doubler | `hit_count` gonflé, quota source | `COLLECT_LOCK_TTL_SECONDS` ; renouvellement du verrou si besoin |
| Redis absent : verrou local seulement | Doublons entre instances | Avertissement `lock.redis_unavailable` ; Redis requis en production |
| DNS rebinding résiduel (T2.3) | SSRF faible | Épingler l'IP avant multi-tenant |
| Pas de limitation des tentatives de connexion | Force brute | Avant exposition publique |

## 7. SWOAT

| | |
|---|---|
| **Forces** | Collecte complète et autonome sans dépendance nouvelle ; clé OTX protégée à trois niveaux ; provenance exploitable (base d'un score de confiance) ; mémoire mesurée très en dessous de la cible |
| **Faiblesses** | Aucune donnée réelle encore ; pas de source STIX identifiée ; `main` toujours sans le travail des sprints 2 et 3 |
| **Opportunités** | `source_count` → score de confiance IOC, argument différenciant face à MISP/OpenCTI ; worker prêt pour la collecte NVD/EPSS/KEV de la phase 3 |
| **Menaces** | Conditions des API gratuites (abuse.ch a changé en 2025, OTX peut limiter) ; dérive calendaire (v1.0 prévue au 30/09 dans le README, irréaliste) |
| **Axes d'action** | Pousser et fusionner maintenant ; créer les clés ; constater M2 ; accepter ADR-004/005/006 |

## 8. Décisions

- **Prises (à valider)** : ADR-006 — table `indicator_sources`, OTX comme format de flux,
  worker intégré + verrou Redis, journal JSON.
- **En attente de votre décision** : ADR-004 (recalage planning), ADR-005 (cycle de vie IOC),
  ADR-006. Choix de la source STIX (tâche 1.8).

## 9. Étape suivante

**Clore M2 (cible 08/10/2026)** : clés abuse.ch et OTX dans `.env`, `sentry seed`,
`sentry feeds worker` 24 h, `sentry status` tout en ✔, tag `v0.2.0`, `Rapport/BILAN_PHASE_2.md`.
Puis **phase 3 — CVE** (NVD 2.0, KEV, EPSS) : le worker et le journal servent tels quels.
