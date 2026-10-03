# 🛡️ SENTRY — Rapport global d'avancement

**Date :** 03/10/2026 · **Version publiée :** `0.1.0` (M1) · **Candidate :** `1.0.0-rc` sur
`feature/phases-4-6`
**Périmètre :** du lancement du dépôt (21/09/2026) au code complet des six modules

---

> **Mis à jour par l'audit du 03/10 après fusion :** `Rapport/ETAT_GLOBAL_SENTRY_2026-10-03.md`
> fait foi pour l'état de `main` (validation réelle, sécurité, dette).

## 1. En une phrase

Les six modules de SENTRY sont codés, intégrés et testés (388 tests sur PostgreSQL 16, 94 % de
couverture, `mypy --strict` propre) ; **seul M1 est fusionné dans `main` et constaté**. Le reste
du chemin vers la v1.0 tient à trois choses hors code : fusionner trois branches, obtenir deux
clés gratuites (RedEye, OTX), faire tourner le worker sur données réelles.

## 2. Avancement par phase

Deux colonnes distinctes, parce qu'elles mesurent deux choses différentes : **Code** = tâches du
plan directeur livrées et testées ; **Jalon** = critère constaté par `sentry status` sur données
réelles.

| Phase | Code | Jalon | Reste à faire |
|---|---|---|---|
| P1 Foundation | 100 % | ✅ **M1 atteint** (`v0.1.0`, 24/09) | — |
| P2 Threat Feeds | 100 % | à constater | clé OTX, jeton RedEye, worker 24 h |
| P3 CVE Tracker | 100 % | à constater | clé NVD, première synchro complète |
| P4 Incidents | ≈ 85 % | à constater | 3.6 liste d'exclusion des faux positifs |
| P5 SOC Dashboard | ≈ 70 % | à constater | séries 7 j, HTTPS, en-têtes, préproduction |
| P6 Threat Hunting | ≈ 75 % | à constater | guide de déploiement, audit de sécurité final |
| **Global code** (phases à poids égal) | **≈ 88 %** | **1 / 6** | |

Confiance : élevée sur le code (vérifié par la CI locale, deux versions de Python) ; moyenne sur
le temps restant, qui dépend de la tenue des sources gratuites et du comportement réel de NVD et
de RedEye, jamais éprouvés contre leurs vraies réponses.

## 3. Ce qui est fait, module par module

### MOD-01 Foundation
- Configuration Pydantic validée au démarrage, secrets uniquement dans `.env`, masqués partout.
- PostgreSQL 16 en async (SQLAlchemy 2 + asyncpg), 6 migrations Alembic, 14 tables, contraintes
  CHECK nommées.
- Comptes et rôles (ADMIN, ANALYST, VIEWER), JWT, Argon2id ; limitation des tentatives de
  connexion (5 par compte, 20 par IP sur 15 min, Redis avec repli local, réponse 429 +
  `Retry-After`).
- CLI Click + Rich (34 commandes) ; `sentry status` mesure les jalons sur la base réelle.

### MOD-02 Threat Feeds
- Formats : CSV, JSON, texte, STIX 2.1, TAXII 2.1, AlienVault OTX.
- Client TAXII sur `taxii2-client` 2.3.0, **durci** : redirections interdites, délai, taille de
  réponse plafonnée, contrôle SSRF, authentification par hôte exact (basic, bearer, en-tête),
  pagination plafonnée, `added_after` incrémental.
- Protection SSRF sur toute URL de source (résolution DNS + refus des plages privées).
- IOC normalisés, dédupliqués, expirés selon leur type, provenance multi-sources.
- Sources vérifiées avant intégration (`sentry taxii discover`, `sentry feeds probe`).

### MOD-03 CVE Tracker
- NVD 2.0 incrémental, catalogue CISA KEV, FIRST EPSS.
- Score composite déterministe 0–100 (ADR-001), recalculé à chaque changement d'entrée,
  priorité P0–P3 et délai de remédiation, historique d'audit des scores.
- Alertes au franchissement de seuil, webhook, acquittement.

### MOD-04 Incidents
- Machine d'état NIST SP 800-61 à 6 étapes ; transition interdite → 409 ; post-mortem
  obligatoire à la clôture.
- Chronologie **immuable garantie par la base** (trigger plpgsql) et par l'ORM.
- Liaisons incident ↔ IOC et incident ↔ CVE ; ouverture depuis une alerte, idempotente.

### MOD-05 SOC Dashboard
- Synthèse temps réel, activité des dernières 24 h, console Rich.
- Exports JSON et CSV en flux (mémoire constante), CSV protégé contre l'injection de formules.

### MOD-06 Threat Hunting
- Six règles (Tor, DNS dynamique, DGA par entropie de Shannon, IP ransomware, CVE exploitable ×
  inventaire, IOC connu) ; chasse sur observables ou sur la base.
- Sessions et correspondances enregistrées ; une règle en échec n'arrête pas les autres.
- Chasse planifiée par le worker unique (flux, CVE et chasse sous un même verrou Redis).

## 4. Méthodes utilisées

| Méthode | Application dans SENTRY |
|---|---|
| Clean Architecture | couches strictes clients → contrôleurs → services → accès aux données ; logique métier sans dépendance HTTP, testable seule |
| Décisions tracées (ADR) | 10 ADR : scoring, hébergement, auth, recalage du planning, cycle de vie IOC, provenance, moteur CVE, incidents, hunting, client TAXII |
| Tests d'abord sur le risque | tests contre un vrai PostgreSQL (pas de SQLite de substitution) ; faux serveurs HTTP pour TAXII/NVD ; tests réels isolés par marqueur `live` |
| Sécurité dès la conception | SSRF, secrets hors base, Argon2id, limitation de débit, CWE-1236, immutabilité par trigger, revue des régressions introduites par une bibliothèque tierce |
| Qualité outillée | `ruff` (lint + format), `mypy --strict`, couverture ≥ 80 % imposée, matrice Python 3.12 / 3.14 |
| Intégration continue GitLab | qualité, tests, migrations aller-retour, image Docker, SAST, détection de secrets, analyse de dépendances |
| Vérifier avant d'intégrer | chaque source de renseignement sondée avant d'entrer dans le seed |
| Pilotage par jalons constatés | un jalon n'est « atteint » que mesuré par `sentry status` sur données réelles |
| Branches de fonctionnalité + MR | aucune écriture directe sur `main` ; livraison par bundles Git avec procédure |

## 5. Qualité

| Indicateur | M1 (24/09) | 29/09 | **03/10** | Cible |
|---|---|---|---|---|
| Tests | 95 | 326 | **388** | — |
| Couverture | 94 % | ≈ 95 % | **94 %** | ≥ 80 % |
| Routes `/api/v1` | 3 | 14 | **28** | — |
| Commandes CLI | 9 | 19 | **34** | — |
| Tables / migrations | — / 1 | 10 / 4 | **14 / 6** | — |
| ADR | 3 | 7 | **10** | — |
| Liste des CVE, P95 (30 000 CVE) | — | 8 ms | 8 ms | 250 ms |
| Pic mémoire (37 000 IOC réels) | — | 120 Mo | 120 Mo | 256 Mo |

## 6. Écart au planning

| Jalon | Plan initial | Plan recalé (ADR-004) | Constat au 03/10 |
|---|---|---|---|
| M1 Foundation | 05/08 | — | ✅ 24/09 |
| M2 Threat Feeds | 19/08 | 08/10 | code ✅, constat à faire |
| M3 CVE | 02/09 | 22/10 | code ✅, constat à faire |
| M4 Incidents | 16/09 | 05/11 | code ✅ (≈ 5 semaines d'avance) |
| M5 Dashboard | 23/09 | 12/11 | code partiel |
| v1.0 | 30/09 | 19/11 | code partiel |

Le développement a rattrapé et dépassé le plan recalé. Le goulot est désormais l'intégration :
trois branches empilées hors `main`, aucune donnée réelle en base de préproduction.

## 7. État du dépôt

- `main` (GitLab) : M1.
- Votre poste : `feature/sprint3-m2` = `cb74ae7` (= `9402bb1` + dossier `Bubble/`).
- Bundle `sentry-v1-candidate.bundle` (prérequis `9402bb1`) : `feature/taxii-v2`,
  `feature/phase3-cve-v2`, `feature/phases-4-6`. Procédure : `ETAPES_POUSSER_SUR_MAIN.md`.

## 8. Risques

| Risque | Niveau | Parade |
|---|---|---|
| Écart entre code et constat (5 phases hors `main`) | **Élevé** | fusion cette semaine, worker 24 h |
| Une seule source STIX/TAXII exploitable, sous jeton | Moyen | jeton RedEye ; OTX en complément ; client prêt pour CrowdSec si budget |
| Formats réels NVD / RedEye non éprouvés | Moyen | tests `live` + `sentry feeds probe` avant activation |
| Exposition publique sans HTTPS ni en-têtes | Moyen | tâche 4.5 avant toute mise en ligne |
| Faux positifs DGA non mesurés | Faible | calibration sur un corpus réel (Tranco + DGArchive) |
| Copies de travail multiples (Kali, OneDrive, bundles) | Moyen | une seule copie de travail sous Git |

## 9. Lignes à venir

**Court terme (d'ici la v1.0, 19/11)**
1. Fusion, clés, worker 24 h ; M2 et M3 constatés, tags `v0.2.0`, `v0.3.0`.
2. Liste d'exclusion des faux positifs reliée aux incidents (3.6) → `v0.4.0`.
3. Séries 7 jours glissants, HTTPS (reverse proxy), en-têtes de sécurité, préproduction sur VPS
   européen 7 jours (4.2, 4.5, 4.6) → `v0.5.0`.
4. Guide de déploiement, audit de sécurité final (`pip-audit`, SAST, revue des ADR) → `v1.0.0`.

**Après la v1.0**
- Score de confiance des IOC selon leur provenance et leur ancienneté.
- Rapprochement CVE ↔ IOC ↔ actifs via CPE (remplace l'appariement par mots de RULE-05).
- Règles de chasse au format Sigma ; import YARA.
- Export STIX 2.1 et serveur TAXII sortant (SENTRY devient producteur de renseignement).
- Assistant IA (LLM + RAG) pour résumer bulletins et incidents.
- Multi-tenant et SSO (OIDC), puis Cyberill TI Cloud hébergé en UE.

## 10. Perspectives

SENTRY vise un créneau réel : un outil CTI que peuvent faire tourner une PME, une ETI ou une
collectivité, dans moins de 256 Mo, sans licence à 40 000 € ni cluster à 16 Go. Les obligations
NIS 2 et DORA (veille active, notification sous 24 à 72 h) créent la demande ; la chronologie
immuable des incidents et le score déterministe répondent directement à l'exigence de
justification devant un auditeur. La condition pour que cette promesse tienne est de prouver
le fonctionnement sur données réelles pendant au moins sept jours consécutifs : c'est l'objet
des prochaines semaines.

## 11. Décisions attendues de votre part

1. Accepter ou amender ADR-008, 009 et 010.
2. Demander le jeton RedEye et la clé OTX.
3. Protéger `main` sur GitLab (fusion par merge request uniquement).
4. Choisir l'hébergeur de préproduction (VPS UE).
