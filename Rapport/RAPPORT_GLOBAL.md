# 🛡️ SENTRY — Rapport global d'avancement

**Date :** 29/09/2026 · **Version publiée :** `0.1.0` (M1) · **Versions en préparation :**
`0.2.0` (M2) et `0.3.0` (M3)
**Périmètre :** du lancement du dépôt (21/09/2026) à la phase 3 codée

---

## 1. En une phrase

Les phases 1 à 3 sont codées et testées : SENTRY sait collecter du renseignement (7 sources,
5 formats), dédupliquer les IOC avec leur provenance, suivre les CVE (NVD, KEV, EPSS), les
prioriser et alerter. **Rien de cela n'est encore constaté sur données réelles ni fusionné dans
`main` au-delà de M1** : c'est le travail de la semaine, et il est entre vos mains (push, clés,
premier lancement).

## 2. Avancement par phase

Pourcentage = part des tâches du plan directeur livrées **et testées**. Un jalon n'est
« atteint » que constaté par `sentry status` sur données réelles.

| Phase | Code | Jalon | Avancement |
|---|---|---|---|
| P1 Foundation | ✅ | **M1 atteint** (`v0.1.0`, 24/09) | **100 %** |
| P2 Threat Feeds | ✅ | M2 à constater (clé OTX seule manquante) | **≈ 95 %** |
| P3 CVE Tracker | ✅ | M3 à constater (première synchro) | **≈ 90 %** |
| P4 Incidents | 🟡 machine d'état seule | — | ≈ 10 % |
| P5 SOC Dashboard | ❌ | — | 0 % |
| P6 Threat Hunting | ❌ | — | 0 % |
| **Global** (phases à poids égal) | | | **≈ 49 %** |

Confiance : moyenne. Les pourcentages de P2 et P3 comptent le constat sur données comme la part
restante (5 à 10 %) ; si une source réelle ne se comporte pas comme sa documentation, il faudra
un correctif, d'où l'écart entre P2 et P3 (P3 n'a jamais touché une vraie réponse NVD).

## 3. Ce que SENTRY fait aujourd'hui (branche `feature/phase3-cve`)

- Comptes et rôles (ADMIN, ANALYST, VIEWER), JWT, Argon2id.
- Sources de flux protégées contre le SSRF ; CSV, JSON, STIX 2.1, TAXII 2.1, OTX ; 7 sources de
  référence dont 5 sans clé ; secrets hors base et masqués.
- IOC normalisés, dédupliqués, expirés par type, avec provenance multi-sources.
- Moteur CVE : NVD 2.0 incrémental, catalogue KEV, EPSS ; score composite recalculé à chaque
  changement, priorité P0–P3 et délai de remédiation, historique d'audit.
- Alertes au franchissement du seuil, webhook, acquittement.
- Planificateur unique (`sentry feeds worker`) : flux en continu, CVE toutes les 6 h, verrou
  Redis, journal JSON.
- Mesure d'avancement : `sentry status` (critères M2 et M3).

## 4. Qualité

| Indicateur | M1 (`v0.1.0`) | 28/09 | Aujourd'hui |
|---|---|---|---|
| Tests (PostgreSQL 16, Python 3.12 et 3.14) | 95 | 289 | **326** |
| Couverture | 94 % | 95,7 % | **≈ 95 %** |
| Routes `/api/v1` | 3 | 10 | **14** |
| Commandes CLI | 9 | 15 | **19** |
| Migrations | 1 | 3 | **4** |
| ADR | 3 | 6 | **7** |
| Liste des CVE, P95 (30 000 CVE) | — | — | **8 ms** (cible 250 ms) |
| Pic mémoire (ingestion de 37 000 IOC réels) | — | 91 Mo | **120 Mo** (cible 256 Mo) |

## 5. Écart au planning

| Jalon | Plan initial | Plan recalé (ADR-004) | Constat au 29/09 |
|---|---|---|---|
| M1 Foundation | 05/08 | — | ✅ 24/09 |
| M2 Threat Feeds | 19/08 | 08/10 | code ✅, constat à faire |
| M3 CVE | 02/09 | 22/10 | code ✅ (en avance de 3 semaines), constat à faire |
| M4 Incidents | 16/09 | 05/11 | — |
| M5 Dashboard | 23/09 | 12/11 | — |
| v1.0 | 30/09 | 19/11 | — |

Le code est en avance sur le plan recalé ; l'intégration (push, CI GitLab, données réelles) est
en retard sur le code. Le risque de planning s'est déplacé : il ne tient plus à la vitesse de
développement, il tient au délai entre « codé » et « constaté ».

## 6. État du dépôt

- `main` (GitLab) = `3f9196f`.
- Votre poste : `security/feed-last-error` = `87bcca6` (sprint 2 + correctifs + e-mail auteur).
- Bundle `sentry-m2-phase3.bundle` : `feature/sprint3-m2` et `feature/phase3-cve`, construits sur
  `87bcca6`. Procédure : `ETAPES_POUSSER_SUR_MAIN.md`.

## 7. Risques

| Risque | Niveau | Parade |
|---|---|---|
| Écart entre code et constat (3 phases hors `main`) | **Élevé** | Fusionner cette semaine, lancer le worker 24 h |
| Formats réels NVD / TAXII non éprouvés | Moyen | Premier `sentry cves sync` suivi de près ; sources isolées (une panne n'arrête pas les autres) |
| Sources gratuites instables (DigitalSide, Feodo quasi vide, conditions abuse.ch) | Moyen | 7 sources ; `sentry status` signale les sources dégradées |
| Sécurité avant exposition publique (force brute, DNS rebinding) | Moyen | Traités avant toute mise en ligne |
| Copies de travail multiples (Kali, OneDrive, bundles) | Moyen | Une seule copie de travail, OneDrive en lecture |

## 8. Perspectives

1. **Cette semaine** : fusion des deux branches, clés NVD et OTX, worker 24 h, M2 puis M3
   constatés, tags `v0.2.0` et `v0.3.0`.
2. **Octobre** : phase 4 (incidents, chronologie immuable, liaison aux alertes CVE et aux IOC).
3. **Novembre** : dashboard SOC, threat hunting, v1.0 le 19/11.
4. **Au-delà** : score de confiance IOC par provenance, rapprochement CVE ↔ IOC, assistant IA.

## 9. Décisions attendues de votre part

1. Accepter ou amender ADR-004, 005, 006 et 007.
2. Choisir le canal d'alerte (webhook).
3. Protéger `main` sur GitLab (fusion par merge request uniquement).
