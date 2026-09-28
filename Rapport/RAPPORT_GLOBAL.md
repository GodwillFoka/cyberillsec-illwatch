# 🛡️ SENTRY — Rapport global d'avancement

**Date :** 28/09/2026 · **Version publiée :** `0.1.0` (M1) · **Version en préparation :** `0.2.0` (M2)
**Périmètre :** du lancement du dépôt (21/09/2026) à la fin du Sprint 3

---

## 1. En une phrase

Le socle technique (phase 1) est clos, le module de collecte de renseignement (phase 2) est
entièrement codé et testé mais **pas encore constaté sur données réelles ni fusionné dans `main`** ;
les phases 3 à 6 n'ont que leurs briques de calcul. Le calendrier initial (v1.0 au 30/09/2026)
est hors d'atteinte ; le calendrier recalé (v1.0 au 19/11/2026, ADR-004) reste tenable si M2 est
constaté avant le 08/10.

## 2. Avancement par phase

Pourcentage = part des tâches du plan directeur livrées **et testées**. Un jalon n'est « atteint »
que constaté sur données (`sentry status`) ou en pipeline GitLab.

| Phase | Périmètre | Code | Jalon | Avancement |
|---|---|---|---|---|
| P1 Foundation | Config, base, auth JWT, CLI, migrations, CI | ✅ | **M1 atteint** (tag `v0.1.0`, 24/09) | **100 %** |
| P2 Threat Feeds | CRUD flux, collecte CSV/JSON/STIX/OTX, IOC, provenance, worker | ✅ | M2 non constaté | **≈ 85 %** |
| P3 CVE Tracker | NVD, KEV, EPSS, score, alerting | 🟡 score composite seul | — | ≈ 15 % |
| P4 Incidents | Machine d'état NIST, timeline, API | 🟡 machine d'état seule | — | ≈ 10 % |
| P5 SOC Dashboard | Agrégations, exports | ❌ | — | 0 % |
| P6 Threat Hunting | Moteur de règles | ❌ | — | 0 % |
| **Global** (phases à poids égal) | | | | **≈ 35 %** |

Confiance : moyenne. Le poids égal des phases est une convention ; pondéré par l'effort estimé
du Cahier des charges, le résultat serait proche (P2 et P3 sont les plus lourdes). Les 15 % restants
de P2 : données réelles (clés), source STIX (1.8), fusion dans `main`, tag `v0.2.0`.

## 3. Ce que SENTRY fait aujourd'hui (branche `feature/sprint3-ingestion`)

- Comptes, rôles ADMIN / ANALYST / VIEWER, jetons JWT, mots de passe Argon2id.
- Sources de flux gérées par API et CLI, protégées contre le SSRF (HTTPS public, DNS vérifié,
  redirections revalidées, taille bornée).
- Collecte CSV, JSON, STIX 2.1 et AlienVault OTX ; secrets hors base, masqués dans les erreurs.
- IOC normalisés et dédupliqués, expiration par type, provenance multi-sources.
- Collecte planifiée (`sentry feeds worker`), verrou Redis par flux, journal JSON.
- Mesure d'avancement sur données : `sentry status`.
- Score de risque CVE (formule ADR-001) et machine d'état des incidents, prêts à brancher.

## 4. Qualité

| Indicateur | M1 (`v0.1.0`) | Aujourd'hui |
|---|---|---|
| Tests (PostgreSQL 16) | 95 | **289** |
| Couverture | 94 % | **95,7 %** |
| Routes API | 3 | 11 |
| Commandes CLI | 9 | 15 |
| Migrations | 1 | 3 |
| ADR | 3 | 6 |
| Lint, typage strict, `alembic check`, Python 3.12 + 3.14 | ✅ | ✅ |
| Mémoire (collecte de 20 000 IOC) | — | pic 91 Mo (cible ≤ 256 Mo) |

## 5. Écart au planning

| Jalon | README (plan initial) | Plan recalé (ADR-004) | Constat au 28/09 |
|---|---|---|---|
| M1 Foundation | 05/08 | — | ✅ 24/09 |
| M2 Threat Feeds | 19/08 | 08/10 | code prêt, à constater |
| M3 CVE | 02/09 | 22/10 | — |
| M4 Incidents | 16/09 | 05/11 | — |
| M5 Dashboard | 23/09 | 12/11 | — |
| v1.0 | 30/09 | 19/11 | — |

Lecture franche : le plan initial supposait un démarrage début juillet ; le dépôt existe depuis le
21/09. Le retard est un décalage de démarrage plus qu'une vélocité insuffisante : P1 et P2 ont
été codées en huit jours. Le risque réel est ailleurs (section 7). Le tableau « Feuille de route »
du README doit être aligné sur ADR-004 dès que vous l'acceptez.

## 6. État du dépôt GitLab

- `main` = `3f9196f` (M1 + contraintes). **Aucun travail des sprints 2 et 3 n'y est.**
- `origin/feature/threat-feeds-indicators` = `0ec2a6e`. Les 9 commits jusqu'à `202c6aa` sont dans
  le bundle, pas encore poussés.
- Sur votre poste : branche locale `security/feed-last-error` (à `2b0bfaf`) avec une
  modification non commitée de `feeds.py` — cause des 15 tests en échec, et doublon de `202c6aa`.
- Procédure de remise en ordre et de fusion : `ETAPES_POUSSER_SUR_MAIN.md` (livré à côté du bundle).

## 7. Risques

| Risque | Niveau | Parade |
|---|---|---|
| Travail non fusionné qui s'accumule (2 sprints hors `main`) | **Élevé** | Fusionner `202c6aa` aujourd'hui, puis le Sprint 3 par MR |
| Copies de travail divergentes (Kali, OneDrive, bundles) | Élevé | Une seule copie de travail (Kali), OneDrive en lecture seule |
| Dépendance aux API gratuites (abuse.ch, OTX, NVD) | Moyen | Connecteurs isolés, erreurs tracées, `sentry status` |
| Périmètre (branding, documents annexes) | Moyen | Geler le périmètre v1.0 |
| Sécurité avant exposition publique (force brute, DNS rebinding) | Moyen | Traités avant toute mise en ligne (étape 4) |

## 8. Perspectives

1. **Semaine 40 (29/09–04/10)** : fusion dans `main`, clés, collecte réelle 24 h, M2 constaté,
   `v0.2.0`.
2. **Semaines 41–42** : phase 3 (NVD 2.0, KEV, EPSS, recalcul du score, alerting). Le worker et
   le journal JSON sont réutilisables tels quels.
3. **Novembre** : incidents, dashboard, threat hunting, v1.0 le 19/11 si la cadence tient.
4. **Au-delà** : score de confiance IOC fondé sur la provenance, assistant IA, multi-tenant.

## 9. Décisions attendues de votre part

1. Accepter ou amender ADR-004 (planning), ADR-005 (cycle de vie IOC), ADR-006 (provenance, OTX,
   worker).
2. Choisir une source STIX publique pour le critère M2 (ou un serveur TAXII, tâche 1.8).
3. Protéger `main` sur GitLab (fusion par MR uniquement).
