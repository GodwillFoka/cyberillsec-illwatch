# ILLWATCH — État d'avancement des travaux

**Document vivant**, mis à jour à chaque étape. Dernière mise à jour : **08/10/2026, 21 h 30**.
Les rapports datés (`NN_JJ-MM-AAAA.md`) figent l'état d'une semaine ; celui-ci donne l'état courant.

## 1. Position

> **08/10 — SENTRY devient ILLWATCH** (nom « Sentry » déjà pris). Bascule terminée : code
> renommé (`4c1e220`), dépôts GitHub et GitLab renommés, poste Kali migré sans perte (13 tables, comptages
> identiques) dans le dossier `cyberillsec-illwatch` ; scénario SOC **48/48** sous ILLWATCH.

ILLWATCH est dans le jalon **M7 — Production Hardening**, premier des cinq jalons menant à la
v0.2.0 (M7 → M8 → M9 → M10 → M11). Les lots 1 à 3 de M7 sont codés et fusionnés ; **reste le
déploiement de préproduction sur un VPS européen** pour clore M7. M1 à M6 sont constatés sur
données réelles, en local et en CI.

## 2. Jalons

| Jalon | État | Constat |
|---|---|---|
| M1 Foundation | ✅ | local et CI |
| M2 Threat Feeds | ✅ | atteint pour la première fois le 06/10 (OTX et STIX connectés), local et CI |
| M3 Moteur CVE | ✅ | KEV 1 734, EPSS ≥ 94 %, 495 CVE en P0 |
| M4 Incidents | ✅ | incident mené jusqu'à la clôture |
| M5 Dashboard | ✅ | scénario SOC 48/48 |
| M6 Hunting | ✅ | 339 correspondances en CI |
| **M7 Production Hardening** | 🟡 en cours | lots 1-3 fusionnés ; performances gros volume traitées ; ADR-014 appliqué ; analyses de sécurité constatées (image 0 Critical, SAST 0, secrets 0) ; **reste uniquement le VPS UE** |
| M8 Detection & Correlation | ⏳ | — |
| M9 à M11 | ⏳ | opérer, contextualiser, exploiter |

## 3. Chantier en cours

| Chantier | Branche | État |
|---|---|---|
| **Interface web** | `bb102d3` | ✅ maquette v6 adoptée, ADR-016 accepté ; ✅ lot 1 côté serveur fusionné (journal des collectes, séries temporelles, flux SSE) ; ⏳ socle `frontend/` et écrans |
| **Renommage SENTRY → ILLWATCH** | `d92b8c9` | ✅ code (162 fichiers, CI 463/463, validation réelle verte) ; dépôt GitHub renommé ; Kali migré : 528 453 IOC et 26 416 CVE retrouvés, volumes à nom fixe, dossier renommé, scénario 48/48 |
| Performances sur gros volume (export, tableau de bord) | `5b55f64` | ✅ fusionné et mesuré : tableau de bord 3,9 s → 0,5 s ; export IOC 89 s → 13 à 17 s |
| Analyse d'image (Container Scanning GitLab) | `a2fb367` | ✅ constaté sur `56ab581` : 0 Critical ; High 52 → 44, total 240 → 165 (−31 %) ; 44 High Debian sans correctif acceptées |
| Analyse de code (SAST Semgrep GitLab) | `56ab581` | ✅ constaté : **0 constat** ; concorde avec bandit (CI GitHub) |
| Détection de secrets (historique Git) | `56ab581` | ✅ fusionné : 17 constats gitleaks, tous faux positifs ; gitleaks à chaque push (CI GitHub) |
| Rattrapage de l'historique OTX (Kali) | — | ✅ historique entièrement lu le 07/10 ; collecte incrémentale ensuite |
| ADR-014 (score sans EPSS, plancher KEV) | `ad69dc6` | ✅ accepté (A + B + C), fusionné, appliqué sur Kali : 612 CVE reclassées, P1 627 → 1 239, **0 CVE KEV en P2/P3** |

## 4. Journal des livraisons

| Date | Commit | Contenu |
|---|---|---|
| 08/10 | `bb102d3` | Lot 1 serveur (PR #1) : `collection_runs`, `/feeds/health`, `/feeds/{id}/runs`, `/dashboard/timeseries`, flux SSE `/stream` et bus Redis ; 2 migrations |
| 08/10 | `9f7fe1f` | ADR-016 interface web, système de design v6 |
| 08/10 | `d92b8c9` | Projet Compose et volumes à nom fixe : dossier du dépôt renommable sans perte |
| 08/10 | `57f42fc` | Script de migration : comparaison triée (fausse alerte corrigée), retour arrière fiable |
| 08/10 | `4c1e220` | SENTRY → ILLWATCH : paquet, CLI, variables `ILLWATCH_*`, base `illwatch`, infra, docs, logo ; script de migration |
| 07/10 | `56ab581` | Fusion : détection de secrets gitleaks en CI ; anciennes branches supprimées |
| 07/10 | `a2fb367` | Fusion : image sans curl |
| 07/10 | `62b7bf0` | Image sans curl, sonde de santé en Python, risque résiduel documenté |
| 07/10 | `ad69dc6` | Fusion ADR-014 ; reclassement Kali : 612 changements, constaté |
| 07/10 | `6d0ff40` | ADR-014 : plancher KEV ⇒ P1, motif `+floor_kev`, `illwatch cves rescore`, test panne EPSS |
| 07/10 | `5b55f64` | État d'avancement vivant créé |
| 07/10 | `3422168` | Export par clé au lieu d'`OFFSET`, envoi par paquets ; tableau de bord en 2 lectures au lieu de 5 |
| 07/10 | `fa73bd6` | URL au port invalide rejetée seule (bloquait le rattrapage OTX de nuit) |
| 06/10 | `c11f00f` | Collecte OTX : reprise des collectes tronquées ou interrompues, message NVD |
| 06/10 | `bdb4bc8` | Rapport du 06/10 (soirée), Markdown et PDF |
| 06/10 | `595d425` | Clone neuf : tests isolés du `.env`, `set-password`, messages |

## 5. Indicateurs

| Indicateur | Valeur | Date |
|---|---|---|
| Tests (CI) | 463 / 463, Python 3.12 et 3.14 | 08/10 (`4c1e220`) |
| Couverture | 93-94 % (seuil 80 %) | 07/10 |
| Scénario SOC | 48 / 48 sous ILLWATCH, local (gros volume) et CI | 08/10 |
| Sources saines | 7 / 9 (DigitalSide hors ligne depuis le 29/09) | 06/10 |
| IOC en base (Kali) | 528 453, dont 334 311 actifs ; 787 confirmés par ≥ 2 sources | 08/10 |
| CVE en base (Kali) | 26 416 : P0 495 · P1 1 239 · P2 36 · P3 24 646 ; KEV 1 734, toutes ≥ P1 | 07/10 |

## 6. Performances (528 453 IOC, poste Kali, 08/10 sous ILLWATCH)

| Appel | Avant (07/10) | Après correctif | Cible |
|---|---|---|---|
| Export des IOC | 89 s | **12,0 s** (max 12,7 s) ✔ | < 15 s |
| Tableau de bord | 2,0 à 3,9 s | **0,63 s** (max 1,06 s) ✔ | < 1 s |
| Chasse sur la base complète | 5,7 s | 7,4 s (334 311 IOC actifs, 345 corresp.) | < 10 s ✔ |
| Export des CVE | 4,4 s | **1,5 s** (max 1,6 s) ✔ | < 5 s |
| Autres appels | < 0,6 s | — | ✔ |

## 7. Risques et points ouverts

| Point | Impact | Action | État |
|---|---|---|---|
| Export des IOC proche de la cible (12,0 s pour 528 453 IOC) | croît avec la base | sérialisation à optimiser en M8 si besoin | 🟡 à surveiller |
| 612 CVE exploitées (KEV) en P2/P3 | non conforme à la BOD 22-01 | ADR-014 appliqué : 0 CVE KEV sous P1 | ✅ |
| Plages CIDR rejetées (1 640 chez RedEye) | information perdue | type « réseau » au backlog M8 | ⏳ |
| Image : 44 High Debian sans correctif (165 au total, 0 Critical) | non exposées, processus non privilégié | acceptées et documentées (OPERATIONS § 7 quinquies) ; revue à chaque analyse | ✅ accepté |
| Secrets dans l'historique Git | fuite de clés | gitleaks : 0 vrai secret sur 79 commits ; contrôle ajouté à chaque push | ✅ |
| Analyse de code | vulnérabilités applicatives | SAST Semgrep GitLab : 0 constat (`56ab581`) ; bandit vert | ✅ |
| Branches GitHub `feature/m7-production-hardening`, `maj/2026-10-06` | aucune (entièrement contenues dans `main`) | supprimées le 07/10 | ✅ |
| Anciens volumes SENTRY sur Kali | espace disque | supprimés le 08/10 ; dernière sauvegarde `~/illwatch-migration/sentry.dump` conservée | ✅ |
| Dépôt GitLab à renommer | liens de la documentation | renommé, `main` synchronisé (`955e2a1`) | ✅ |
| Horloge de la VM Kali décalée de 6 h | journaux trompeurs | régler le fuseau de la VM | ⏳ |
| Limites de débit GitLab au 19/10 | sans effet au rythme actuel | à surveiller | — |

## 8. Prochaines étapes

Décision du 08/10 : **l'interface web passe avant l'hébergement**. La préproduction se fera avec
l'interface en place.

1. **Interface web v1, lot 1** — maquette v6 **adoptée**, ADR-016 accepté, système de design
   documenté (`docs/DESIGN_SYSTEM.md`). Côté serveur **fait** (journal de collecte, séries
   temporelles, flux SSE). À développer : socle `frontend/` (Vite, TypeScript, TanStack Query,
   types générés depuis OpenAPI, image Docker), puis Vue d'ensemble, Triage, IOC, CVE, Incidents,
   Investigation, Chasse. Sur Kali : `git pull` puis `alembic upgrade head`.
2. Préproduction VPS UE (SSL Labs ≥ A, 7 jours de collecte) → **clôture de M7**.
3. Ouvrir M8 Detection & Correlation.
