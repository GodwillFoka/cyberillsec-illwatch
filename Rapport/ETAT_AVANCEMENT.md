# SENTRY — État d'avancement des travaux

**Document vivant**, mis à jour à chaque étape. Dernière mise à jour : **07/10/2026, 22 h 45**.
Les rapports datés (`NN_JJ-MM-AAAA.md`) figent l'état d'une semaine ; celui-ci donne l'état courant.

## 1. Position

SENTRY est dans le jalon **M7 — Production Hardening**, premier des cinq jalons menant à la
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
| **M7 Production Hardening** | 🟡 en cours | lots 1-3 fusionnés ; performances gros volume traitées ; ADR-014 à trancher ; **VPS UE à faire** |
| M8 Detection & Correlation | ⏳ | — |
| M9 à M11 | ⏳ | opérer, contextualiser, exploiter |

## 3. Chantier en cours

| Chantier | Branche | État |
|---|---|---|
| Performances sur gros volume (export, tableau de bord) | `5b55f64` | ✅ fusionné et mesuré : tableau de bord 3,9 s → 0,5 s ; export IOC 89 s → 13 à 17 s |
| Rattrapage de l'historique OTX (Kali) | — | ✅ historique entièrement lu le 07/10 ; collecte incrémentale ensuite |
| ADR-014 (score sans EPSS, plancher KEV) | — | 🟡 chiffré sur la base réelle, **décision attendue** |

## 4. Journal des livraisons

| Date | Commit | Contenu |
|---|---|---|
| 07/10 | `5b55f64` | État d'avancement vivant créé |
| 07/10 | `3422168` | Export par clé au lieu d'`OFFSET`, envoi par paquets ; tableau de bord en 2 lectures au lieu de 5 |
| 07/10 | `fa73bd6` | URL au port invalide rejetée seule (bloquait le rattrapage OTX de nuit) |
| 06/10 | `c11f00f` | Collecte OTX : reprise des collectes tronquées ou interrompues, message NVD |
| 06/10 | `bdb4bc8` | Rapport du 06/10 (soirée), Markdown et PDF |
| 06/10 | `595d425` | Clone neuf : tests isolés du `.env`, `set-password`, messages |

## 5. Indicateurs

| Indicateur | Valeur | Date |
|---|---|---|
| Tests (CI) | 454 / 454, Python 3.12 et 3.14 | 07/10 (`fa73bd6`) |
| Couverture | 93-94 % (seuil 80 %) | 07/10 |
| Scénario SOC | 48 / 48, local (gros volume) et CI | 07/10 |
| Sources saines | 7 / 9 (DigitalSide hors ligne depuis le 29/09) | 06/10 |
| IOC en base (Kali) | 480 669, dont 305 286 actifs | 07/10 |
| CVE en base (Kali) | 26 416 : P0 495 · P1 627 · P2 638 · P3 24 656 ; KEV 1 734 | 07/10 |

## 6. Performances (480 669 IOC, poste Kali)

| Appel | Avant (07/10) | Après correctif | Cible |
|---|---|---|---|
| Export des IOC | 89 s | 12,9 s pendant la collecte ; **16,6 s** (max 17,0 s) au repos, base agrandie ⚠️ | < 15 s |
| Tableau de bord | 2,0 à 3,9 s | **0,51 s** (max 0,87 s) ✔ | < 1 s |
| Chasse sur la base complète | 5,7 s | 5,0 s | < 10 s ✔ |
| Export des CVE | 4,4 s | **2,0 s** (max 2,2 s) ✔ | < 5 s |
| Autres appels | < 0,6 s | — | ✔ |

## 7. Risques et points ouverts

| Point | Impact | Action | État |
|---|---|---|---|
| Export des IOC légèrement au-dessus de la cible (16,6 s) | acceptable derrière un proxy (délai > 60 s) | sérialisation à optimiser en M8 si besoin | 🟡 |
| ADR-014 non tranché | 612 CVE exploitées (KEV) en P2/P3, dont 10 en P3 ; une panne EPSS ferait tomber les 495 P0 | décision A + B + C recommandée | 🟡 |
| Plages CIDR rejetées (1 640 chez RedEye) | information perdue | type « réseau » au backlog M8 | ⏳ |
| Analyses de sécurité GitLab non vérifiées sur M7 | SAST, secrets, dépendances | consulter *Build → Pipelines* | ⏳ |
| Branches GitHub `feature/m7-production-hardening`, `maj/2026-10-06` | non ancêtres de `main` | vérifier leur contenu avant suppression | ⏳ |
| Horloge de la VM Kali décalée de 6 h | journaux trompeurs | régler le fuseau de la VM | ⏳ |
| Limites de débit GitLab au 19/10 | sans effet au rythme actuel | à surveiller | — |

## 8. Prochaines étapes

1. Trancher l'ADR-014, puis coder la décision (plancher KEV, dernier EPSS connu).
2. Vérifier les analyses de sécurité GitLab sur `main`.
3. Préproduction VPS UE (SSL Labs ≥ A, 7 jours de collecte) → **clôture de M7**.
4. Ouvrir M8 Detection & Correlation.
