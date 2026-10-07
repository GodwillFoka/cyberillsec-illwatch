# SENTRY — État d'avancement des travaux

**Document vivant**, mis à jour à chaque étape. Dernière mise à jour : **07/10/2026, 19 h 05**.
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
| **M7 Production Hardening** | 🟡 en cours | lots 1-3 fusionnés ; export 7× plus rapide ; **VPS UE à faire** |
| M8 Detection & Correlation | ⏳ | — |
| M9 à M11 | ⏳ | opérer, contextualiser, exploiter |

## 3. Chantier en cours

| Chantier | Branche | État |
|---|---|---|
| Performances sur gros volume (export, tableau de bord) | `5b55f64` | ✅ fusionné ; export 89 s → 12,9 s ; tableau de bord à confirmer |
| Rattrapage de l'historique OTX (Kali) | — | 🟡 interrompu par erreur le 07/10 à 18 h 50 (`kill %1`), à relancer |

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
| Scénario SOC | 48 / 48, local et CI | 07/10 |
| Sources saines | 7 / 9 (DigitalSide hors ligne depuis le 29/09) | 06/10 |
| IOC en base (Kali) | 480 669, dont 305 286 actifs | 07/10 |
| CVE en base (Kali) | ≈ 25 700, dont 495 en P0 | 06/10 |

## 6. Performances (480 669 IOC, poste Kali)

| Appel | Avant (07/10) | Après correctif | Cible |
|---|---|---|---|
| Export des IOC | 89 s | **12,9 s** (max 13,4 s) ✔ | < 15 s |
| Tableau de bord | 2,0 à 3,9 s | *à mesurer* | < 1 s |
| Chasse sur la base complète | 5,7 s | 5,8 s (inchangé) | < 10 s ✔ |
| Export des CVE | 4,4 s | *à mesurer* | < 5 s ✔ |
| Autres appels | < 0,6 s | — | ✔ |

## 7. Risques et points ouverts

| Point | Impact | Action | État |
|---|---|---|---|
| Export et tableau de bord lents | préproduction compromise | `5b55f64` : export ✔, tableau de bord à mesurer | 🟡 |
| ADR-014 non tranché | sans EPSS, aucune CVE en P0 | décision | ⏳ |
| Plages CIDR rejetées (1 640 chez RedEye) | information perdue | type « réseau » au backlog M8 | ⏳ |
| Analyses de sécurité GitLab non vérifiées sur M7 | SAST, secrets, dépendances | consulter *Build → Pipelines* | ⏳ |
| Branches GitHub `feature/m7-production-hardening`, `maj/2026-10-06` | non ancêtres de `main` | vérifier leur contenu avant suppression | ⏳ |
| Horloge de la VM Kali décalée de 6 h | journaux trompeurs | régler le fuseau de la VM | ⏳ |
| Limites de débit GitLab au 19/10 | sans effet au rythme actuel | à surveiller | — |

## 8. Prochaines étapes

1. Mesurer le tableau de bord après `5b55f64` (sans collecte en parallèle).
2. Relancer et finir le rattrapage OTX (Kali).
3. Trancher l'ADR-014.
4. Préproduction VPS UE (SSL Labs ≥ A, 7 jours de collecte) → **clôture de M7**.
5. Ouvrir M8 Detection & Correlation.
