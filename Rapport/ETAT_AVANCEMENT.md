# ILLWATCH — État d'avancement des travaux

**Document vivant**, mis à jour à chaque étape. Dernière mise à jour : **08/10/2026, 00 h 45**.
Les rapports datés (`NN_JJ-MM-AAAA.md`) figent l'état d'une semaine ; celui-ci donne l'état courant.

## 1. Position

> **08/10 — SENTRY devient ILLWATCH** (nom « Sentry » déjà pris). Code renommé et fusionné
> (`4c1e220`, CI et validation réelle vertes) ; reste à renommer les dépôts et à migrer le poste Kali.

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
| **Renommage SENTRY → ILLWATCH** | `4c1e220` | ✅ code fusionné : 162 fichiers, CI 463/463, validation réelle verte ; ⏳ dépôts à renommer, poste Kali à migrer (`scripts/migrer-vers-illwatch.sh`) |
| Performances sur gros volume (export, tableau de bord) | `5b55f64` | ✅ fusionné et mesuré : tableau de bord 3,9 s → 0,5 s ; export IOC 89 s → 13 à 17 s |
| Analyse d'image (Container Scanning GitLab) | `a2fb367` | ✅ constaté sur `56ab581` : 0 Critical ; High 52 → 44, total 240 → 165 (−31 %) ; 44 High Debian sans correctif acceptées |
| Analyse de code (SAST Semgrep GitLab) | `56ab581` | ✅ constaté : **0 constat** ; concorde avec bandit (CI GitHub) |
| Détection de secrets (historique Git) | `56ab581` | ✅ fusionné : 17 constats gitleaks, tous faux positifs ; gitleaks à chaque push (CI GitHub) |
| Rattrapage de l'historique OTX (Kali) | — | ✅ historique entièrement lu le 07/10 ; collecte incrémentale ensuite |
| ADR-014 (score sans EPSS, plancher KEV) | `ad69dc6` | ✅ accepté (A + B + C), fusionné, appliqué sur Kali : 612 CVE reclassées, P1 627 → 1 239, **0 CVE KEV en P2/P3** |

## 4. Journal des livraisons

| Date | Commit | Contenu |
|---|---|---|
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
| Scénario SOC | 48 / 48, local (gros volume) et CI | 07/10 |
| Sources saines | 7 / 9 (DigitalSide hors ligne depuis le 29/09) | 06/10 |
| IOC en base (Kali) | 480 669, dont 305 286 actifs | 07/10 |
| CVE en base (Kali) | 26 416 : P0 495 · P1 1 239 · P2 36 · P3 24 646 ; KEV 1 734, toutes ≥ P1 | 07/10 |

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
| 612 CVE exploitées (KEV) en P2/P3 | non conforme à la BOD 22-01 | ADR-014 appliqué : 0 CVE KEV sous P1 | ✅ |
| Plages CIDR rejetées (1 640 chez RedEye) | information perdue | type « réseau » au backlog M8 | ⏳ |
| Image : 44 High Debian sans correctif (165 au total, 0 Critical) | non exposées, processus non privilégié | acceptées et documentées (OPERATIONS § 7 quinquies) ; revue à chaque analyse | ✅ accepté |
| Secrets dans l'historique Git | fuite de clés | gitleaks : 0 vrai secret sur 79 commits ; contrôle ajouté à chaque push | ✅ |
| Analyse de code | vulnérabilités applicatives | SAST Semgrep GitLab : 0 constat (`56ab581`) ; bandit vert | ✅ |
| Branches GitHub `feature/m7-production-hardening`, `maj/2026-10-06` | aucune (entièrement contenues dans `main`) | supprimées le 07/10 | ✅ |
| Poste Kali encore sous SENTRY (base `sentry`) | la commande `illwatch` ne trouve pas la base | `scripts/migrer-vers-illwatch.sh` (sauvegarde, comptages, retour arrière) | ⏳ |
| Horloge de la VM Kali décalée de 6 h | journaux trompeurs | régler le fuseau de la VM | ⏳ |
| Limites de débit GitLab au 19/10 | sans effet au rythme actuel | à surveiller | — |

## 8. Prochaines étapes

1. Renommer les dépôts GitHub et GitLab en `cyberillsec-illwatch`, migrer le poste Kali.
2. Préproduction VPS UE (SSL Labs ≥ A, 7 jours de collecte) → **clôture de M7**.
3. Ouvrir M8 Detection & Correlation.
