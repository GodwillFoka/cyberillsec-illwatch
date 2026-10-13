# ILL Watch — État d'avancement des travaux

**Document vivant**, mis à jour à chaque étape. Dernière mise à jour : **14/10/2026, 03 h 30**.
Les rapports datés (`NN_JJ-MM-AAAA.md`) figent l'état d'une semaine ; celui-ci donne l'état courant.

## 1. Position

> **11-12/10 — Identité ILL Watch v2** (brand book, ADR-018) : nom affiché « ILL Watch » (identifiants
> techniques inchangés), logo écu-radar, palette Nuit et Signal, Inter et JetBrains Mono, voix de la
> marque ; appliquée à l'interface et à la documentation, vérifiée écran par écran (PR #33).

> **08/10 — SENTRY devient ILLWATCH** (nom « Sentry » déjà pris). Bascule terminée : code
> renommé (`4c1e220`), dépôts GitHub et GitLab renommés, poste Kali migré sans perte (13 tables, comptages
> identiques) dans le dossier `cyberillsec-illwatch` ; scénario SOC **48/48** sous ILLWATCH.

ILLWATCH est dans le jalon **M7 — Production Hardening**, premier des cinq jalons menant à la
v0.2.0 (M7 → M8 → M9 → M10 → M11). Les lots 1 à 3 de M7 sont codés et fusionnés. Décision du
08/10 (ADR-016) : l'interface web passe avant l'hébergement. Le lot 1 de l'interface est **codé et
fusionné** (vue d'ensemble, triage, incidents, IOC, CVE, chasse) : il reste à le constater sur
Kali sur données réelles. **Décision du 11/10** : la préproduction publique (VPS européen) est
**reportée** ; elle est remplacée en attendant par une **préproduction locale** vérifiée en CI à
chaque modification. M7 reste ouvert jusqu'au VPS. **M8 a ses quatre incréments livrés** (ADR-017,
ADR-019, ADR-020) : confiance des IOC, enrichissement des IP, inventaire et corrélation, mesure
sur jeu figé (100 % détectés, 0 % de faux positifs). **Première passe réelle sur Kali (13/10)** :
38 évènements, ≈ 80 % de faux positifs faute de comparer les versions → corrélation par version
(ADR-021, PR #38) ; mesure réelle à refaire après `illwatch cves refresh-affected`. M1 à M6 sont constatés sur données réelles, en local et en CI.

## 2. Jalons

| Jalon | État | Constat |
|---|---|---|
| M1 Foundation | ✅ | local et CI |
| M2 Threat Feeds | ✅ | atteint pour la première fois le 06/10 (OTX et STIX connectés), local et CI |
| M3 Moteur CVE | ✅ | KEV 1 734, EPSS ≥ 94 %, 495 CVE en P0 |
| M4 Incidents | ✅ | incident mené jusqu'à la clôture |
| M5 Dashboard | ✅ | scénario SOC 48/48 |
| M6 Hunting | ✅ | 339 correspondances en CI |
| **M7 Production Hardening** | 🟡 en cours | lots 1-3 fusionnés ; performances gros volume traitées ; ADR-014 appliqué ; analyses de sécurité constatées (image 0 Critical, SAST 0, secrets 0) ; interface complète (8 écrans, identité ILL Watch v2, React 19) ; préproduction locale vérifiée en CI ; **VPS UE reporté (11/10)** |
| M8 Detection & Correlation | ✅ clos le 14/10 | incréments 1 à 4 livrés : confiance (ADR-017), enrichissement (ADR-019), inventaire et corrélation CORR-01 à 03 (ADR-020), mesure 100 % / 0 % FP (`Rapport/M8_MESURE_13-10-2026.md`) ; passe réelle Kali ≈ 80 % FP → corrélation par version (ADR-021), données réelles 38 → 0 vrai positif (`Rapport/BILAN_M8.md`) |
| M9 SOC Operations | 🟢 livré le 14/10 (ADR-022, PR #46) | critère constaté en CI (parcours L1 → L2 → L3, MTTR mesuré) ; scénario à rejouer sur Kali (`Rapport/BILAN_M9.md`) |
| M10, M11 | ⏳ | contextualiser (ATT&CK, acteurs), exploiter (observabilité) |

## 3. Chantier en cours

| Chantier | Branche | État |
|---|---|---|
| **Interface web** | `main` | ✅ maquette v6 adoptée, ADR-016 accepté ; ✅ lot 1 côté serveur ; ✅ socle `frontend/`, vue d'ensemble (PR #4), triage (PR #8), incidents et investigation (PR #9), IOC (PR #24), CVE (PR #25), chasse (PR #26) ; ⏳ constat sur Kali |
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
| 14/10 | PR #46 | **M9 SOC Operations** (ADR-022) : niveaux L1/L2/L3 et escalade motivée, liste d'exclusion des faux positifs (tâche 3.6), corrélation « faux positif » jamais rouverte, chasse depuis l'incident, recommandations de réponse, règles versionnées, écran Pilotage (MTTA, MTTR, délais cibles, charge) ; outillage de clôture de M7 (`scripts/deploy-vps.sh`, workflow « Clôture M7 ») |
| 14/10 | PR #45 | **Clôture de M8** (`Rapport/BILAN_M8.md`) ; plages CIDR (type `NETWORK`) ; plateforme de l'actif ; calibration DGA sur Tranco et RULE-03 v2 (faux positifs 0,71 % → 0,094 %, détection 49,9 % → 64,1 %) |
| 14/10 | PR #39 à #43 | Statut du pipeline GitLab remonté dans GitHub (pipeline #2944320344 vert, 12/12) ; `correlate list --all` avec Version et État ; verdict « conditionnel » (plateformes NVD) : mesure réelle Kali **38 évènements → 0 vrai positif** (37 clos automatiquement, CVE-2022-0543 sur Redis requalifiée) |
| 13/10 | PR #38 | **Corrélation par version** (ADR-021) : plages vulnérables NVD conservées (`cves.affected`, migration `e5b8c1d4a907`), verdict par version (hors plage / autre produit écartés), `illwatch cves refresh-affected`, jeu figé 18 cas / 8 attendus ; **débordements** : données de démonstration extrêmes (URL de 440 caractères, titres et noms longs), captures pleine hauteur et tous écrans en mobile, recherche et titres de détail corrigés sur mobile |
| 13/10 | PR #37 | **Débordements** : libellés des barres (types d'IOC), erreurs TAXII longues, retour à la ligne général des textes ; détecteur de texte qui déborde dans les captures CI |
| 13/10 | PR #36 | **M8 incréments 3 et 4** : inventaire d'actifs, corrélation CORR-01 à 03 (score justifié, worker horaire, écrans Corrélations et Inventaire), mesure sur jeu figé 100 % / 0 % FP vérifiée par la CI, mise à jour mensuelle automatique de DB-IP ; ADR-020 |
| 12/10 | PR #35 | Enrichissement : volumes réels mesurés sur Kali (710 834 plages pays, 477 362 AS) |
| 12/10 | PR #34 | **M8 incrément 2** : enrichissement hors ligne des IP (pays, système autonome) depuis DB-IP Lite importée localement, `illwatch enrich`, ADR-019 ; écrans chargés à la demande (fin de l'avertissement de taille au build) ; captures de la fiche IP et des paramètres |
| 12/10 | PR #33 | **Identité ILL Watch v2** (ADR-018) : logos et favicon du kit, symbole écu-radar, jetons Nuit, Signal, Inter + JetBrains Mono, menu et voix de la marque, DESIGN_SYSTEM v8, site de documentation ; reprise complète A-B-C-D : CI, préproduction et captures vertes, revue indépendante (4 points corrigés), « à l'instant », typographie française (unités insécables, virgule décimale, libellés français de la chronologie et de la chasse) |
| 11/10 | PR #32 | **B** écrans Sources CTI et Administration (API comptes et paramètres) ; **D** M8 démarré : fiabilité des sources (A–F), confiance des IOC ; seconde revue indépendante : 11 points corrigés |
| 11/10 | PR #31 | Design v7 « Veille de nuit » : logo œil-radar, IBM Plex, icônes, palette recalibrée, mobile ; vérifié sur captures |
| 11/10 | PR #30 | **C** React 19.3 + Vite 7.3 : `npm audit` 0 vulnérabilité, outils compris (audit complet bloquant) |
| 11/10 | PR #29 | **A** préproduction locale (Caddy HTTPS, contrôles, captures en CI) ; `illwatch demo load` ; VPS reporté |
| 11/10 | PR #28 | Re-vérification complète des écrans IOC, CVE, chasse : CI relancée sur `main`, validation réelle, seconde revue indépendante (verdict OK) ; 4 points mineurs corrigés (chemins d'API encodés partout, garde-fou du formulaire de chasse, docs). Interface construite sur Kali avec `scripts/build-web.sh` |
| 10/10 | PR #26 | Écran Chasse : sessions, périmètre, correspondances paginées et filtrées (liens IOC/CVE), nouvelle chasse ; API `GET /hunting/sessions/{id}/matches` — **lot 1 de l'interface complet** ; revue indépendante des 3 écrans : 5 constats moyens corrigés (dont un sécurité : identifiants d'adresse validés) |
| 10/10 | PR #25 | Écran CVE et priorités : liste par risque, recherche, filtres priorité/KEV, fiche (signaux, score décomposé, historique, alertes, incidents), association ou ouverture d'incident ; jokers SQL échappés dans la recherche |
| 10/10 | PR #24 | Écran Indicateurs (IOC) : recherche normalisée, filtres, fiche (provenance, incidents associés, association), soumission d'un lot, export CSV audité ; API incidents filtrés par IOC/CVE |
| 10/10 | `8f6599b` | Vérification : `ci-local.sh` en une commande (réseau, outils, interface web, image en option, journal) ; workflow « Branches » : les 12 branches fusionnées supprimées, seules `main` et `release/v0.1.1` restent |
| 10/10 | `12fbe41` | Dépendances : politique Dependabot (mineures regroupées, majeures planifiées), TypeScript 5.9 et 4 autres mises à jour mineures ; React 19 / Vite 8 à planifier |
| 10/10 | PR #10 | **Audit global** (revue indépendante) : 1 élevé, 6 moyens corrigés — test daté, bus Redis auto-réparant, onglets coordonnés, double collecte, CSP de l'infobulle, SSE derrière Caddy ; jobs GitLab interface ; docs ([rapport](AUDIT_GLOBAL_2026-10-10.md)) |
| 10/10 | PR #9 | Écran Incidents : liste, ouverture, page d'investigation (cycle NIST, chronologie, transitions, notes, assignation, éléments liés) |
| 10/10 | PR #8 | Écran Triage : file priorisée, panneau 5 sections (score décomposé, historique), acquitter, ouvrir l'incident selon le rôle |
| 10/10 | `26d9bdb` | Sécurité interface (PR #5) : React Router retiré (XSS, redirections ouvertes), ECharts 6.1.0 ; `npm audit` bloquant en CI |
| 10/10 | PR #6 | Vitest remplacé par `node --test`, Vite 5.4.21 ; test du tableau de bord rendu indépendant de la date |
| 10/10 | PR #4 | Interface web : socle React/TypeScript, temps réel SSE, vue d'ensemble v6 ; servie par FastAPI, image multi-étapes, job CI « Interface web » |
| 10/10 | `84c0511` | Retrait progressif des sources en panne (PR #3) : 1, 2, 4… min entre deux essais, plafonné à l'intervalle de la source |
| 08/10 | `1e1fff2` | Correctif (PR #2) : journal de collecte en point de sauvegarde, verrou toujours rendu ; avertissement si `alembic upgrade` est lancé sans `illwatch db upgrade` |
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
| Vérification depuis la session de travail : npm et PyPI bloqués (politique réseau), journaux CI illisibles, suppression de branches refusée | contrôle local impossible côté session | CI GitHub fait foi (erreurs remontées en annotations) ; `ci-local.sh` sur Kali ; workflow « Branches » | ✅ contourné proprement |
| Pipeline GitLab non consultable depuis la session (connecteur en erreur, gitlab.com filtré) | jobs GitLab non constatés | contournement : workflow GitHub « Statut GitLab » qui lit l'API GitLab et publie le résultat en annotations ; secret `GITLAB_TOKEN` (read_api) posé le 13/10 ; **constaté : pipeline #2944320344 (`5ff53e4`) vert, 12/12 jobs** (dont `openapi`, `interface`, SAST, secrets, image) | ✅ |
| Source RedEye (osint.digitalside.it) en délai dépassé côté serveur ; IPsum à 50 % de réussite | collectes en échec, bruit dans la santé des sources | suspendre RedEye depuis l'écran Sources tant que le serveur ne répond pas | ⏳ |
| Horloge de la VM Kali décalée de 6 h | journaux trompeurs | régler le fuseau de la VM | ⏳ |
| Limites de débit GitLab au 19/10 | sans effet au rythme actuel | à surveiller | — |

## 8. Prochaines étapes

1. **Sur Kali** : mettre à jour (PR #45 et #46 : `illwatch db upgrade` pour les migrations
   `b7e4d2a9c613` et `c9f1a3e5b742`), essayer l'écran Pilotage, escalader un incident, lancer
   une chasse depuis un incident ; rejouer le scénario d'acceptation → clôture de M9.
2. Renseigner la plateforme des actifs (« Kali Linux 2026.3 ») : le verdict « selon
   plateforme » devient tranché.
3. **M7** : louer un VPS UE et un nom de domaine, puis `scripts/deploy-vps.sh install` et
   inscrire le domaine dans `deploy/vps-domaine.txt` → workflow « Clôture M7 » (note TLS A).
4. **M10 — CTI Intelligence Layer** : ATT&CK, acteurs, campagnes.
5. Suspendre RedEye tant que son serveur ne répond pas.
