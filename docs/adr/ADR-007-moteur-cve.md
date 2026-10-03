# ADR-007 — Moteur CVE : sources, recalcul, ligne de base des alertes

- **Statut :** proposé
- **Date :** 2026-09-29
- **Décideurs :** à valider par le porteur du projet
- **Concerne :** MOD-03, RF-11 à RF-16, RNF-PERF-01, tables `cves`, `cve_priority_history`,
  `cve_alerts`, `collector_state`, `sentry/modules/cve_tracker/`

## Contexte

Le score composite (ADR-001) existait sans données. La phase 3 doit l'alimenter depuis trois
sources publiques aux contraintes différentes : NVD 2.0 (volumineux, débit limité à 5 requêtes
par 30 s sans clé, fenêtres de dates de 120 jours au plus), CISA KEV (un fichier JSON complet)
et FIRST EPSS (API par lots). Elle doit aussi alerter sans noyer l'astreinte.

## Décision

1. **Périmètre suivi** : toutes les CVE du catalogue KEV (quelle que soit leur date) + les CVE
   modifiées depuis `NVD_INITIAL_DAYS` jours (30 par défaut), puis incrémental par
   `lastModStartDate`. Pas d'import des 300 000 CVE historiques : sans exploitation connue, une
   vieille CVE plafonne à 30 points (ADR-001) et n'apporte que du volume.
2. **CVSS retenu** : v3.1 (formule du CdC), à défaut v3.0, à défaut v4.0 ; l'évaluation du NVD
   (« Primary ») prime sur celle du CNA. Le vecteur stocké indique la version.
3. **Exploit public** = une référence NVD étiquetée « Exploit ». **Campagne ransomware** =
   `knownRansomwareCampaignUse: Known` au KEV. Deux signaux publics, vérifiables, déterministes.
4. **Recalcul** du score et de la priorité à chaque changement d'entrée ; tout changement de
   priorité est historisé (ancien et nouveau score, source).
5. **Alerte** au franchissement du seuil `RISK_ALERT_THRESHOLD` (75) vers le haut. **La
   première synchronisation complète est une ligne de base sans alerte.**
6. **Livraison** : l'alerte est d'abord enregistrée et journalisée, puis envoyée au webhook
   (`ALERT_WEBHOOK_URL`), 5 tentatives au plus.
7. **Ordonnancement** : `sentry feeds worker` synchronise les CVE toutes les 6 h
   (`CVE_SYNC_INTERVAL_SECONDS`) sous verrou Redis ; `sentry cves sync` à la demande.

## Justification

- Ligne de base : l'import initial ferait passer des centaines de CVE KEV au-dessus du seuil
  en une fois. Une astreinte qui reçoit 400 alertes le premier jour apprend à les ignorer. Les
  CVE critiques restent consultables (`priority=P0_CRITIQUE`).
- Seuil 75 plutôt que 80 (P0) : alerte dès qu'une CVE entre dans le haut de la zone P1, avant
  son passage en P0 ; c'est la valeur du CdC (`RISK_ALERT_THRESHOLD`).
- Historique en base plutôt que dans les journaux : c'est une preuve d'audit (NIS 2, DORA)
  qui doit survivre à la rotation des journaux.

## Conséquences

- **Positives** : chaque point du score est justifiable (`GET /api/v1/cves/{id}` → `breakdown`
  et `history`) ; synchro incrémentale bornée en mémoire (page par page) ; P95 de la liste mesuré
  à 8 ms (filtres) et 108 ms (recherche texte) sur 30 000 CVE.
- **Négatives** :
  - première synchro lente sans clé NVD (≈ 6 s par page de 500 CVE) : la clé gratuite est
    fortement recommandée ;
  - une CVE KEV que le NVD n'a pas encore évaluée a un CVSS nul : son score sous-estime la
    sévérité technique (mais pas l'exploitation, qui domine la formule) ;
  - v4.0 et v3.1 n'ont pas la même échelle de sévérité ; les mélanger est une approximation
    assumée tant que le NVD n'évalue pas toutes les CVE récentes ;
  - la recherche texte (`ILIKE`) n'utilise pas d'index : acceptable jusqu'à ~100 000 CVE, au-delà
    un index trigramme (`pg_trgm`) sera nécessaire.

## Suivi

- Cache Redis des réponses NVD (tâche 2.7) si la synchro devient coûteuse.
- Rapprochement CVE ↔ IOC (OTX, STIX) pour le signal « Attaque » au-delà du seul ransomware.
- Index `pg_trgm` sur `cves.description` au-delà de 100 000 CVE.
