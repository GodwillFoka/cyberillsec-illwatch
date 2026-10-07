# ADR-009 — Threat hunting : règles déterministes, deux modes, sessions enregistrées

- **Statut :** proposé
- **Date :** 2026-10-03
- **Décideurs :** à valider par le porteur du projet
- **Concerne :** MOD-06, RF-25 à RF-28, tables `hunting_sessions`, `hunting_matches`,
  `illwatch/modules/threat_hunting/`

## Contexte

Le cahier des charges impose un moteur de règles et un catalogue initial de 5 règles. ILLWATCH
ne reçoit pas les journaux réseau d'une organisation : il faut un moyen de lui soumettre ce qui
doit être chassé, sans devenir un SIEM.

## Décision

1. **Deux modes** : chasse sur **observables soumis** (export de pare-feu, proxy, EDR ; 10 000
   valeurs au plus, normalisées comme des IOC) ou chasse sur la **base d'IOC** (manuelle ou
   planifiée par le worker, `HUNT_INTERVAL_SECONDS`).
2. **Règles déterministes en Python** plutôt qu'un moteur Sigma/KQL complet : les 5 règles du
   CdC ne portent pas sur des journaux structurés mais sur des observables ; un moteur Sigma
   n'apporterait que du poids. RULE-06 « IOC connu » complète le catalogue : c'est la question
   que tout analyste pose en premier.
3. **RULE-05** s'appuie sur un inventaire déclaratif (noms de produits) rapproché de la
   description des CVE P0/P1 à exploit public. Approximation assumée tant qu'ILLWATCH ne gère pas
   d'inventaire CPE.
4. Chaque exécution est une **session** enregistrée ; une règle en échec (liste Tor
   injoignable) rend la session `PARTIELLE` sans arrêter les autres.

## Conséquences

- **Positives** : résultats reproductibles et explicables ; aucune dépendance lourde.
- **Négatives** : RULE-03 (DGA) est une heuristique (entropie, voyelles, chiffres) avec des faux
  positifs possibles sur des noms courts ou des marques atypiques ; RULE-05 dépend de la
  qualité du texte des CVE. Suivi : import Sigma (règles `pattern_type=sigma` déjà présentes
  dans certaines collections TAXII) et inventaire CPE au-delà de la v1.0.
