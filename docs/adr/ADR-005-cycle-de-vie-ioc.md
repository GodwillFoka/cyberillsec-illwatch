# ADR-005 — Cycle de vie et déduplication des IOC

- **Statut :** proposé
- **Date :** 2026-09-27
- **Décideurs :** à valider par le porteur du projet
- **Concerne :** MOD-02, RF-07, RF-08, RNF-PERF-02, table `indicators`,
  `illwatch/modules/threat_feeds/indicators.py`

## Contexte

La table `indicators` possède `first_seen`, `last_seen`, `hit_count`, `severity`, `expires_at`
et `feed_id`, mais rien ne fixait ce qu'elles signifient quand un même IOC est rapporté plusieurs
fois, par plusieurs sources, avec des sévérités différentes. Sans règle écrite, chaque collecteur
(T2.3, T2.9, T2.10) l'interpréterait à sa façon et les métriques du dashboard (MOD-05) seraient
fausses.

## Décision

1. **Identité.** Un IOC est identifié par `(type, valeur normalisée)`. La normalisation refait
   les formes désamorcées (`hxxps://evil[.]com`), met en minuscules domaines, e-mails, hashs,
   schéma et hôte des URL, retire le point final DNS, le port par défaut et le fragment d'URL,
   et canonise les adresses IP. La contrainte `UNIQUE (type, value)` garantit l'unicité.
2. **Écriture.** Un seul `INSERT … ON CONFLICT DO UPDATE` par paquet de 500 lignes. Le lot est
   d'abord dédupliqué en mémoire.
3. **`hit_count`** = nombre d'ingestions ayant rapporté l'IOC. Répéter un IOC dans un même lot ne
   compte qu'une fois.
4. **`first_seen` / `last_seen`** = plus ancienne et plus récente observation. `first_seen` ne peut
   que reculer, `last_seen` ne peut qu'avancer. Une date d'observation future est ramenée à
   l'instant d'ingestion.
5. **`severity`** = la plus haute sévérité jamais rapportée.
6. **`expires_at`** = `last_seen` + durée de validité du type, repoussée à chaque ré-observation :
   IP et URL 30 jours, domaines et e-mails 90 jours, hashs sans expiration (`NULL`). Un IOC
   **expiré est conservé** ; il est seulement exclu des vues actives (`active=true`). Une
   ré-observation le réactive.
7. **`feed_id`** = première source connue, jamais écrasée.
8. **Rejets.** Une valeur invalide, ou dont le type annoncé diffère du type détecté, est rejetée et
   **listée** dans le résultat, jamais ignorée en silence.
9. **Pas de modification ni de suppression unitaire** d'un IOC par l'API.

## Justification

- Compter les ingestions plutôt que les lignes brutes empêche un flux qui répète une valeur
  mille fois dans un fichier de gonfler artificiellement un IOC.
- Garder la sévérité maximale : une source prudente ne doit pas faire baisser l'alerte d'une
  source mieux informée. Le coût (une erreur de sévérité ne redescend pas seule) est accepté
  jusqu'à la gestion des faux positifs.
- Les durées de validité suivent la pratique CTI : l'infrastructure réseau d'un attaquant change
  de mains en quelques semaines ; un hash reste la preuve d'un fichier précis.
- *Écartés* — suppression physique à expiration : destruction de l'historique d'enquête ;
  lecture puis écriture ligne à ligne : incompatible avec RNF-PERF-02.

## Conséquences

- Positives : déduplication garantie par la base ; 1 000 IOC ingérés et réingérés en moins de
  5 s sur PostgreSQL (test `test_performance_rnf_perf_02`) ; dashboard et hunting pourront
  s'appuyer sur `is_active` et `hit_count` sans ambiguïté.
- Négatives : une seule source par IOC (`feed_id`). La provenance multi-sources demandera une
  table de liaison `indicator_sources`. Les compteurs `inserted` / `updated` renvoyés par l'API
  sont indicatifs en cas d'ingestions concurrentes du même IOC.

## Suivi

- Table `indicator_sources` (provenance multi-flux) avant le connecteur OTX.
- Gestion des faux positifs (liste d'exclusion) avant le module de hunting.
- Durées de validité configurables par flux si un besoin réel apparaît.
