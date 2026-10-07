# ADR-006 — Provenance multi-sources des IOC et collecte planifiée

- **Statut :** proposé
- **Date :** 2026-09-28
- **Décideurs :** à valider par le porteur du projet
- **Concerne :** MOD-02, RF-07, T2.6, T2.9, tables `indicators` et `indicator_sources`,
  `illwatch/modules/threat_feeds/{indicators,locks,otx,collector}.py`

## Contexte

`indicators.feed_id` ne retient que la première source d'un IOC (ADR-005). Or la valeur d'un IOC
dépend du nombre de sources indépendantes qui le confirment : une IP signalée par Feodo Tracker,
URLhaus et un pulse OTX n'a pas le poids d'une IP vue une fois. Le jalon M2 exige aussi une
collecte « sans intervention » et un connecteur OTX, dont la clé API ne doit jamais fuiter.

## Décision

1. **Table de liaison `indicator_sources`** : clé `(indicator_id, feed_id)`, avec `first_seen`,
   `last_seen` et `hit_count` **par source**. Alimentée dans la même instruction groupée que
   l'IOC (`INSERT … ON CONFLICT DO UPDATE … RETURNING`, puis upsert des liens). `ON DELETE
   CASCADE` des deux côtés : supprimer un flux efface sa provenance, pas l'IOC.
   `indicators.feed_id` est conservé (première source, rétrocompatibilité de l'API).
2. **Migration `1f3dafc3008c`** : crée la table, **recopie** la provenance existante depuis
   `indicators.feed_id`, et ajoute `OTX` à la contrainte `ck_threat_feeds_feed_type`. La descente
   est refusée tant qu'un flux OTX existe : aucune suppression implicite de données.
3. **OTX = format de flux** (`FeedType.OTX`) avec un connecteur dédié : pagination `next`,
   `modified_since` incrémental (marge 15 min), `OTX_MAX_PAGES` pages au plus. La clé part en
   en-tête `X-OTX-API-KEY`, **uniquement vers `otx.alienvault.com`** : contrôlé à
   l'enregistrement du flux (API → 422), avant chaque page (y compris les liens `next`), et par
   le fetcher qui refuse toute redirection inter-hôtes d'une requête authentifiée.
4. **Collecte planifiée** : `illwatch feeds worker` (boucle `collect_due_feeds`, période
   `WORKER_TICK_SECONDS`) et **verrou Redis par flux** (`SET NX EX`, libération par script Lua
   conditionnée au jeton). Redis injoignable → verrou local et avertissement journalisé.
5. **Journal JSON** : une ligne `feed.collected` par collecte (volumes, durée, erreur, pic RSS).

## Justification

- Table de liaison plutôt que colonne tableau (`feed_ids UUID[]`) : compteurs et dates par
  source, index sur `feed_id`, portable SQLite/PostgreSQL, intégrité référentielle.
- Worker intégré plutôt que Celery/APScheduler : aucune dépendance nouvelle, empreinte mémoire
  compatible avec RNF-MEM-01 (≤ 256 Mo), et le cron reste possible (`fetch-all`).
- Verrou Redis simple plutôt que Redlock : l'enjeu est d'éviter un double téléchargement, pas une
  exclusion mutuelle critique. Redis est déjà dans la pile.

## Conséquences

- **Positives** : `source_count` et la liste des sources exposés par l'API ; `illwatch status`
  compte les IOC confirmés par ≥ 2 sources ; plusieurs workers peuvent tourner sans doublon.
- **Négatives** :
  - une écriture de plus par paquet d'IOC rattaché à un flux (≈ ×1,5 sur l'ingestion ; RNF-PERF-02
    reste vérifié par les tests) ;
  - Redis en panne ⇒ plus de protection entre instances (dégradation assumée, journalisée) ;
  - une collecte plus longue que `COLLECT_LOCK_TTL_SECONDS` (15 min) peut être doublée ;
  - OTX tronqué (`OTX_MAX_PAGES`) : les pulses au-delà de la limite peuvent être manqués puisque
    le curseur `modified_since` avance. Signalé par un avertissement dans le rapport et le journal.

## Suivi

- Score de confiance d'un IOC fondé sur `source_count` (phase 3 ou 6).
- Épingler l'IP résolue dans la connexion HTTP (risque résiduel de DNS rebinding, T2.3).
- Mesurer la mémoire réelle sous collecte OTX complète (RNF-MEM-01) avec `peak_rss_mb` du journal.
