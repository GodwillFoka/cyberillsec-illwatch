# Bilan M11 « Observability & Deployment » (15/10/2026)

**Décision :** ADR-026 · **Livraison :** PR #51 · **État :** livré, **clôture en attente** des
7 jours de staging (VPS de M7).

## Critère de sortie

> 7 jours de collecte continue en staging sans intervention, tableaux de bord complets,
> restauration testée.

| Volet | État | Constat |
|---|---|---|
| Tableaux de bord complets | ✅ | 2 tableaux Grafana provisionnés, vérifiés et capturés en CI (`14-grafana-service`, `15-grafana-collecte`) |
| Restauration testée | ✅ | à chaque modification (préproduction CI : sauvegarde, restauration, comptages) ; chaque mois sur le VPS (`scripts/restore-test.sh`, cron du 1er) |
| Acceptation | ✅ | scénario SOC exécuté en CI sur le jeu de démonstration figé, à chaque modification |
| 7 jours de collecte continue en staging | ⏳ | attend le VPS de M7 ; alertes `IllwatchFeedStale` et `IllwatchNoCollection` prêtes à le constater |

## Livré

- `GET /metrics` (texte Prometheus, sans dépendance nouvelle) : HTTP par modèle de route,
  durées, jauges métier (IOC actifs, nouveaux IOC 24 h, état et dernier succès des sources,
  collectes 24 h, synchronisations NVD/KEV/EPSS, incidents ouverts, évènements non acquittés,
  refus d'authentification, base, Redis). Accès : `METRICS_TOKEN` ou réseau interne ; Caddy
  répond 404.
- `docker-compose.observability.yml` : Prometheus (30 jours, 10 alertes) et Grafana, sur
  127.0.0.1 seulement ; activés par `scripts/deploy-vps.sh`.
- Préproduction CI : contrôles TAXII et `/metrics`, `promtool check config`, collecte
  Prometheus constatée (`up = 1`), règles chargées, tableaux provisionnés et capturés.
- `docs/ENVIRONNEMENTS.md` : développement → staging → production, passage en production.

## Incidents de mise au point

- Le modèle de route fourni par FastAPI omettait le préfixe `/api/v1` : reconstitué à partir
  de l'adresse (préfixe statique, cardinalité bornée).
- Le scénario d'acceptation (étape M7 « titulaire non bloquée depuis une autre adresse ») a
  besoin d'une API qui fait confiance à `X-Forwarded-For` local : second processus uvicorn
  dédié dans le conteneur, la production restant inchangée.
- Grafana sous Chromium sans interface : langue explicite requise (« Incorrect locale
  information provided ») ; `root_url` sur `localhost` retiré (ressources visées en IPv6).

## Reste

1. VPS de M7 en staging, 7 jours sans intervention, capture du tableau « Collecte et SOC ».
2. Alertmanager et notification (SMTP ou webhook) des alertes critiques.
