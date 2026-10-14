# ADR-026 — M11 : observabilité et environnements

- **Statut :** **accepté le 15/10/2026** (décision de Godwill FOKA : « tu fais M11 »)
- **Date :** 2026-10-15
- **Décideurs :** Godwill FOKA
- **Concerne :** ADR-011 (journal JSON, identifiant de requête), ADR-013 (Caddy), ROADMAP M11

## Contexte

ILL Watch tourne seul (worker de collecte, synchronisations CVE, corrélation) : sans mesure, une
source arrêtée ou un worker tombé ne se voit qu'à l'écran Sources, quand quelqu'un le regarde.
Le critère de sortie de M11 (« 7 jours de collecte continue en staging sans intervention »)
exige de le constater, donc de le mesurer.

## Décision

1. **`GET /metrics`** au format texte Prometheus, **sans dépendance** (le format est simple ;
   `prometheus_client` apporterait registre global et multiprocessus inutiles ici) :
   - HTTP : requêtes par méthode, **modèle de route** (cardinalité bornée) et statut,
     histogramme des durées (flux SSE exclus de l'histogramme) ;
   - métier, calculé en base à chaque collecte : IOC actifs par type, nouveaux IOC sur 24 h,
     état, dernier succès et intervalle de chaque source, collectes 24 h par résultat,
     dernier succès des synchronisations (NVD, KEV, EPSS…), incidents ouverts (sévérité,
     niveau SOC), évènements corrélés non acquittés, refus d'authentification sur 24 h,
     base et Redis joignables, version.
2. **Accès** : jeton `METRICS_TOKEN` (Bearer) s'il est défini ; sinon adresses privées ou
   locales seulement. Caddy répond 404 sur `/metrics` : jamais relayé vers Internet.
3. **Prometheus + Grafana** en surcouche Compose (`docker-compose.observability.yml`),
   activée par `deploy-vps.sh` ; écoute sur 127.0.0.1 (tunnel SSH). Dix alertes (API, base,
   Redis, source sans succès depuis 3 intervalles, aucune collecte en 24 h, NVD, 5xx, p95,
   force brute, incident critique ouvert). Deux tableaux **générés** par
   `scripts/grafana_dashboards.py` ; un test vérifie que chaque métrique citée existe.
4. **Journaux** : le journal JSON d'accès et d'audit avec identifiant de requête (M7) est
   conservé tel quel ; la corrélation journal ↔ requête se fait par `request_id`.
5. **Environnements** dev → staging → production décrits dans `docs/ENVIRONNEMENTS.md`.
6. **Acceptation en CI** : le scénario SOC tourne à chaque modification sur le jeu de
   démonstration figé (préproduction) ; Prometheus et Grafana y sont démarrés, vérifiés et
   capturés.
7. **Restauration testée chaque mois** sur le VPS (`scripts/restore-test.sh`, cron du 1er) :
   empreinte, restauration dans une base jetable, volumes comparés à la production.

Écartés : exporters PostgreSQL et Redis dédiés (deux conteneurs de plus pour des mesures
fines inutiles à ce volume ; la disponibilité suffit) ; Loki (les journaux JSON restent
lisibles par `docker compose logs`, à reconsidérer au-delà d'une instance) ; Alertmanager
(les alertes sont visibles dans Prometheus et Grafana ; notification par e-mail à ajouter
quand un serveur SMTP sera choisi).

## Conséquences

- Positives : une collecte arrêtée déclenche une alerte en moins d'une heure ; les 7 jours de
  staging se constatent sur un tableau, pas à la mémoire.
- Négatives : les jauges métier coûtent une dizaine de requêtes agrégées toutes les 30 s
  (indexées, négligeables à ce volume) ; les compteurs HTTP sont propres à chaque processus
  et repartent de zéro au redémarrage (Prometheus gère les remises à zéro des compteurs) ;
  pas de notification hors des écrans tant qu'Alertmanager n'est pas branché.

## Suivi

- Alertmanager + SMTP (ou webhook) pour les alertes critiques.
- Clôture de M11 : 7 jours de staging sur le VPS de M7, tableau Grafana à l'appui.
