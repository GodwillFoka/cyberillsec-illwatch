# Architecture technique d'ILLWATCH

Ce document raconte comment le code est organisé et, surtout, pourquoi il l'est ainsi. Chaque
choix ci-dessous répond à une contrainte réelle : tenir dans peu de mémoire, résister aux
sources défaillantes, garder une trace qu'on ne peut pas falsifier. Pour les spécifications
fonctionnelles, reportez-vous au [Cahier des charges](CAHIER_DES_CHARGES.md).

## Principe directeur

ILLWATCH suit une Clean Architecture en couches, avec une dépendance strictement descendante :
chaque couche ne connaît que celle du dessous.

```
  [CLIENTS]           CLI (Click)                 API REST (FastAPI)
                           │                              │
  [CONTROLLERS]      illwatch/cli/                   illwatch/app/api/
                           └──────────────┬──────────────┘
                                          ▼
  [SERVICES]                      illwatch/modules/
                       (logique métier pure, calculateurs,
                         collecteurs, moteur de scoring)
                                          ▼
  [DATA ACCESS]          illwatch/app/database.py · illwatch/app/models/
                                          ▼
  [PERSISTENCE]                PostgreSQL 16 · Redis 7
```

**La règle d'or :** un contrôleur d'API ne fait jamais de calcul métier ni de requête SQL
complexe. Il valide les paramètres d'entrée, appelle la couche `modules/`, et renvoie un schéma
Pydantic.

Cette règle n'a rien d'esthétique. Le moteur de scoring et la machine d'état des incidents sont
les deux endroits où une erreur a des conséquences bien réelles : une CVE mal priorisée reste
sans correctif, un incident mal fermé perd sa valeur de preuve. En les gardant dans des fonctions
pures, sans dépendance à HTTP ni à la base, on peut les tester de façon exhaustive. C'est ce que
traduisent les 100 % de couverture sur `scoring.py` et `state_machine.py`.

## Découpage des paquets

| Chemin | Rôle | Dépend de |
|---|---|---|
| `illwatch/shared/` | Énumérations et utilitaires transverses | rien |
| `illwatch/app/config.py` | Configuration Pydantic validée au démarrage | rien |
| `illwatch/app/database.py` | Moteur, sessions, classe `Base` | `config` |
| `illwatch/app/models/` | Modèles relationnels SQLAlchemy | `database`, `shared` |
| `illwatch/modules/` | Logique métier pure par domaine | `models`, `shared` |
| `illwatch/app/api/` | Contrôleurs REST | `modules`, `database` |
| `illwatch/cli/` | Commandes Click | `modules`, `config` |
| `frontend/` | Interface web React (ADR-016), servie par `illwatch/app/web.py` | l'API REST et SSE uniquement |

Une importation qui remonte cette liste n'est pas un raccourci : c'est un défaut d'architecture.

## Décisions structurantes

### Asynchrone de bout en bout

La collecte passe son temps à attendre : des dizaines de requêtes HTTP vers des API distantes,
dont certaines mettent plusieurs secondes à répondre. Dans un modèle synchrone, chaque flux
immobiliserait un worker. Tout le chemin (`httpx`, SQLAlchemy async, asyncpg, FastAPI) est donc
asynchrone, et c'est ce qui permet de tenir l'objectif RNF-MEM-01 (256 Mo au plus) avec un seul
processus.

Corollaire : aucun appel bloquant n'a sa place dans la boucle d'évènements. Quand une
bibliothèque synchrone est incontournable, elle passe par `asyncio.to_thread`.

### Isolation des collecteurs

Chaque collecteur tourne dans un worker indépendant (RSK-02). Une source en panne ne doit jamais
emporter les autres, ni l'API. Un flux en échec passe en `status = DEGRADED`, son erreur est
tracée, et le cycle suivant le réessaie : il n'est pas désactivé d'office.

### Déduplication confiée à la base

Ce qui garantit RF-08, c'est la contrainte `UNIQUE (type, value)` sur `indicators`, pas la
discipline du code applicatif. Un `INSERT ... ON CONFLICT DO UPDATE` laisse PostgreSQL arbitrer
les courses entre workers concurrents. En amont, la normalisation (`normalize_indicator`) veille à
ce que `EVIL.COM` et `evil.com` tombent bien sur la même ligne.

### Résilience réseau

Les API publiques sont capricieuses, alors ILLWATCH s'y prépare : trois tentatives avec un délai
qui double à chaque fois (`tenacity`), un délai d'attente de 15 s, le respect de l'en-tête
`Retry-After` sur un HTTP 429, et un cache Redis pour amortir les limites de débit (RSK-01). Les
clés d'API sont facultatives : sans elles, ILLWATCH fonctionne, simplement plus lentement.

### Migrations

En production, personne ne modifie le schéma à la main, et `create_all()` n'y a pas sa place.
Toute évolution passe par une révision Alembic versionnée. `alembic/env.py` lit l'URL de la base
dans la configuration Pydantic plutôt que dans `alembic.ini`, pour qu'il n'existe qu'une seule
source de vérité.

## Flux de données : la chaîne de collecte

```
   Sources externes            ILLWATCH                          Sorties
   ────────────────            ──────                          ───────
   NVD 2.0        ─┐
   CISA KEV       ─┤        ┌──────────────┐
   FIRST EPSS     ─┼──────► │ Collecteurs  │  worker isolé par flux
   AlienVault OTX ─┤        └──────┬───────┘
   Flux STIX/JSON ─┘               ▼
                            ┌──────────────┐
                            │Normalisation │  typage IOC, canonisation
                            └──────┬───────┘
                                   ▼
                            ┌──────────────┐
                            │Déduplication │  UNIQUE(type,value) + upsert
                            └──────┬───────┘
                                   ▼
                            ┌──────────────┐
                            │   Scoring    │  R ∈ [0,100], déterministe
                            └──────┬───────┘
                                   ▼
                            ┌──────────────┐        ┌──────────────┐
                            │  PostgreSQL  │ ─────► │ API · CLI ·  │
                            │    Redis     │        │  Dashboard   │
                            └──────────────┘        └──────────────┘
```

## Temps réel (ADR-016)

```
 API (incidents, alertes)  ─┐   écriture en base          après COMMIT
 Worker (collecte, chasse) ─┴─► after_flush : événement ─► publication Redis
                                 déduit, mis en attente     canal illwatch:events
                                                                   │
                     navigateur ◄── GET /api/v1/stream (SSE) ◄─────┘
                     relit la donnée par l'API REST   filtrage par rôle, battement 15 s
```

Un évènement annonce qu'une chose a changé (identifiant, niveau), jamais la donnée elle-même :
l'interface va la relire avec les droits de l'utilisateur. Ainsi, le flux temps réel ne peut rien
révéler qu'un compte n'aurait pas le droit de voir. L'évènement n'est publié qu'après le commit,
si bien qu'une transaction annulée n'annonce rien. Sans Redis, le bus reste local au processus
(l'API voit ses propres évènements, pas ceux du worker), et un avertissement est journalisé.

## Modèle de données

La base compte 28 tables, créées par 20 migrations (`alembic/versions/`). Les règles métier y
sont inscrites dans la base elle-même (CHECK sur chaque énumération, clés étrangères, unicité),
et pas seulement dans le code : même une écriture SQL directe ne peut pas créer un état
incohérent. Le schéma ci-dessous montre le cœur historique du modèle :

```
users ──┬──< incidents ──┬──< incident_events        (immuable : UPDATE/DELETE/TRUNCATE refusés)
        │                ├──< incident_indicators >── indicators
        │                └──< incident_cves ──────>── cves
        ├──< hunting_sessions ──< hunting_matches ──> indicators | cves
        ├──< audit_events                             (journal d'audit, ajout seul : ADR-011)
        └──< refresh_tokens                           (sessions révocables : ADR-012)

threat_feeds ──< indicators ──< indicator_sources >── threat_feeds   (provenance, ADR-006)

cves ──< cve_priority_history          cves ──< cve_alerts ──> incidents.source_alert_id
collector_state                        (curseurs NVD, ligne de base des alertes, cadences)
```

Les jalons suivants y ont ajouté leurs propres tables : `collection_runs` (journal des
collectes), `enrichment_datasets` et `ip_ranges` (enrichissement des adresses), `assets` et
`correlated_events` (corrélation), `exclusions` (faux positifs), `attack_techniques`,
`attack_actors` et `attack_uses` (MITRE ATT&CK), `campaigns` et `campaign_indicators`
(campagnes), et `demo_requests` (demandes de démonstration).

Quelques index portent la performance : `uq_indicator_type_value` (déduplication),
`idx_indicators_last_seen` (expiration), `idx_cves_risk_score` et `idx_cves_priority` (tri et
filtres du moteur CVE), `idx_incident_events_timeline` (chronologie),
`idx_incidents_status_severity` (tableau de bord).

## Sécurité

Une plateforme qui concentre votre renseignement et la description de votre surface exposée est
une cible de choix. Voici comment elle se protège, mesure par mesure :

| Mesure | Mise en œuvre |
|---|---|
| Aucun secret dans le code ni en base | Configuration Pydantic depuis l'environnement ; gabarits d'URL et en-têtes ; masquage dans erreurs et journaux |
| SSRF | Liste blanche d'adresses publiques, DNS vérifié avant chaque requête, redirections revalidées (httpx) ou refusées (taxii2-client) : `threat_feeds/fetcher.py`, `taxii.py` |
| Réponses hostiles | Taille plafonnée lue en flux, délai par requête, backoff, 429 respecté |
| Authentification | JWT HS256 de 15 min avec `kid` (rotation de clé sans déconnexion), Argon2id, rôle relu en base ; jeton de rafraîchissement opaque, rotatif, lignée révoquée au rejeu ; 429 après 5 échecs compte × IP, 50 par compte, 20 par IP |
| Moindre privilège en base | Rôle applicatif sans droit de structure, `SELECT/INSERT` seulement sur les tables en ajout seul ; migrations par le rôle propriétaire (`app/db_roles.py`, ADR-012) |
| Validation stricte des entrées | Pydantic v2 (`extra="forbid"`) sur toutes les frontières d'API |
| Pas d'injection SQL | Aucune requête construite par concaténation ; ORM ou requêtes paramétrées |
| Intégrité de l'audit | Chronologie d'incident et journal d'audit en ajout seul : ORM + déclencheurs PostgreSQL refusant `UPDATE`, `DELETE` et `TRUNCATE` (ADR-011) |
| Traçabilité | `audit_events` : connexions, refus d'accès, administration, exports, chasse ; `X-Request-ID` relie réponse, accès et audit (`app/middleware.py`, `foundation/audit.py`) |
| Couche HTTP | `nosniff`, `X-Frame-Options`, CSP `default-src 'none'` et `no-store` sur l'API, HSTS en production, 500 JSON sans détail interne |
| Exploitation | `/health` (vivacité) et `/ready` (base + schéma), sauvegarde vérifiée et restauration, entretien quotidien (`docs/OPERATIONS.md`) |
| Transport et déploiement | Caddy (TLS, HTTP/2-3) seul exposé ; `migrate` éphémère avec le rôle propriétaire ; API et worker en rôle applicatif (`docker-compose.prod.yml`, ADR-013) |
| Injection CSV | Cellules exportées neutralisées (`dashboard/service.py`) |
| Conteneur non privilégié | Utilisateur `illwatch` UID 10001 ; `.dockerignore` excluant `.env` et `.git` |
| Dépendances surveillées et figées | `constraints.txt` partagé par la CI, l'image et le poste ; Renovate ; SAST, secrets et dépendances analysés à chaque pipeline |

## Ce que nous avons choisi de ne pas faire en v1.0

Dire non fait aussi partie de l'architecture. Chacun de ces refus protège la simplicité qui rend
ILLWATCH facile à installer et à maintenir :

- **Pas de microservices.** Le monolithe modulaire tient jusqu'à 100 000 évènements par jour.
  Découper avant d'en avoir besoin coûterait la simplicité de déploiement, qui est un argument
  du produit.
- **Pas d'Elasticsearch.** PostgreSQL, avec des index adaptés, couvre les besoins de recherche de
  la v1.0 (P95 de 8 ms sur 30 000 CVE). C'est justement la lourdeur des alternatives
  qu'ILLWATCH veut éviter.
- ~~Pas d'interface web~~ *(levé en octobre 2026 par l'ADR-016)* : la v1.0 n'offrait qu'une API
  et une ligne de commande. L'interface web React et TypeScript, avec son temps réel par SSE,
  vit aujourd'hui dans `frontend/`.
- **Pas de moteur Sigma complet.** Les règles de chasse portent sur des observables, pas sur des
  journaux structurés : six règles déterministes suffisent (ADR-009).
- **Pas de facteur CWE dans le scoring.** Voir l'[ADR-001](adr/ADR-001-scoring-composite.md).
