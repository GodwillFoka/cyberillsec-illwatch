# Architecture technique de SENTRY

Ce document décrit comment le code est organisé et pourquoi. Pour les spécifications
fonctionnelles, voir le [Cahier des charges](CAHIER_DES_CHARGES.md).

## Principe directeur

SENTRY suit une Clean Architecture en couches, avec une dépendance strictement descendante : une
couche ne connaît que celle du dessous.

```
  [CLIENTS]           CLI (Click)                 API REST (FastAPI)
                           │                              │
  [CONTROLLERS]      sentry/cli/                   sentry/app/api/
                           └──────────────┬──────────────┘
                                          ▼
  [SERVICES]                      sentry/modules/
                       (logique métier pure, calculateurs,
                         collecteurs, moteur de scoring)
                                          ▼
  [DATA ACCESS]          sentry/app/database.py · sentry/app/models/
                                          ▼
  [PERSISTENCE]                PostgreSQL 16 · Redis 7
```

**La règle d'or :** un contrôleur d'API ne fait jamais de calcul métier ni de requête SQL complexe.
Il valide les paramètres d'entrée, appelle la couche `modules/`, et retourne un schéma Pydantic.

La raison n'est pas esthétique. Le moteur de scoring et la machine d'état des incidents sont les
deux endroits où une erreur a des conséquences opérationnelles réelles : une CVE mal priorisée n'est
pas patchée, un incident mal fermé perd sa traçabilité forensique. Les garder dans des fonctions
pures, sans dépendance à HTTP ni à la base, permet de les tester exhaustivement — ce que reflètent
les 100 % de couverture sur `scoring.py` et `state_machine.py`.

## Découpage des paquets

| Chemin | Rôle | Dépend de |
|---|---|---|
| `sentry/shared/` | Énumérations et utilitaires transverses | rien |
| `sentry/app/config.py` | Configuration Pydantic validée au démarrage | rien |
| `sentry/app/database.py` | Moteur, sessions, classe `Base` | `config` |
| `sentry/app/models/` | Modèles relationnels SQLAlchemy | `database`, `shared` |
| `sentry/modules/` | Logique métier pure par domaine | `models`, `shared` |
| `sentry/app/api/` | Contrôleurs REST | `modules`, `database` |
| `sentry/cli/` | Commandes Click | `modules`, `config` |

Une importation qui remonte cette liste est un défaut d'architecture, pas un raccourci.

## Décisions structurantes

### Asynchrone de bout en bout

La collecte est une charge I/O-bound : des dizaines de requêtes HTTP vers des API distantes dont
certaines répondent en plusieurs secondes. Un modèle synchrone bloquerait un worker par flux. Tout
le chemin — `httpx`, SQLAlchemy async, asyncpg, FastAPI — est asynchrone, ce qui permet de tenir
l'objectif RNF-MEM-01 (≤ 256 Mo) avec un seul process.

Corollaire : aucun appel bloquant ne doit entrer dans la boucle d'événements. Une bibliothèque
synchrone incontournable passe par `asyncio.to_thread`.

### Isolation des collecteurs

Chaque collecteur tourne dans un worker indépendant (RSK-02). L'échec d'un flux ne doit jamais faire
tomber les autres ni l'API. Un flux en échec passe en `status = DEGRADED` avec son erreur tracée, et
le cycle suivant le réessaie — il n'est pas désactivé automatiquement.

### Déduplication portée par la base

La contrainte `UNIQUE (type, value)` sur `indicators` est ce qui garantit RF-08, pas la discipline du
code applicatif. Un `INSERT ... ON CONFLICT DO UPDATE` laisse PostgreSQL arbitrer les courses entre
workers concurrents. La normalisation en amont (`normalize_indicator`) garantit que `EVIL.COM` et
`evil.com` heurtent bien la même ligne.

### Résilience réseau

Trois tentatives avec backoff exponentiel (`tenacity`), timeout de 15 s, respect de l'en-tête
`Retry-After` sur HTTP 429, cache Redis pour amortir le rate limiting des API publiques (RSK-01).
Les clés API sont optionnelles : SENTRY fonctionne sans, plus lentement.

### Migrations

Le schéma n'est jamais modifié à la main ni par `create_all()` en production. Toute évolution passe
par une révision Alembic committée, `alembic/env.py` lisant l'URL depuis la configuration Pydantic
plutôt que depuis `alembic.ini` — pour qu'il n'existe qu'une seule source de vérité.

## Flux de données — pipeline de collecte

```
   Sources externes            SENTRY                          Sorties
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

## Modèle de données

Six tables, détaillées en DDL au [§4.4 du Cahier des charges](CAHIER_DES_CHARGES.md#44-modèle-relationnel).

```
users ──────┬──< incidents ──< incident_events
            └──< incident_events (author)

threat_feeds ──< indicators

cves  (autonome en v1.0 ; tables de liaison incidents↔IOC/CVE en phase 4)
```

Index critiques : `idx_indicators_type_val` (déduplication), `idx_indicators_last_seen` (aging),
`idx_cves_risk_score` (tri du dashboard), `idx_incident_events_timeline` (reconstruction
chronologique).

## Sécurité

| Mesure | Mise en œuvre |
|---|---|
| Aucun secret dans le code | Configuration Pydantic depuis l'environnement ; `.env` ignoré par git |
| Validation stricte des entrées | Pydantic v2 sur toutes les frontières d'API |
| Pas d'injection SQL | Aucune requête construite par concaténation ; ORM ou requêtes paramétrées |
| Conteneur non privilégié | Utilisateur `sentry` UID 10001 dans l'image Docker |
| Chiffrement en transit | TLS 1.3 exigé sur toute communication externe |
| Dépendances surveillées | Dependabot hebdomadaire sur pip, mensuel sur Actions et Docker |

## Ce qui n'est délibérément pas fait en v1.0

- **Pas de microservices.** Le monolithe modulaire tient jusqu'à 100 000 événements/jour. Découper
  avant d'en avoir besoin coûterait la simplicité de déploiement, qui est un argument produit.
- **Pas d'Elasticsearch.** PostgreSQL avec des index adaptés couvre les besoins de recherche de la
  v1.0. C'est précisément la lourdeur des alternatives que SENTRY cherche à éviter.
- **Pas d'IHM lourde.** API et CLI d'abord ; le dashboard SOC de la phase 5 est une vue console
  `rich` plus des endpoints d'agrégation.
- **Pas de facteur CWE dans le scoring.** Voir [ADR-001](adr/ADR-001-scoring-composite.md).
