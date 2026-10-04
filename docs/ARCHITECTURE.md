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

Seize tables, créées par huit migrations (`alembic/versions/`). Les contraintes métier sont
portées par la base (CHECK sur chaque énumération, clés étrangères, unicité), pas seulement par
le code : une écriture SQL directe ne peut pas créer un état incohérent.

```
users ──┬──< incidents ──┬──< incident_events        (immuable : UPDATE/DELETE/TRUNCATE refusés)
        │                ├──< incident_indicators >── indicators
        │                └──< incident_cves ──────>── cves
        ├──< hunting_sessions ──< hunting_matches ──> indicators | cves
        ├──< audit_events                             (journal d'audit, ajout seul — ADR-011)
        └──< refresh_tokens                           (sessions révocables — ADR-012)

threat_feeds ──< indicators ──< indicator_sources >── threat_feeds   (provenance, ADR-006)

cves ──< cve_priority_history          cves ──< cve_alerts ──> incidents.source_alert_id
collector_state                        (curseurs NVD, ligne de base des alertes, cadences)
```

Index critiques : `uq_indicator_type_value` (déduplication), `idx_indicators_last_seen`
(expiration), `idx_cves_risk_score` et `idx_cves_priority` (tri et filtres du moteur CVE),
`idx_incident_events_timeline` (chronologie), `idx_incidents_status_severity` (tableau de bord).

## Sécurité

| Mesure | Mise en œuvre |
|---|---|
| Aucun secret dans le code ni en base | Configuration Pydantic depuis l'environnement ; gabarits d'URL et en-têtes ; masquage dans erreurs et journaux |
| SSRF | Liste blanche d'adresses publiques, DNS vérifié avant chaque requête, redirections revalidées (httpx) ou refusées (taxii2-client) — `threat_feeds/fetcher.py`, `taxii.py` |
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
| Conteneur non privilégié | Utilisateur `sentry` UID 10001 ; `.dockerignore` excluant `.env` et `.git` |
| Dépendances surveillées et figées | `constraints.txt` partagé par la CI, l'image et le poste ; Renovate ; SAST, secrets et dépendances analysés à chaque pipeline |

## Ce qui n'est délibérément pas fait en v1.0

- **Pas de microservices.** Le monolithe modulaire tient jusqu'à 100 000 événements/jour. Découper
  avant d'en avoir besoin coûterait la simplicité de déploiement, qui est un argument produit.
- **Pas d'Elasticsearch.** PostgreSQL avec des index adaptés couvre les besoins de recherche de la
  v1.0 (P95 de 8 ms sur 30 000 CVE). C'est la lourdeur des alternatives que SENTRY évite.
- **Pas d'IHM web.** API et CLI d'abord ; le tableau de bord SOC est une vue console `rich` plus des
  endpoints d'agrégation et d'export. Une interface web est la première évolution après la v1.0.
- **Pas de moteur Sigma complet.** Les règles de chasse portent sur des observables, pas sur des
  journaux structurés : six règles déterministes suffisent (ADR-009).
- **Pas de facteur CWE dans le scoring.** Voir [ADR-001](adr/ADR-001-scoring-composite.md).
