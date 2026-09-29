<div align="center">

# 🛡️ SENTRY

**Security Monitoring & Cyber Threat Intelligence Platform**

*CyberillSec — A CYBERILL Initiative*

[![pipeline](https://gitlab.com/GodwillFoka/cyberillsec-sentry/badges/main/pipeline.svg)](https://gitlab.com/GodwillFoka/cyberillsec-sentry/-/pipelines)
[![coverage](https://gitlab.com/GodwillFoka/cyberillsec-sentry/badges/main/coverage.svg)](https://gitlab.com/GodwillFoka/cyberillsec-sentry/-/pipelines)
[![License: MIT](https://img.shields.io/badge/License-MIT-E6681B.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12+-20155C.svg)](https://www.python.org/)

*« Engineering Cyber Resilience. Empowering Digital Trust. »*

</div>

---

## Le problème

Un analyste SOC passe 60 à 70 % de son temps à recopier des indicateurs entre une dizaine d'outils,
à lire des bulletins illisibles et à trier des alertes en double. Les plateformes commerciales qui
résolvent ce problème (Recorded Future, Mandiant Advantage, CrowdStrike Falcon Intelligence) coûtent
entre 40 000 € et 150 000 € par an — hors d'atteinte des PME, ETI et organisations publiques
régionales. Les alternatives open source existantes demandent des clusters de 16 Go de RAM au
démarrage.

Pendant ce temps, les attaquants exploitent les vulnérabilités publiées en moins de 48 heures, et
NIS 2 et DORA imposent une veille active avec notification sous 24 à 72 heures.

## La réponse

SENTRY est un cerveau CTI centralisé, léger et 100 % open source (MIT) :

1. **Collecte** automatiquement le renseignement sur les menaces (NVD, CISA KEV, FIRST EPSS,
   AlienVault OTX, flux STIX/JSON/CSV).
2. **Normalise** ces données hétérogènes dans un modèle unique et dédupliqué.
3. **Score** chaque vulnérabilité sur une échelle déterministe de 0 à 100 combinant sévérité
   technique, probabilité d'exploitation, exploitation avérée et campagnes actives.
4. **Expose** le tout via une API REST, une CLI riche et un dashboard SOC — pour décider d'une
   remédiation en quelques secondes au lieu de plusieurs heures.

Empreinte mémoire cible en régime nominal : **< 256 Mo**. Hébergement européen, souveraineté des
données.

| Critère | CrowdStrike | Recorded Future | MISP | OpenCTI | **SENTRY** |
|---|---|---|---|---|---|
| Open source | Non | Non | AGPL | Apache | **MIT** |
| Dashboard SOC | Oui | Partiel | Non | Non | **Natif** |
| Scoring composite | Oui | Oui | Non | Non | **Oui** |
| Coût annuel | 50–100 k$ | 30–200 k$ | 0 $ | 0 $ | **0 $** |
| Hébergement UE | Non | Non | Oui | Oui | **Oui** |

## Scoring de risque composite

Le cœur de SENTRY. Pour chaque CVE :

```
R = min(100, CVSS × 3.0 + EPSS × 100 × 0.25 + KEV × 25 + Exploit × 10 + Attaque × 10)
```

| Composante | Domaine | Contribution max |
|---|---|---|
| CVSS v3.1 — sévérité technique brute | 0.0 – 10.0 | 30 |
| EPSS — probabilité d'exploitation à 30 j | 0.0 – 1.0 | 25 |
| CISA KEV — exploitation formellement prouvée | 0 / 1 | 25 |
| Exploit public / PoC documenté | 0 / 1 | 10 |
| Campagne ransomware confirmée | 0 / 1 | 10 |

Grille de décision SOC : **R ≥ 80** → P0, patch sous 24 h · **60 ≤ R < 80** → P1, patch sous 7 j ·
**40 ≤ R < 60** → P2, patch sous 30 j · **R < 40** → P3, maintenance standard.

Conséquence assumée : une CVSS 10.0 sans exploitation observée plafonne à 30 et ne réveille personne
la nuit. C'est l'exploitation réelle qui pilote la priorité, pas la sévérité théorique.

## Architecture

Six modules cohésifs et faiblement couplés, en couches strictes (Clean Architecture) :

```
  [CLIENTS]        CLI (Click)              API REST (FastAPI)
                        │                            │
  [CONTROLLERS]    sentry/cli/               sentry/app/api/
                        └─────────────┬─────────────┘
                                      ▼
  [SERVICES]                  sentry/modules/
                    (logique métier pure, collecteurs, scoring)
                                      ▼
  [DATA ACCESS]        sentry/app/database.py · sentry/app/models/
                                      ▼
  [PERSISTENCE]             PostgreSQL 16 · Redis 7
```

| Module | Périmètre |
|---|---|
| **MOD-01** Foundation | Configuration, base SQL, authentification, CLI, migrations Alembic |
| **MOD-02** Threat Feeds | Collecte multi-sources, normalisation, moteur IOC, déduplication, aging |
| **MOD-03** CVE Tracker | NVD 2.0, CISA KEV, FIRST EPSS, scoring composite, alerting |
| **MOD-04** Incidents | Machine d'état à 6 étapes (NIST SP 800-61), timeline immuable |
| **MOD-05** SOC Dashboard | Agrégation analytique, métriques temps réel, exports JSON/CSV |
| **MOD-06** Threat Hunting | Moteur de pattern-matching, règles de corrélation |

Détail complet : [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Stack

Python 3.12+ · FastAPI · SQLAlchemy 2.0 async + asyncpg · PostgreSQL 16 · Alembic · Redis 7.2 ·
Pydantic v2 · httpx · Click + Rich · Pytest · Docker Compose.

Le choix de Python n'est pas un défaut : l'intégralité des standards CTI mondiaux (STIX, TAXII,
bindings YARA, parsers Sigma) y est développée en priorité, et Pydantic v2 (cœur Rust) rapproche
FastAPI des débits de Go.

## Démarrage rapide

**Prérequis :** Python 3.12+, Git, Docker & Docker Compose, un environnement Linux / macOS / WSL2.

```bash
git clone https://gitlab.com/GodwillFoka/cyberillsec-sentry.git
cd cyberillsec-sentry

python3.12 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"

cp .env.example .env          # puis renseigner SECRET_KEY et les clés API
docker compose up -d          # PostgreSQL 16 + Redis 7
sentry db init                # migrations de schéma (alembic upgrade head)
sentry seed                   # flux de référence publics
sentry users create --username admin --email admin@example.org --role admin

pytest                        # rapide, sur SQLite en mémoire
./scripts/ci-local.sh          # pipeline complet (base dédiée sentry_test)
uvicorn sentry.app.main:app --reload --port 8000
```

Ouvrir <http://localhost:8000/docs> : la documentation Swagger interactive doit s'afficher.

Guide pas à pas, y compris pour un développeur découvrant la cybersécurité :
[`docs/ONBOARDING.md`](docs/ONBOARDING.md).

## Ce que SENTRY sait faire aujourd'hui

| Domaine | Disponible | Comment |
|---|---|---|
| Comptes et rôles | ✅ | `sentry users create`, `POST /api/v1/auth/token` |
| Sources de flux | ✅ | `sentry feeds add/list`, `/api/v1/feeds` (ADMIN pour l'écriture) |
| Collecte CSV / JSON / STIX 2.1 / TAXII 2.1 | ✅ | `sentry feeds fetch <nom>` ou `fetch-all` |
| Sources publiques prêtes à l'emploi | ✅ | `sentry seed` : 7 sources, dont 5 sans aucune clé |
| Connecteur AlienVault OTX | ✅ | source de type `OTX`, clé `OTX_API_KEY` dans `.env` |
| Collecte planifiée | ✅ | `sentry feeds worker` (verrou Redis par flux, plusieurs instances possibles) |
| Journal de collecte JSON | ✅ | une ligne `feed.collected` par collecte sur la sortie d'erreur |
| IOC dédupliqués, expiration | ✅ | `/api/v1/indicators` (lecture, soumission par lot) |
| Provenance multi-sources | ✅ | `GET /api/v1/indicators/{id}` → `sources` ; `source_count` en liste |
| Moteur CVE (NVD, KEV, EPSS) | ✅ | `sentry cves sync`, `/api/v1/cves` ; synchro auto par le worker |
| Score de risque et priorité SOC | ✅ | décomposition et historique : `sentry cves show`, `/api/v1/cves/{id}` |
| Alertes CVE | ✅ | `/api/v1/alerts`, `sentry cves alerts`, webhook `ALERT_WEBHOOK_URL` |
| Incidents | 🟡 | machine d'état prête ; API en phase 4 |
| Dashboard, threat hunting | ❌ | phases 5 et 6 |

## Mesurer l'avancement

- **Sur les données** : `sentry status` — schéma, santé des sources, volume d'IOC et critères
  du jalon M2 constatés en base (✔/✘).
- **Sur le code** : `./scripts/ci-local.sh` — qualité, tests, couverture, migrations.
- **Sur le planning** : `Rapport/PLAN_DIRECTEUR.md` — tâches par étape et critères de fin.

## CLI

```bash
sentry version          # version et environnement
sentry config           # configuration effective, secrets masqués
sentry db check         # connectivité base de données
sentry db init          # application de toutes les migrations
sentry db upgrade [rev] # migration jusqu'à une révision (défaut : head)
sentry db downgrade rev # retour arrière (confirmation demandée)
sentry db current       # révision appliquée vs révision cible
sentry seed             # données de référence, idempotent
sentry users create     # création de compte (mot de passe saisi masqué, ≥ 12 caractères)
sentry feeds list       # sources de flux et leur état
sentry feeds add        # nouvelle source (HTTPS public, nom unique)
sentry feeds fetch X    # collecte immédiate d'une source
sentry feeds fetch-all  # collecte des sources échues (usage ponctuel ou cron)
sentry feeds worker     # planificateur : flux en continu + CVE toutes les 6 h (Ctrl+C pour arrêter)
sentry cves sync        # synchronisation KEV + NVD + EPSS, recalcul des scores, alertes
sentry cves list        # CVE les plus risquées (--priority P0_CRITIQUE, --kev, --search …)
sentry cves show ID     # décomposition du score, délai de remédiation, historique de priorité
sentry cves alerts      # alertes non acquittées
sentry status           # avancement mesuré : schéma, sources, IOC, CVE, critères M2 et M3
```

Authentification : `POST /api/v1/auth/token` (flux OAuth2 *password*, formulaire
`username` / `password`) renvoie un jeton Bearer JWT ; `GET /api/v1/users/me` renvoie le profil.
Le bouton **Authorize** de Swagger (`/docs`) utilise directement ce flux.

Sources de flux (T2.2) : `GET /api/v1/feeds` et `GET /api/v1/feeds/{id}` pour tout utilisateur
authentifié ; `POST`, `PATCH` et `DELETE` réservés au rôle `ADMIN`. Seules les URL HTTPS publiques
sont acceptées.

Indicateurs (IOC) : `GET /api/v1/indicators` et `GET /api/v1/indicators/{id}` pour tout
utilisateur authentifié ; `POST /api/v1/indicators` (lot de 1 000 au plus) pour `ADMIN` et
`ANALYST`. Règles de déduplication et d'expiration : `docs/adr/ADR-005-cycle-de-vie-ioc.md` ;
provenance multi-sources : `docs/adr/ADR-006-provenance-multi-sources.md`.

Collecte en production : `docker compose --profile full up -d` démarre l'API **et** le worker.
Journal exploitable : `sentry feeds worker 2>> collecte.jsonl`, puis par exemple
`jq 'select(.event=="feed.collected") | {feed_name, inserted, duration_ms}' collecte.jsonl`.

Vulnérabilités : `GET /api/v1/cves` (tri par risque ; filtres `priority`, `min_score`, `is_kev`,
`q`, `modified_since`) et `GET /api/v1/cves/{id}` (décomposition du score, historique) pour tout
utilisateur authentifié ; `GET /api/v1/alerts` et `POST /api/v1/alerts/{id}/ack` (ADMIN, ANALYST).
Règles de synchronisation et d'alerte : `docs/adr/ADR-007-moteur-cve.md`.

Les commandes `sentry incidents`, `sentry dashboard show` et `sentry hunt` arrivent avec leurs
modules respectifs (phases 4 à 6).

## Structure du dépôt

```
cyberillsec-sentry/
├── .gitlab-ci.yml          # Pipeline CI/CD (qualité, tests, build, sécurité)
├── .gitlab/                # Gabarits de merge requests et d'issues
├── alembic/versions/       # Historique immuable des migrations SQL
├── docs/                   # Cahier des charges, vision, architecture, ADR
├── Rapport/                # Bilans hebdomadaires du jeudi
├── sentry/
│   ├── app/
│   │   ├── api/            # Contrôleurs et routes REST
│   │   ├── models/         # Modèles relationnels SQLAlchemy
│   │   ├── config.py       # Configuration Pydantic validée au démarrage
│   │   ├── database.py     # Moteur et sessions asynchrones
│   │   └── main.py         # Point d'entrée FastAPI
│   ├── cli/                # Commandes Click
│   ├── modules/            # Modules métier (threat_feeds, cve_tracker, …)
│   └── shared/             # Énumérations et utilitaires transverses
├── tests/                  # Suite Pytest
├── docker-compose.yml
└── pyproject.toml
```

## Qualité

Quatre exigences non négociables, vérifiées par la CI sur chaque merge request :

- **Typage strict** — `mypy --strict` sans exception ;
- **Lint & format** — `ruff check .` et `ruff format .`, 100 caractères maximum par ligne ;
- **Tests** — toute route ou fonction de calcul est accompagnée de son test ; couverture ≥ 80 % ;
- **Exceptions** — jamais de `except: pass` ; chaque exception est tracée et typée.

```bash
ruff check . && ruff format --check .
mypy sentry
pytest
```

## Feuille de route

État au 29/09/2026 : **P1 livrée (`v0.1.0`)**, **P2 codée** (jalon M2 à constater sur données
réelles avec `sentry status`), **P3 codée** (jalon M3 à constater). Dates recalées sur le
démarrage réel du dépôt (21/09/2026), voir [ADR-004](docs/adr/ADR-004-recalage-planning.md) ;
les dates du Cahier des charges figurent entre parenthèses.

| Phase | Livrable | Jalon | État |
|---|---|---|---|
| P1 Foundation | Squelette, CLI, Docker, CI | M1 (05/08) | ✅ `v0.1.0` le 24/09 |
| P2 Threat Feeds | Collecteurs, IOC, déduplication | M2 — 08/10/2026 (19/08) | code ✅, constat en cours |
| P3 CVE Tracker | NVD, EPSS, KEV, scoring, alerting | M3 — 22/10/2026 (02/09) | code ✅, constat en cours |
| P4 Incidents | Machine d'état, timeline, liaisons | M4 — 05/11/2026 (16/09) | machine d'état prête |
| P5 SOC Dashboard | Agrégation, exports, vue console | M5 — 12/11/2026 (23/09) | — |
| P6 Threat Hunting | Moteur de règles, 5 règles v1.0 | **v1.0 — 19/11/2026** (30/09) | — |

Au-delà de la v1.0 : assistant IA (LLM + RAG), multi-tenant et SSO, puis Cyberill TI Cloud.

## Contribuer

Les contributions sont bienvenues : développeurs, chercheurs, analystes SOC, technical writers.
Lire [`CONTRIBUTING.md`](CONTRIBUTING.md) avant d'ouvrir une merge request, et
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) avant d'interagir avec la communauté.

Signalement de vulnérabilité : [`SECURITY.md`](SECURITY.md) — **pas** via une issue publique.

## Licence

[MIT](LICENSE) © CYBERILL — Godwill FOKA, Berlin.

---

<div align="center">

**Construisons ensemble l'alternative européenne en Cyber Threat Intelligence.**

</div>
