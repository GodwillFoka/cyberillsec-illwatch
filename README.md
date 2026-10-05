<div align="center">

# 🛡️ SENTRY

**Security Monitoring & Cyber Threat Intelligence Platform**

*CyberillSec — A CYBERILL Initiative*

[![CI](https://github.com/GodwillFoka/cyberillsec-sentry/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/GodwillFoka/cyberillsec-sentry/actions/workflows/ci.yml)
[![Couverture ≥ 80 %](https://img.shields.io/badge/couverture-%E2%89%A5%2080%25-20155C.svg)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/License-MIT-E6681B.svg)](LICENSE)
[![Python 3.12 | 3.14](https://img.shields.io/badge/Python-3.12%20%7C%203.14-20155C.svg)](https://www.python.org/)
[![mypy strict](https://img.shields.io/badge/mypy-strict-20155C.svg)](pyproject.toml)
[![STIX/TAXII 2.1](https://img.shields.io/badge/STIX%2FTAXII-2.1-E6681B.svg)](https://oasis-open.github.io/cti-documentation/)

*« Engineering Cyber Resilience. Empowering Digital Trust. »*

**Dépôts :** [GitLab (référence)](https://gitlab.com/GodwillFoka/cyberillsec-sentry) · [GitHub (miroir)](https://github.com/GodwillFoka/cyberillsec-sentry)

</div>

---

## En 30 secondes

SENTRY est une plateforme de **Cyber Threat Intelligence** open source qui fait le travail
répétitif d'un analyste SOC — collecter, dédupliquer, prioriser, corréler — pour qu'il ne garde
que les décisions :

- **collecte** en continu le renseignement public : CSV, JSON, STIX 2.1, **TAXII 2.1**,
  AlienVault OTX, NVD 2.0, CISA KEV, FIRST EPSS ;
- **normalise et déduplique** les indicateurs de compromission (IOC) en gardant leur provenance ;
- **priorise** chaque vulnérabilité sur un **score déterministe de 0 à 100** fondé sur
  l'exploitation réelle, et alerte quand une CVE franchit le seuil ;
- **pilote la réponse** : incidents NIST SP 800-61 à chronologie **immuable**, ouverts en un clic
  depuis une alerte ;
- **chasse** les menaces dans les journaux d'une organisation (Tor, DNS dynamique, DGA,
  infrastructures ransomware, CVE exploitables sur l'inventaire) ;
- **expose** tout cela par une API REST (30 routes), une CLI riche (34 commandes) et un tableau
  de bord SOC, dans **moins de 256 Mo de mémoire**.

## Le problème

Un analyste SOC passe 60 à 70 % de son temps à recopier des indicateurs entre une dizaine
d'outils, à lire des bulletins illisibles et à trier des alertes en double. Les plateformes
commerciales qui résolvent ce problème coûtent de **40 000 à 150 000 € par an** — hors de portée
des PME, des ETI et des collectivités. Les plateformes open source complètes exigent une
infrastructure lourde : OpenCTI, par exemple, demande au minimum **8 Go de RAM pour la plateforme
et 8 Go pour son moteur de recherche**, plus Redis, RabbitMQ et un stockage objet¹.

Pendant ce temps, les attaquants exploitent une vulnérabilité publiée en moins de 48 heures, et
**NIS 2** et **DORA** imposent une veille active et une notification d'incident sous 24 à 72 h.

## La réponse

| | Plateformes commerciales | Plateformes open source complètes | **SENTRY** |
|---|---|---|---|
| Coût annuel | 40 à 150 k€ | 0 € (hors infrastructure) | **0 €** |
| Licence | Propriétaire | AGPL / Apache | **MIT** |
| Infrastructure | SaaS hors UE le plus souvent | ≥ 16 Go de RAM, 4 à 5 services | **< 256 Mo, PostgreSQL + Redis** |
| Priorisation CVE par l'exploitation réelle | Oui | Via connecteurs | **Native (KEV + EPSS + exploit)** |
| Souveraineté | Variable | Auto-hébergé | **Auto-hébergé, UE** |

SENTRY ne cherche pas à remplacer un graphe de connaissances CTI complet : il donne à une
équipe de 1 à 10 personnes ce dont elle a besoin **le lundi matin** — quoi patcher d'abord, quoi
bloquer, qu'est-ce qui a changé, et la preuve de ce qui a été fait.

## Fonctionnalités

| Module | Ce qu'il fait | État |
|---|---|---|
| **MOD-01 Foundation** | Configuration validée au démarrage, PostgreSQL + Alembic, JWT + Argon2id, rôles ADMIN / ANALYST / VIEWER, limitation des tentatives de connexion | ✅ opérationnel |
| **MOD-02 Threat Feeds** | 5 formats de flux, client TAXII 2.1 `taxii2-client` durci, connecteur OTX, sonde de source avant intégration, déduplication, expiration par type, provenance multi-sources, worker planifié avec verrou Redis | ✅ intégré · validé sur 3 sources réelles |
| **MOD-03 CVE Tracker** | NVD 2.0 incrémental, catalogue KEV, EPSS, score composite recalculé à chaque changement, historique de priorité, alertes + webhook | ✅ intégré · KEV réel validé, NVD/EPSS à constater |
| **MOD-04 Incidents** | Cycle NIST SP 800-61 à 6 états, chronologie immuable (ORM + déclencheur PostgreSQL), liens IOC/CVE, incident depuis une alerte | ✅ intégré · scénario réel validé |
| **MOD-05 SOC Dashboard** | Synthèse temps réel, activité 24 h, MTTR, exports CSV RFC 4180 / JSON RFC 8259 protégés contre l'injection CSV | ✅ intégré · scénario réel validé |
| **MOD-06 Threat Hunting** | 6 règles déterministes, chasse sur observables ou sur la base, sessions enregistrées, chasse planifiée | ✅ intégré · scénario réel validé |

« Codé » signifie : implémenté, testé, intégré au pipeline. Un jalon n'est déclaré **atteint**
que lorsque `sentry status` le constate sur données réelles.

## Score de risque composite

Le cœur de SENTRY. Pour chaque CVE :

```
R = min(100, CVSS × 3.0 + EPSS × 100 × 0.25 + KEV × 25 + Exploit × 10 + Ransomware × 10)
```

| Composante | Source | Contribution max |
|---|---|---|
| CVSS v3.1 — sévérité technique | NVD 2.0 | 30 |
| EPSS — probabilité d'exploitation à 30 jours | FIRST | 25 |
| Exploitation avérée | CISA KEV | 25 |
| Exploit public documenté | Références NVD « Exploit » | 10 |
| Campagne ransomware confirmée | CISA KEV | 10 |

**R ≥ 80** → P0, patch sous 24 h · **60 ≤ R < 80** → P1, 7 j · **40 ≤ R < 60** → P2, 30 j ·
**R < 40** → P3. Une CVSS 10.0 sans exploitation observée plafonne à 30 et ne réveille personne
la nuit : c'est l'exploitation réelle qui pilote la priorité. Chaque point est justifiable
(`GET /api/v1/cves/{id}` → `breakdown` et `history`) — voir [ADR-001](docs/adr/ADR-001-scoring-composite.md).

## Architecture

```mermaid
flowchart LR
    subgraph Sources publiques
        A[CSV / JSON / STIX]:::src
        B[TAXII 2.1]:::src
        C[AlienVault OTX]:::src
        D[NVD 2.0 · KEV · EPSS]:::src
    end
    subgraph SENTRY
        W[Worker planifié<br/>verrou Redis]
        F[Fetcher durci<br/>SSRF · taille · délai]
        N[Normalisation<br/>déduplication]
        S[Score composite<br/>alerting]
        I[Incidents<br/>chronologie immuable]
        H[Threat hunting]
        DB[(PostgreSQL 16)]
    end
    A & B & C & D --> F
    W --> F --> N --> DB
    D --> S --> DB
    DB --> I & H
    DB --> API[API REST · CLI · Dashboard]
    classDef src fill:#20155C,color:#fff
```

Clean Architecture en couches strictes : les contrôleurs (API FastAPI, CLI Click) ne contiennent
aucune logique métier ; tout passe par `sentry/modules/`, testable sans HTTP ni base. Détail :
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) et les [10 décisions d'architecture](docs/adr/).

## Sécurité par conception

Une plateforme de sécurité qui télécharge des données hostiles doit être la première à s'en
protéger.

| Risque | Mesure |
|---|---|
| **SSRF** (une URL de flux qui vise le réseau interne) | Liste blanche d'adresses publiques (`is_global`, CGNAT, NAT64, 6to4), résolution DNS vérifiée avant chaque requête, redirections revalidées ou refusées |
| Réponse hostile (taille, lenteur) | Lecture en flux plafonnée, délai par requête, backoff exponentiel, 429 respecté |
| Fuite de secrets | Clés jamais en base (gabarits `{ABUSECH_AUTH_KEY}`, en-têtes), masquées dans erreurs et journaux, identifiants TAXII attachés à un seul hôte |
| Force brute | 5 échecs par compte / 20 par IP en 15 min → 429 avant toute vérification du mot de passe |
| Falsification de l'historique | Chronologie d'incident refusant `UPDATE`/`DELETE` jusque dans PostgreSQL (déclencheur) |
| Injection CSV (CWE-1236) | Cellules exportées commençant par `= + - @` neutralisées |
| Élévation de privilèges | RBAC sur chaque route d'écriture, rôle relu en base à chaque requête |
| Chaîne d'approvisionnement | SAST, détection de secrets et analyse des dépendances à chaque pipeline ; Renovate |
| Conteneur | Utilisateur non privilégié (UID 10001), contexte de build sans `.env` |

## Qualité et mesures

| Indicateur | Valeur |
|---|---|
| Tests automatisés | **≈ 390**, sur PostgreSQL 16 réel, Python 3.12 **et** 3.14 |
| Couverture | **≈ 94 %** (seuil bloquant : 80 %) |
| Typage | `mypy --strict`, 0 erreur sur 69 modules |
| Lint / format | `ruff`, 0 erreur |
| Migrations | 6, vérifiées montée → `alembic check` → descente → remontée à chaque pipeline |
| Liste des CVE, P95 (30 000 CVE) | **8 ms** (cible 250 ms) |
| Ingestion réelle (37 000 IOC) | 24 s, pic mémoire **120 Mo** (cible 256 Mo) |
| Scénario SOC de bout en bout (`scripts/scenario_soc.py`) | **40/40** sur données réelles, latence médiane des appels incidents 12 ms |
| Chasse sur 3 867 IOC réels | **27 ms** |

Pipeline GitLab : qualité (lint, typage) → tests (matrice 3.12 / 3.14 + migrations sur base
vierge) → build de l'image Docker → sécurité (SAST, secrets, dépendances). `scripts/ci-local.sh`
le reproduit en local avant chaque push.

## Stack technique

**Python 3.12+** · **FastAPI** · **Pydantic v2** · **SQLAlchemy 2.0 async** + asyncpg ·
**PostgreSQL 16** · **Alembic** · **Redis 7.2** · httpx · **taxii2-client** (OASIS) · Click + Rich ·
Pytest · Docker Compose · GitLab CI.

Python est le langage de l'écosystème CTI (STIX, TAXII, YARA, Sigma) ; Pydantic v2 (cœur Rust)
et l'asynchrone de bout en bout donnent un débit largement suffisant dans un seul processus.

## Démarrage rapide

**Prérequis :** Python 3.12+, Git, Docker et Docker Compose. Développé sur **Kali Linux**
(Python 3.14) et vérifié en CI sous Python 3.12 et 3.14 ; compatible Debian/Ubuntu, macOS, WSL2.

```bash
git clone https://gitlab.com/GodwillFoka/cyberillsec-sentry.git   # ou le miroir :
# git clone https://github.com/GodwillFoka/cyberillsec-sentry.git
cd cyberillsec-sentry
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

cp .env.example .env               # SECRET_KEY : openssl rand -hex 32
docker compose up -d postgres redis
sentry db init && sentry seed      # schéma + sources de référence vérifiées
sentry users create --username admin --email admin@example.org --role admin

./scripts/ci-local.sh              # pipeline complet en local
uvicorn sentry.app.main:app --reload --port 8000   # http://localhost:8000/docs
```

Sur **Kali Linux** : `sudo apt install -y docker.io docker-compose python3-venv`, puis
`sudo usermod -aG docker $USER` et reconnexion (si `docker compose` est absent, la commande
s'écrit `docker-compose`). Guide pas à pas, y compris pour un développeur qui
découvre la cybersécurité : [`docs/ONBOARDING.md`](docs/ONBOARDING.md).

## Utilisation

```bash
# Renseignement
sentry feeds probe <nom|url> --type TAXII   # vérifier qu'une source répond et porte des IOC
sentry taxii discover https://attack-taxii.mitre.org/taxii2/
sentry feeds fetch-all --force
sentry feeds worker                          # flux en continu, CVE toutes les 6 h, chasse quotidienne

# Vulnérabilités
sentry cves sync && sentry cves list --priority P0_CRITIQUE
sentry cves show CVE-2021-44228              # décomposition du score

# Réponse
sentry incidents from-alert <alerte>         # incident pré-rempli depuis une alerte CVE
sentry incidents move <id> CONFINEMENT --note "Poste isolé"

# Chasse et pilotage
sentry hunt run --observables proxy.txt --asset FortiOS
sentry dashboard show
sentry dashboard export cves --format csv -o cves.csv
sentry status                                # jalons constatés sur données réelles
```

| API (`/api/v1`) | Rôle requis en écriture |
|---|---|
| `auth/token`, `users/me` | — |
| `feeds`, `indicators` | ADMIN (flux), ADMIN / ANALYST (IOC) |
| `cves`, `alerts` | ADMIN / ANALYST (acquittement) |
| `incidents` | ADMIN / ANALYST |
| `dashboard/summary`, `dashboard/recent`, `dashboard/export` | lecture |
| `hunting/rules`, `hunting/sessions` | ADMIN / ANALYST (lancer une chasse) |

Documentation interactive : `/docs` (Swagger) et `/redoc`.

## Structure du dépôt

```
cyberillsec-sentry/
├── .gitlab-ci.yml          # Pipeline : qualité, tests 3.12/3.14, migrations, image, sécurité
├── .github/workflows/      # Même pipeline sur GitHub Actions (miroir)
├── alembic/versions/       # 6 migrations, historique immuable
├── docs/                   # Cahier des charges, vision, architecture, 10 ADR
├── Rapport/                # Bilans d'étape et rapport global
├── scripts/ci-local.sh     # Réplique locale du pipeline
├── sentry/
│   ├── app/                # API FastAPI, modèles, configuration, sécurité
│   ├── cli/                # Commandes Click
│   ├── modules/            # threat_feeds, cve_tracker, incidents, dashboard, threat_hunting
│   └── shared/             # Énumérations, journal JSON
└── tests/                  # ≈ 390 tests, fixtures tirées de sources réelles
```

## Feuille de route

Les six modules sont **intégrés dans `main`** et validés de bout en bout sur données réelles
(audit du 03/10/2026 : [`Rapport/ETAT_GLOBAL_SENTRY_2026-10-03.md`](Rapport/ETAT_GLOBAL_SENTRY_2026-10-03.md)).
La suite vise une plateforme **déployable et démontrable** :

| Étape | Objectif | État |
|---|---|---|
| M1 → M6 | Foundation, Threat Feeds, CVE, Incidents, Dashboard, Hunting | ✅ intégrés (`v0.1.1`) |
| **M7** | Production Hardening : audit append-only, en-têtes, readiness, dépendances verrouillées | 🔄 en cours |
| M8 | Detection & Correlation : enrichissement, score de confiance IOC, corrélation IOC × CVE × actif | ⏳ |
| M9 | SOC Operations : triage L1/L2/L3, faux positifs, séries temporelles | ⏳ |
| M10 | CTI Intelligence : acteurs, campagnes, MITRE ATT&CK, export STIX | ⏳ |
| M11 | Observability & Deployment : Prometheus, Grafana, staging → production | ⏳ |
| **v0.2.0** | Production Candidate | ⏳ |

Critères de sortie de chaque jalon : [`docs/ROADMAP.md`](docs/ROADMAP.md). Au-delà : assistant
d'analyse (LLM + RAG sur la base CTI), multi-tenant et SSO, puis **Cyberill TI Cloud** (offre
hébergée en UE).

## Ce que ce projet démontre

- **Architecture logicielle** : Clean Architecture, asynchrone de bout en bout, décisions
  tracées en ADR avec leurs coûts assumés.
- **Ingénierie de la sécurité** : modèle de menace appliqué au code (SSRF, injection CSV, force
  brute, fuite de secrets, falsification d'audit), défense en profondeur jusqu'à la base.
- **Cyber Threat Intelligence** : STIX 2.1, TAXII 2.1, KEV, EPSS, CVSS, NIST SP 800-61,
  heuristiques de détection (DGA, DNS dynamique, Tor), conformité NIS 2 / DORA.
- **Données** : modèle relationnel contraint (CHECK, déclencheurs), upserts groupés, migrations
  réversibles, performances mesurées.
- **DevSecOps** : typage strict, ≈ 94 % de couverture, pipeline multi-versions, analyses de
  sécurité, réplique locale du pipeline.
- **Conduite de projet** : cahier des charges, plan directeur, bilans d'étape, mesure de
  l'avancement sur les données plutôt que sur les déclarations.

## Contribuer

Contributions bienvenues : développeurs, chercheurs, analystes SOC, rédacteurs techniques. Lire
[`CONTRIBUTING.md`](CONTRIBUTING.md) et [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
Vulnérabilité : [`SECURITY.md`](SECURITY.md) — **pas** d'issue publique.

## Licence

[MIT](LICENSE) © CYBERILL — Godwill FOKA, Berlin.

¹ [Documentation de déploiement OpenCTI](https://docs.opencti.io/latest/deployment/overview/)
(consultée le 03/10/2026).

---

<div align="center">

**Construisons ensemble l'alternative européenne en Cyber Threat Intelligence.**

</div>
