# Guide d'onboarding — Day-1 Survival Guide

Ce guide te prend par la main pour configurer ton poste et livrer ta première fonctionnalité en
moins d'une heure. Il est écrit pour quelqu'un qui n'a jamais fait de cybersécurité : le
[lexique du Cahier des charges](CAHIER_DES_CHARGES.md#13-lexique-du-développeur-cyber) explique
CVE, CVSS, EPSS, KEV, IOC et TTP sans jargon. Lis-le d'abord si ces sigles ne te parlent pas.

## 1. Prérequis

- Linux (Kali Linux, Ubuntu 22.04+ ou Debian 12), macOS, ou WSL2 sous Windows
- Kali Linux : `sudo apt install -y docker.io docker-compose python3-venv` puis
  `sudo usermod -aG docker $USER` et reconnexion
- Python 3.12 ou supérieur — `python3 --version`
- Git — `git --version`
- Docker et Docker Compose — `docker compose version`

## 2. Installation

```bash
# 1. Cloner le dépôt
git clone https://gitlab.com/GodwillFoka/cyberillsec-sentry.git
# miroir : https://github.com/GodwillFoka/cyberillsec-sentry.git
cd cyberillsec-sentry

# 2. Environnement virtuel isolé
python3.12 -m venv .venv
source .venv/bin/activate        # Windows : .venv\Scripts\activate

# 3. Dépendances (production + outils de développement)
pip install --upgrade pip
pip install -e ".[dev]"

# 4. Configuration locale
cp .env.example .env
#    puis génère une vraie clé :  openssl rand -hex 32  →  SECRET_KEY

# 5. Infrastructure locale
docker compose up -d             # PostgreSQL 16 + Redis 7

# 6. Migrations de schéma, données de référence et premier compte
sentry db init
sentry seed
sentry users create --username admin --email admin@example.org --role admin

# 7. Vérification — SQLite par défaut ; PostgreSQL si DATABASE_URL est exportée
pytest
./scripts/ci-local.sh   # pipeline complet sur la base dédiée sentry_test

# 8. Serveur en rechargement automatique
uvicorn sentry.app.main:app --reload --host 0.0.0.0 --port 8000
```

Ouvre <http://localhost:8000/docs> : la documentation Swagger interactive doit s'afficher.
Vérifie aussi <http://localhost:8000/health>, qui doit répondre `{"status":"ok", …}` avec
`"database":"connected"`.

## 3. Le dépôt, dossier par dossier

```
cyberillsec-sentry/
├── .gitlab-ci.yml           Pipeline CI/CD (qualité, tests, build, sécurité)
├── .gitlab/                 Gabarits de merge requests et d'issues
├── alembic/
│   └── versions/            Historique immuable des migrations SQL
├── docs/
│   ├── CAHIER_DES_CHARGES.md   Spécification opposable — la référence
│   ├── PRODUCT_VISION.md       Vision stratégique
│   ├── ARCHITECTURE.md         Comment le code est organisé et pourquoi
│   ├── ONBOARDING.md           Ce fichier
│   ├── adr/                    Décisions d'architecture tracées
│   └── pdf/                    Documents fondateurs d'origine
├── Rapport/                 Bilans hebdomadaires du jeudi
├── sentry/                  Code source applicatif
│   ├── app/
│   │   ├── api/             Contrôleurs et routes REST
│   │   ├── models/          Modèles relationnels SQLAlchemy
│   │   ├── config.py        Variables d'environnement typées Pydantic
│   │   ├── database.py      Moteur et sessions asynchrones
│   │   └── main.py          Point d'entrée FastAPI
│   ├── cli/                 Commandes Click (`sentry …`)
│   ├── modules/             Modules métier indépendants
│   │   ├── threat_feeds/    Collecte, parseurs, IOC
│   │   ├── cve_tracker/     NVD, EPSS, KEV, scoring
│   │   ├── incidents/       Machine d'état, timeline
│   │   ├── dashboard/       Agrégation et exports
│   │   └── threat_hunting/  Moteur de règles
│   └── shared/              Énumérations et utilitaires transverses
├── tests/                   Suite Pytest
├── docker-compose.yml
└── pyproject.toml           Ruff, mypy, pytest, dépendances
```

**Où écrire ton code ?** La logique métier va dans `sentry/modules/<module>/`. La route qui
l'expose va dans `sentry/app/api/v1/`. Le test va dans `tests/`. Si tu hésites, relis
[`ARCHITECTURE.md`](ARCHITECTURE.md).

## 4. Standards d'ingénierie

Quatre piliers, vérifiés automatiquement par la CI.

**Typage strict.** Toute signature est typée. `mypy` tourne en mode strict.

```python
# BON
async def calculate_risk(cve_id: str, cvss: float, is_kev: bool) -> float: ...


# REFUSÉ
def calculate_risk(cve_id, cvss, is_kev): ...
```

**Lint et formatage.** `ruff check .` et `ruff format .` avant chaque commit. 100 caractères max.

**Tests obligatoires.** Toute nouvelle route ou fonction de calcul est accompagnée de son test.
Succès : 100 %. Couverture : ≥ 80 %.

**Exceptions.** Jamais de `except: pass`. Chaque exception est typée, tracée, avec un message
exploitable par celui qui lira les logs à 3 h du matin.

## 5. GitFlow et commits

La branche `main` est sacrée : aucun commit direct. Chaque tâche part de `main` :

```bash
git checkout main && git pull origin main
git checkout -b feat/T3.6-cve-alerting
```

Format des messages — [Conventional Commits](https://www.conventionalcommits.org/fr/) :

```
feat(feeds): add STIX 2.1 parser for alienvault otx
test(cve): add unit tests for composite risk scoring formula
fix(database): resolve asyncpg connection pool timeout
docs(onboarding): update day-1 guide for docker compose setup
```

## 6. Ta première tâche, pas à pas

1. **Synchroniser** — `git checkout main && git pull origin main`
2. **Brancher** — `git checkout -b feat/T2.1-threat-feed-model`
3. **Développer** — dans le sous-module concerné
4. **Tester** — écris le test dans `tests/`, puis `pytest -v`
5. **Vérifier le style** — `ruff check . && ruff format --check . && mypy sentry`
6. **Committer et pousser**
   ```bash
   git add .
   git commit -m "feat(feeds): implement threat feed model and migration"
   git push origin feat/T2.1-threat-feed-model
   ```
7. **Ouvrir la MR** vers `main` en renseignant les critères de validation testés
8. **Fusion** dès que la CI est verte et la revue approuvée

## 7. Commandes du quotidien

```bash
# Qualité complète, comme la CI
ruff check . && ruff format --check . && mypy sentry && pytest

# Un seul test, en verbeux
pytest tests/test_scoring.py::test_score_maximal_borne_a_100 -v

# Rapport de couverture HTML
pytest --cov-report=html && open htmlcov/index.html

# Nouvelle migration après modification d'un modèle
alembic revision --autogenerate -m "add threat_feeds table"
alembic upgrade head

# CLI
sentry version
sentry config
sentry db check
sentry db current
```

## 8. Problèmes fréquents

| Symptôme | Cause probable | Correctif |
|---|---|---|
| `connection refused` sur le port 5433 | Conteneurs non démarrés | `docker compose up -d` puis `docker compose ps` |
| `Target database is not up to date` | Migrations en retard | `sentry db upgrade` |
| `ValidationError` au démarrage | `.env` absent ou incomplet | `cp .env.example .env` et renseigner `SECRET_KEY` |
| `SECRET_KEY par défaut interdite en production` | `ENVIRONMENT=production` avec la clé d'exemple | `openssl rand -hex 32` → `SECRET_KEY` |
| Tests `postgres` marqués *skipped* | `DATABASE_URL` non exportée : suite lancée sur SQLite | `./scripts/ci-local.sh` (base `sentry_test`) |
| `Base « sentry » refusée` | `DATABASE_URL` pointe vers la base de travail | Utiliser une base dont le nom finit par `_test` |
| Les tests passent en local, échouent en CI | Dépendance à un état local | Les tests doivent créer leurs propres données ; voir `tests/conftest.py` |
| HTTP 429 depuis NVD | Rate limit sans clé API | Demander une clé sur nvd.nist.gov et renseigner `NVD_API_KEY` |
| Une source reste `DEGRADED` | Hôte injoignable, clé absente ou format changé | `sentry feeds probe <nom>` : joignable ? identifiants acceptés ? IOC produits ? |
| HTTP 429 sur `/auth/token` | 5 échecs de connexion en 15 min | Attendre 15 min (`LOGIN_WINDOW_SECONDS`) ou vider la clé Redis `sentry:login:user:<nom>` |
| Tests réseau marqués *skipped* | Tests `live` désactivés par défaut | `SENTRY_LIVE_TESTS=1 pytest tests/test_live_sources.py --no-cov` |

## 9. Bilan hebdomadaire

Chaque jeudi soir, sans exception, l'avancement de la semaine est compilé dans `Rapport/NN_date.md`
et poussé sur le dépôt. Le gabarit est dans [`../Rapport/TEMPLATE.md`](../Rapport/TEMPLATE.md).

---

Une question sans réponse dans ce guide ? Ouvre une issue avec le label `question` — si tu t'es posé
la question, quelqu'un d'autre se la posera.
