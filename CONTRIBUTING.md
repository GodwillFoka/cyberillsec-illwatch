# Contribuer à SENTRY

Merci de l'intérêt que vous portez au projet. Ce document décrit exactement ce qu'on attend d'une
contribution — lisez-le avant d'ouvrir une merge request, il vous évitera un aller-retour.

## Installation de l'environnement

```bash
git clone https://gitlab.com/GodwillFoka/cyberillsec-sentry.git
cd cyberillsec-sentry
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
docker compose up -d
sentry db init
./scripts/ci-local.sh   # pipeline complet sur la base dédiée sentry_test
```

## Stratégie de branches

La branche `main` est sacrée : **aucun commit direct n'y est autorisé.** Chaque tâche part de `main`
dans une branche dédiée, nommée d'après la tâche du planning :

```
feat/T2.1-threat-feed-model
fix/T3.3-cve-parser-bug
docs/T6.2-hunting-rules-guide
```

## Format des commits — Conventional Commits

```
<type>(<scope>): <description à l'impératif, en minuscules>
```

Types : `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`, `ci`.
Scopes usuels : `feeds`, `cve`, `incidents`, `dashboard`, `hunting`, `database`, `cli`, `api`.

```
feat(feeds): add STIX 2.1 parser for alienvault otx
test(cve): add unit tests for composite risk scoring formula
fix(database): resolve asyncpg connection pool timeout
docs(onboarding): update day-1 guide for docker compose setup
```

## Les quatre piliers de qualité

Ils ne sont pas négociables et la CI les vérifie sur chaque MR.

**1. Typage strict.** Toute signature de fonction est typée. `mypy` tourne en mode strict.

```python
# BON
async def calculate_risk(cve_id: str, cvss: float, is_kev: bool) -> float: ...


# REFUSÉ
def calculate_risk(cve_id, cvss, is_kev): ...
```

**2. Lint et formatage.** `ruff check .` et `ruff format .` avant chaque commit. Aucune ligne au-delà
de 100 caractères.

**3. Tests obligatoires.** Toute nouvelle route d'API ou fonction de calcul est accompagnée de son
test dans `tests/`. Taux de succès : 100 %. Couverture globale : ≥ 80 %.

**4. Gestion des exceptions.** Jamais de `except: pass`. Chaque exception est typée, tracée et
porteuse d'un message exploitable.

## Architecture — la règle d'or

Un contrôleur d'API ne fait **jamais** de calcul métier ni de requête SQL complexe. Il valide les
paramètres d'entrée, appelle la couche `sentry/modules/`, et retourne un schéma Pydantic.

Si votre MR met de la logique métier dans `sentry/app/api/`, elle sera refusée — pas par sévérité,
mais parce que cette logique devient alors intestable sans serveur HTTP.

## Cycle de contribution

1. **Synchroniser** — `git checkout main && git pull origin main`
2. **Brancher** — `git checkout -b feat/T3.6-cve-alerting`
3. **Développer** — dans le sous-module approprié
4. **Tester** — écrire le test, puis `pytest -v`
5. **Vérifier** — `ruff check . && ruff format --check . && mypy sentry`
6. **Committer et pousser** — message Conventional Commits
7. **Ouvrir la MR** vers `main`, en renseignant les critères de validation testés
8. **Fusion** une fois la CI verte et la revue approuvée

## Ce qui fait une bonne merge request

- Une seule préoccupation par PR. Une MR qui corrige un bug *et* refactorise trois modules sera
  renvoyée en découpage.
- La description explique le *pourquoi*, pas le *quoi* — le diff dit déjà le quoi.
- Les décisions d'architecture structurantes passent par un ADR dans `docs/adr/` avant le code.
- Une MR qui change le comportement du scoring ou de la machine d'état modifie aussi ses tests, et
  la description justifie l'écart par rapport au Cahier des Charges.

## Signaler un bug

Ouvrez une issue avec : la version ou le commit, les étapes de reproduction, le comportement attendu
et le comportement observé, les logs pertinents. Une vulnérabilité de sécurité passe par
[`SECURITY.md`](SECURITY.md), pas par une issue publique.

## Code de conduite

Toute interaction dans ce projet est régie par [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
