# Contribuer à ILLWATCH

Merci de vouloir rejoindre l'aventure. Que vous corrigiez une coquille ou ajoutiez une source de
renseignement, chaque contribution compte. Ce document vous dit exactement ce que nous attendons
d'une contribution. Prenez cinq minutes pour le lire avant d'ouvrir une merge request : vous vous
épargnerez un aller-retour, et nous aussi.

## Préparer votre environnement

```bash
git clone https://gitlab.com/GodwillFoka/cyberillsec-illwatch.git
# miroir : https://github.com/GodwillFoka/cyberillsec-illwatch.git
cd cyberillsec-illwatch
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
docker compose up -d
illwatch db init
./scripts/ci-local.sh   # pipeline complet sur la base dédiée illwatch_test
```

Si `ci-local.sh` passe au vert chez vous, il y a de fortes chances qu'il passe aussi en CI.

## Les branches

La branche `main` est sacrée : **personne n'y commite directement**, pas même les responsables du
projet. Chaque tâche part de `main` dans sa propre branche, nommée d'après la tâche du planning :

```
feat/T2.1-threat-feed-model
fix/T3.3-cve-parser-bug
docs/T6.2-hunting-rules-guide
```

## Les messages de commit : Conventional Commits

Un historique lisible est un cadeau pour la personne qui, dans six mois, cherchera pourquoi une
ligne a changé. Nous suivons donc ce format :

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

Ils ne se négocient pas, et la CI les vérifie sur chaque MR. Ce n'est pas de la rigidité : un
outil de sécurité qui casse en production fait plus de mal que de bien.

**1. Typage strict.** Toute signature de fonction est typée, et `mypy` tourne en mode strict.

```python
# BON
async def calculate_risk(cve_id: str, cvss: float, is_kev: bool) -> float: ...


# REFUSÉ
def calculate_risk(cve_id, cvss, is_kev): ...
```

**2. Lint et formatage.** Lancez `ruff check .` et `ruff format .` avant chaque commit. Aucune
ligne ne dépasse 100 caractères.

**3. Des tests, toujours.** Toute nouvelle route d'API ou fonction de calcul arrive avec son test
dans `tests/`. Taux de succès attendu : 100 %. Couverture globale : 80 % au moins.

**4. Des exceptions qui parlent.** Jamais de `except: pass`. Chaque exception est typée, tracée,
et porte un message qui aide vraiment la personne qui la lira.

## La règle d'or de l'architecture

Un contrôleur d'API ne fait **jamais** de calcul métier ni de requête SQL complexe. Son travail
se résume à trois gestes : valider les paramètres d'entrée, appeler la couche
`illwatch/modules/`, renvoyer un schéma Pydantic.

Une MR qui place de la logique métier dans `illwatch/app/api/` sera refusée. Pas par principe,
mais parce que cette logique deviendrait impossible à tester sans démarrer un serveur HTTP.

## Le cycle d'une contribution

1. **Synchroniser** : `git checkout main && git pull origin main`
2. **Brancher** : `git checkout -b feat/T3.6-cve-alerting`
3. **Développer** dans le sous-module approprié
4. **Tester** : écrire le test, puis `pytest -v`
5. **Vérifier** : `ruff check . && ruff format --check . && mypy illwatch`
6. **Committer et pousser**, avec un message Conventional Commits
7. **Ouvrir la MR** vers `main`, en précisant les critères de validation testés
8. **Fusionner** une fois la CI verte et la revue approuvée

## Ce qui fait une bonne merge request

- **Une seule préoccupation par MR.** Une MR qui corrige un bug *et* refactorise trois modules
  vous sera renvoyée pour être découpée : on relit mieux ce qui est petit.
- **La description explique le *pourquoi*.** Le *quoi*, le diff le dit déjà.
- **Les décisions structurantes passent d'abord par un ADR** dans `docs/adr/`, avant la première
  ligne de code.
- **Toucher au scoring ou à la machine d'état engage.** La MR modifie aussi les tests concernés,
  et sa description justifie l'écart avec le Cahier des Charges.

## Signaler un bug

Ouvrez une issue avec la version ou le commit, les étapes pour reproduire, ce que vous attendiez,
ce que vous avez obtenu, et les logs utiles. Plus le signalement est précis, plus la correction
est rapide. Une vulnérabilité de sécurité, en revanche, passe par [`SECURITY.md`](SECURITY.md) et
jamais par une issue publique.

## Code de conduite

Toutes les interactions dans ce projet sont régies par [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
