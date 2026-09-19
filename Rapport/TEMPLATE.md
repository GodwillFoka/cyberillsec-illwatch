# 📊 SENTRY — Rapport d'avancement hebdomadaire [Semaine NN/9]

**Date :** JJ/MM/AAAA · **Auteur :** [Nom] · **Jalon cible :** [M1 … M5 / v1.0]

## 1. Résumé exécutif

Cinq lignes maximum, à destination du management et du RSSI. Ce qui a avancé, ce qui est en risque,
ce qui est décidé.

## 2. Détail technique des tâches traitées

- [x] **Tâche X.X** — description technique, commits associés, fichiers créés ou modifiés.
- [x] **Tâche X.X** — tests rédigés et résultats d'exécution.
- [ ] **Tâche X.X** — reportée : raison et nouvelle échéance.

## 3. Analyse SWOT de la semaine

- **Forces :** composants stables et performants livrés.
- **Faiblesses :** dette technique identifiée, documentation incomplète.
- **Opportunités :** optimisations découvertes en cours de développement.
- **Menaces :** blocages externes, retards potentiels.

## 4. Problèmes rencontrés et solutions

| Blocage | Impact | Solution adoptée | Statut |
|---|---|---|---|
| ex. rate limit NVD à 5 req/30 s sans clé | Collecte 6× plus lente | Demande de clé API + cache Redis 24 h | Résolu |

## 5. Métriques qualité

| Indicateur | Valeur | Seuil |
|---|---|---|
| Couverture `pytest` | XX % | ≥ 80 % |
| Tests passants | XX / XX | 100 % |
| Conformité `ruff` | OK / KO | 100 % |
| `mypy --strict` | OK / KO | 0 erreur |
| Commits sur la semaine | XX | — |
| Pull requests fusionnées | XX | — |

## 6. Prochaine semaine

Les tâches engagées et le jalon visé.
