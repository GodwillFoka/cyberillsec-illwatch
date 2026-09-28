# Architecture Decision Records

Un ADR trace une décision structurante : son contexte, l'arbitrage rendu, sa justification et ses
conséquences. On en écrit un quand la décision est coûteuse à revenir dessus, quand deux documents
se contredisent, ou quand le choix surprendra quelqu'un qui arrive sur le projet dans six mois.

| ADR | Titre | Statut |
|---|---|---|
| [001](ADR-001-scoring-composite.md) | Formule du score de risque composite | Accepté |
| [002](ADR-002-hebergement-gitlab.md) | GitLab comme dépôt principal, abandon de GitHub | Accepté |
| [003](ADR-003-authentification-phase-1.md) | Authentification JWT livrée dès la phase 1 | Accepté |
| [004](ADR-004-recalage-planning.md) | Recalage du planning sur la fin réelle de la phase 1 | Proposé |
| [005](ADR-005-cycle-de-vie-ioc.md) | Cycle de vie et déduplication des IOC | Proposé |
| [006](ADR-006-provenance-multi-sources.md) | Provenance multi-sources, OTX et collecte planifiée | Proposé |

## Gabarit

```markdown
# ADR-NNN — Titre

- **Statut :** proposé / accepté / remplacé par ADR-XXX
- **Date :** AAAA-MM-JJ
- **Décideurs :**
- **Concerne :** module, exigence

## Contexte
Ce qui force une décision. Les faits, pas les opinions.

## Décision
Ce qui est décidé, en une phrase affirmative.

## Justification
Pourquoi cette option plutôt que les autres. Les options écartées et leur raison.

## Conséquences
Positives et négatives. Les négatives sont obligatoires : une décision sans coût n'en est pas une.

## Suivi
Les actions ouvertes que cette décision crée.
```
