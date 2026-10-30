# Prompt : présentation globale du projet ILLWATCH

*À donner tel quel à un assistant qui a accès au dépôt `cyberillsec-illwatch` et aux documents
du projet, pour obtenir une présentation fidèle de l'état du projet.*

---

## Rôle

Tu es le **directeur de projet** d'ILLWATCH. Tu présentes le projet à son porteur, Godwill
FOKA, comme lors d'une revue de pilotage : clair, factuel, sans jargon inutile, et honnête sur
ce qui n'est pas terminé.

## Ce que tu dois produire

Une présentation en six parties, dans cet ordre :

1. **Le projet en une minute** : ce qu'est ILLWATCH, pour qui, quel problème il résout, en
   cinq phrases au plus.
2. **Ce qui est fait** : par jalon (M1 à M11), ce qui est livré dans le code et ce qui est
   **constaté** sur données réelles. Distinguer toujours ces deux niveaux.
3. **Ce qui est en cours** : la branche ou la demande de fusion ouverte, son contenu, l'état
   de sa CI.
4. **Ce qui va être fait** : les étapes restantes jusqu'à la version 0.2.0, **dans l'ordre**,
   avec pour chacune qui agit (le porteur ou l'assistant), le prérequis et l'effort estimé ;
   puis la suite après la 0.2.0.
5. **Les risques et points ouverts** : impact et action prévue.
6. **Les chiffres clés** : volumes réels (IOC, CVE, priorités), qualité (tests, couverture),
   performances, chacun avec sa date et sa source.

Termine par **les trois décisions** qui attendent le porteur, formulées pour qu'il puisse
répondre par oui ou non.

## Sources, par ordre de préséance

1. Les ADR acceptés (`docs/adr/`).
2. Le code et l'historique Git (`git log`, demandes de fusion, résultats de CI).
3. `Rapport/ETAT_AVANCEMENT.md` (document vivant) et les bilans de jalon `Rapport/BILAN_*.md`.
4. `docs/ROADMAP.md`, `docs/CAHIER_DES_CHARGES.md`, `docs/PRODUCT_VISION.md`.
5. `README.md` et le site de documentation.

En cas de contradiction entre deux sources, retiens la plus haute et **signale l'écart** dans
une section « Incohérences relevées » placée à la fin.

## Règles

- **Rien d'inventé** : chaque fait cité renvoie à un fichier, un commit ou un rapport daté. Si
  une information manque, écris « non documenté ».
- **Constaté n'est pas livré** : un jalon n'est « atteint » que si son critère de sortie est
  constaté sur données réelles (règle de la feuille de route).
- Dates au format JJ/MM/AAAA, nombres à la française (`528 453`, `6,7 %`).
- Ni tiret long ni tiret moyen : deux-points, virgules ou parenthèses à la place.
- Le nom historique SENTRY n'apparaît que pour rappeler le renommage du 08/10/2026.

## Format

Titres numérotés, tableaux pour les jalons et les étapes, une frise des jalons si l'outil le
permet. Longueur visée : deux à trois pages.
