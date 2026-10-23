# ILLWATCH — Bilan de M9 « SOC Operations » — 14/10/2026

## Critère de sortie

> Un incident traverse L1 → L2 → L3 sans quitter ILLWATCH, MTTR mesuré.

| Constat | Résultat | Preuve |
|---|---|---|
| Parcours complet par l'API (PostgreSQL 16, Python 3.12 et 3.14) | ouverture L1, IOC associés, assignation, escalade L2 motivée, chasse depuis l'incident, faux positif exclu, escalade L3, réponse NIST, clôture ; MTTR et escalades mesurés | `tests/test_soc.py::test_parcours_l1_l2_l3_de_bout_en_bout` (CI, PR #46) |
| Pilotage sur données de démonstration (préproduction locale HTTPS) | MTTA, MTTR, délais cibles, 2 dépassements, niveaux et escalades affichés | captures `12-pilotage`, `04-incident` (branche `captures`) |
| Scénario d'acceptation sur instance réelle | étapes M9 ajoutées (escalades, chasse, recommandations, refus au-delà de L3, MTTR) | `scripts/scenario_soc.py` ; **à rejouer sur Kali** |

**M9 est livré ; sa clôture sera prononcée après le scénario sur Kali** (même règle que M8 :
un jalon est clos quand son critère est constaté sur données réelles).

## Livré (ADR-022)

| Besoin (ROADMAP) | Réponse |
|---|---|
| Triage L1 → faux positif ou escalade | liste d'exclusion des IOC (tâche 3.6) ; évènement corrélé « faux positif » jamais rouvert ; escalade motivée L1 → L2 → L3 |
| Investigation L2 | chasse depuis l'incident (IOC associés, observables relevés, inventaire), rattachée et résumée dans la chronologie ; enrichissement pays/AS dans la fiche IOC |
| L3 | règles de chasse versionnées (version, historique, versions par session) ; recommandations de réponse par phase NIST |
| Dashboard | écran Pilotage (7 / 30 jours) : MTTA, MTTR, délais cibles par sévérité, dépassements, niveaux, escalades, charge par analyste, ouverts/clos par jour |

## Limites

- Les délais cibles sont des valeurs par défaut (critique 1 h / 24 h … faible 72 h / 30 j),
  non paramétrables à ce stade.
- Les comptes n'ont pas de niveau : la traçabilité (qui escalade, qui agit) tient lieu de
  séparation des rôles L1/L2/L3.
- Les recommandations sont des règles déterministes, pas un playbook exécuté (ILLWATCH
  n'agit pas sur le SI).
