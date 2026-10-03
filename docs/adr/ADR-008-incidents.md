# ADR-008 — Gestion d'incidents : chronologie immuable et incident issu d'une alerte

- **Statut :** proposé
- **Date :** 2026-10-03
- **Décideurs :** à valider par le porteur du projet
- **Concerne :** MOD-04, RF-17 à RF-20, tables `incidents`, `incident_events`,
  `incident_indicators`, `incident_cves`, `sentry/modules/incidents/`

## Contexte

La machine d'état NIST SP 800-61 existait sans API. NIS 2 et DORA exigent de pouvoir prouver,
après coup, qui a fait quoi et quand pendant un incident : la chronologie est une pièce
d'audit, pas un journal technique.

## Décision

1. Toute action passe par `modules/incidents/service.py` et écrit un événement **dans la même
   transaction** que le changement qu'il décrit (pas d'événement, pas de changement).
2. **Immuabilité à deux niveaux** : écouteurs ORM qui refusent `UPDATE`/`DELETE` d'un
   événement, et déclencheur PostgreSQL (`trg_incident_events_immutable`) qui les refuse même
   en SQL direct. Aucune route de suppression d'incident.
3. Un incident clos est **gelé** : ni transition, ni assignation, ni lien ; les commentaires
   restent possibles (retour d'expérience).
4. Une alerte CVE ouvre un incident en un appel (`POST /api/v1/alerts/{id}/incident`) :
   sévérité dérivée de la priorité SOC, CVE associée, alerte acquittée ; idempotent grâce à une
   contrainte d'unicité sur `source_alert_id`.

## Conséquences

- **Positives** : chronologie opposable ; passage alerte → réponse sans ressaisie.
- **Négatives** : une erreur de saisie dans un commentaire ne se corrige que par un nouveau
  commentaire ; supprimer un incident de test exige un accès administrateur à la base (désactiver
  le déclencheur) — c'est voulu.
