# ADR-004 — Recalage du planning sur la date réelle de fin de phase 1

- **Statut :** proposé
- **Date :** 2026-09-23
- **Décideurs :** à valider par le porteur du projet
- **Concerne :** §5.1 et §5.2 du Cahier des charges, feuille de route du README

## Contexte

Le macro-planning prévoit M1 au 05/08/2026 et la v1.0 au 30/09/2026. Au 23/09/2026, le dépôt
contient un seul commit et la phase 1 se termine à peine. Le calendrier n'est plus un outil de
pilotage : chaque jalon apparaît en retard sans que cela dise quoi que ce soit du rythme réel.

## Décision

Conserver la durée relative de chaque phase et décaler le planning à partir de la validation de M1
le 24/09/2026 :

| Phase | Fenêtre | Jalon |
|---|---|---|
| P1 Foundation | → 24/09/2026 | M1 — 24/09/2026 |
| P2 Threat Feeds | 25/09 – 08/10 | M2 — 08/10/2026 |
| P3 CVE Tracker | 09/10 – 22/10 | M3 — 22/10/2026 |
| P4 Incidents | 23/10 – 05/11 | M4 — 05/11/2026 |
| P5 SOC Dashboard | 06/11 – 12/11 | M5 — 12/11/2026 |
| P6 Threat Hunting | 13/11 – 19/11 | v1.0 — 19/11/2026 |

## Justification

La durée relative des phases reflète la complexité estimée dans le Cahier des charges ; rien dans
la phase 1 ne la remet en cause. Une partie de la logique des phases 2 à 4 est déjà écrite et testée
(scoring, machine d'état, validation des IOC), ce qui donne une marge sur P3 et P4.

## Conséquences

- Positives : les bilans du jeudi mesurent de nouveau un écart réel.
- Négatives : la v1.0 glisse de sept semaines. Les charges horaires du §5.1 (51 h au total) restent
  à confronter à la vélocité mesurée à M2 ; si P2 dépasse sa fenêtre, recaler de nouveau plutôt
  que compresser P5 et P6.

## Suivi

- Une fois accepté : mettre à jour §5.1, §5.2 du Cahier des charges et la feuille de route du README.
