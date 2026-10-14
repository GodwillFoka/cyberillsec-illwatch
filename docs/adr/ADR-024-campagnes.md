# ADR-024 — M10, incrément 2 : campagnes et infrastructure

- **Statut :** **accepté le 15/10/2026** (décision de Godwill FOKA : « attaque M10 »)
- **Date :** 2026-10-15
- **Décideurs :** Godwill FOKA
- **Concerne :** ADR-023 (ATT&CK), ROADMAP M10 (« acteur → campagne → malware → infrastructure
  → IOC → TTP »)

## Contexte

ADR-023 attribue un acteur seulement quand son nom figure dans le renseignement. Une
infrastructure connue d'une opération (adresses, domaines d'un même pulse ou d'un même
rapport) n'était reliée à rien.

## Décision

1. **Campagne** (`campaigns`) : nom, description, acteur ATT&CK facultatif (identifiant G… ou
   S…, sans clé étrangère : le référentiel est remplacé à chaque import). Son
   **infrastructure** est l'ensemble des IOC rattachés (`campaign_indicators`).
2. **Rattachement** par valeurs (IOC déjà connus) ou par **description** (tous les IOC dont la
   description par leur source contient un texte : le nom d'un pulse OTX, d'un rapport), 5 000
   au plus par opération, sans doublon.
3. **Attribution par l'infrastructure, d'abord** : une détection (correspondance de chasse,
   évènement corrélé, incident) qui touche un IOC rattaché affiche la campagne et son acteur
   (« campagne « … » »), avant les acteurs simplement cités par leur nom.
4. Écran **Campagnes**, `/api/v1/campaigns`, `illwatch campaigns create | attach | list`.
   Modifier : analystes et administrateurs ; supprimer : administrateurs (les IOC restent).

## Conséquences

- (+) La chaîne acteur → campagne → infrastructure → IOC → technique est complète et
  explicable à l'écran.
- (−) Les campagnes sont saisies par les analystes ; la création automatique (un pulse OTX =
  une campagne) reste une piste, au risque de multiplier les campagnes sans valeur.
- Migration `e2c7a5b9d184`.
