# ADR-017, M8 Detection & Correlation : confiance des IOC d'abord, corrélation ensuite

- **Statut :** **accepté le 11/10/2026** (décision de Godwill FOKA : « Démarrer M8 »)
- **Date :** 2026-10-11
- **Décideurs :** Godwill FOKA
- **Concerne :** feuille de route M8, ADR-001 (score des CVE), ADR-006 (provenance des IOC)

## Contexte

M8 doit faire passer ILLWATCH de l'agrégation à la détection : « un évènement corrélé produit une
alerte priorisée », avec un taux de faux positifs mesuré. Aujourd'hui, un IOC n'a qu'une
**gravité** (déclarée par la source) : rien ne dit si l'on peut **agir** dessus. Or une règle de
corrélation qui croise des IOC peu fiables produit des faux positifs en cascade. La confiance
est donc le socle des incréments suivants. Le 11/10, la préproduction publique (VPS) a été
reportée : M8 démarre pendant que M7 attend son hébergement.

## Décision

M8 est livré en quatre incréments, dans cet ordre :

1. **Confiance des IOC** (ce lot, livré) : score 0-100 calculé à la lecture, avec sa
   décomposition :
   - *Sources* (60 points) : 1 − Π(1 − wᵢ) sur les sources distinctes, wᵢ selon la cote de
     fiabilité de la source (échelle de l'Amirauté, OTAN AJP-2.1) : A 0,90 · B 0,75 · C 0,50 ·
     D 0,30 · E 0,15 · F 0,10. Un IOC soumis à la main compte comme une source C.
   - *Fraîcheur* (30 points) : 30 × 0,5^(âge / demi-vie), demi-vie par type : IP 7 j, URL
     14 j, domaine 30 j, e-mail 60 j, empreintes 180 j.
   - *Récurrence* (10 points) : 2,5 × log₂(observations), plafonnée.
   - Niveaux : élevée ≥ 70, moyenne ≥ 40, faible en dessous.
   - Cote de fiabilité par source (`threat_feeds.reliability`, « C » par défaut), réglée par
     l'administrateur ; sources de référence : abuse.ch et IPsum en B, OTX en D, les autres C.
2. **Enrichissement local** (livré le 12/10, ADR-019) : ASN et pays depuis la base DB-IP Lite
   importée localement (aucune requête sortante par IOC) ; âge des domaines reporté.
3. **Corrélation** (livrée le 13/10, ADR-020) : inventaire d'actifs, règles KEV × actif,
   exploit × actif, actif × IOC → évènement corrélé priorisé ; la confiance filtre les IOC
   éligibles (seuil paramétrable, « moyenne » par défaut).
4. **Mesure** (livrée le 13/10, ADR-020) : jeu de données figé et versionné, 100 % des cas
   attendus détectés, 0 % de faux positifs sur ce jeu, vérifié par la CI ; mesure sur données
   réelles avec le premier pilote.

## Justification

- **Confiance avant corrélation** : sans elle, la corrélation amplifie le bruit. Elle est aussi
  directement utile à l'analyste (écran Indicateurs, tri du triage).
- **Échelle de l'Amirauté** plutôt qu'une note libre : standard du renseignement (OTAN, ANSSI,
  TLP/PAP l'accompagnent souvent), compréhensible sans formation, six crans suffisent.
- **Calcul à la lecture** plutôt que colonne stockée : la fraîcheur change à chaque instant ;
  stocker obligerait à recalculer 528 000 lignes chaque nuit. Le calcul porte sur une page
  (50 IOC, une requête pour les cotes) : coût négligeable. Écarté pour l'instant : filtrer ou
  trier toute la base par confiance (nécessitera une colonne matérialisée, incrément 3).
- **Demi-vies par type** : une IP de VPS change de locataire en jours, une empreinte de
  maliciel reste vraie ; un âge unique aurait sous-noté les empreintes ou sur-noté les IP.
- Écarté : pondérer par la gravité. Gravité et confiance sont deux axes ; les mélanger
  cacherait un IOC grave mais douteux, exactement celui qu'un analyste doit vérifier.

## Conséquences

- Positives : chaque IOC porte une confiance justifiable point par point (comme le score des
  CVE, ADR-001) ; l'administrateur règle la fiabilité de ses sources ; base saine pour la
  corrélation.
- Négatives : les coefficients sont des choix d'expert, **non encore calibrés** (calibration
  prévue à l'incrément 4 sur le jeu figé) ; pas de tri ni de filtre global par confiance tant
  que le score n'est pas matérialisé ; une cote de fiabilité mal réglée biaise tous les IOC de
  la source (d'où le réglage réservé à l'administrateur et journalisé).

## Suivi

- Incrément 2 : ✅ DB-IP Lite (CC BY 4.0), ADR-019.
- Incréments 3 et 4 : ✅ ADR-020 ; restent la colonne de confiance matérialisée (tri global) et la mesure sur l'inventaire d'un pilote.
