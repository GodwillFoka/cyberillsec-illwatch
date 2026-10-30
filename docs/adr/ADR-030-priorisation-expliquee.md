# ADR-030 : Priorisation expliquée des évènements corrélés

- **Statut :** **accepté le 30/10/2026** (revue d'amélioration de Godwill FOKA : rendre la
  priorisation plus utile à chaque organisation, priorité 2)
- **Date :** 2026-10-30
- **Décideurs :** Godwill FOKA
- **Concerne :** ADR-020 (corrélation, score), ADR-021 (comparaison des versions), ADR-014
  (plancher KEV), `illwatch/modules/correlation/explain.py`, `/api/v1/correlations`, écran
  Corrélations

## Contexte

Le score d'un évènement corrélé se décompose déjà en trois parts : la base de la règle, la
criticité de l'actif et le signal (score de la CVE ou confiance de l'IOC). Cette décomposition
répond à « comment le chiffre est-il calculé ? ». Elle ne répond pas aux questions que se pose
l'analyste au moment de choisir quoi traiter d'abord :

- la version installée est-elle *vraiment* dans la plage vulnérable, ou est-ce à vérifier ?
- l'actif est-il exposé sur Internet ?
- la faille est-elle exploitée aujourd'hui, depuis quand, par des rançongiciels ?
- avant quand faut-il agir ?
- que faut-il vérifier avant de mobiliser l'équipe ?

Ces faits sont tous connus (inventaire, CVE, verdict de version, confiance de l'IOC), mais
dispersés dans le détail de l'évènement ou absents de l'écran (l'exposition, par exemple).

## Décision

**Chaque évènement corrélé est accompagné d'une explication de sa priorité, calculée à la
lecture, sans changer le score.**

L'explication contient :

| Élément | Contenu |
|---|---|
| Résumé | une phrase : priorité, score, et les facteurs qui la justifient |
| Facteurs | règle, criticité de l'actif, exposition, exploitation (KEV et date d'entrée, rançongiciel, exploit public, EPSS et percentile), version (pour une CVE) ou confiance et nombre de sources (pour un IOC) |
| Effet de chaque facteur | **pousse** la priorité, la **modère**, **sans effet notable**, ou **à vérifier** ; avec sa part du score quand il en a une |
| Échéance | la plus proche entre le délai de remédiation de la priorité (24 h, 7, 30 ou 90 jours depuis la première détection) et l'échéance fixée par la CISA |
| À vérifier | version non déclarée ou incertaine, actif sans exposition déclarée, indicateur d'une seule source |

## Justification

1. **Le score ne change pas.** Ajouter l'exposition au score aurait modifié une formule
   arbitrée (ADR-020) et rendu les priorités passées incomparables. L'exposition est montrée
   comme un facteur, pas comptée : l'analyste la pèse.
2. **« À vérifier » plutôt que « faux ».** Une version non déclarée n'innocente pas un actif ;
   elle dit qu'il reste une vérification à faire avant d'agir. Le dire évite deux erreurs :
   mobiliser l'équipe pour rien, ou écarter un vrai risque.
3. **L'échéance retient la date la plus proche.** Une faille KEV peut avoir une échéance CISA
   antérieure au délai de la priorité ; c'est elle qui compte pour les organisations soumises à
   la directive BOD 22-01, et elle reste un bon repère pour les autres.
4. **Fonction pure, textes dans la langue de l'instance.** Testable sans base ni serveur, comme
   le moteur de score ; les libellés suivent la langue des textes serveur (ADR-027).

## Conséquences

**Positives**

- L'analyste voit en un coup d'œil pourquoi un évènement passe avant un autre, et ce qu'il doit
  vérifier d'abord.
- L'exposition, déjà saisie dans l'inventaire, sert enfin à la décision.

**Négatives**

- L'exposition repose sur ce que l'inventaire déclare : un actif exposé mais déclaré sans
  adresse apparaîtra « à vérifier ». C'est voulu, mais cela demande un inventaire tenu à jour.
- Les seuils qualitatifs (EPSS d'au moins 10 % pour « pousse la priorité », confiance de 70
  pour un IOC) sont des repères de lecture, pas des règles de calcul ; ils pourront être
  ajustés au vu de la qualité mesurée (ADR-029).
