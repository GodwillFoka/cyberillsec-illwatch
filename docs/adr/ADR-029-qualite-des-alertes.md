# ADR-029 : Mesurer la qualité des alertes en situation réelle

- **Statut :** **accepté le 30/10/2026** (revue d'amélioration de Godwill FOKA : mesurer la
  qualité des alertes en situation réelle, priorité 1)
- **Date :** 2026-10-30
- **Décideurs :** Godwill FOKA
- **Concerne :** ADR-020 (corrélation), ADR-022 (opérations SOC, pilotage), ADR-009 (chasse),
  ADR-007 (alertes CVE), `illwatch/modules/soc/quality.py`, `GET /api/v1/dashboard/quality`,
  écran Pilotage, `illwatch soc quality`

## Contexte

M8 a été clos sur un jeu figé : 100 % des cas attendus détectés, 0 % de faux positifs. Ce
chiffre dit que les règles *savent* détecter. Il ne dit pas si elles *aident* une équipe : sur
des données réelles, combien d'alertes ont mené à un incident, combien ont été écartées,
combien sont restées sans réponse, et en combien de temps ?

Les réponses existent déjà dans la base, éparpillées : `cve_alerts` (acquittement, incident
ouvert depuis l'alerte), `correlated_events` (incident, faux positif qualifié, clôture par le
moteur), `hunting_matches` (IOC associé à un incident), `exclusions` (faux positifs), et
`indicator_sources` (quelle source a rapporté quel IOC). L'écran Pilotage ne montrait qu'un
total de faux positifs, sans dire quelle règle ni quelle source les produisait.

## Décision

**ILLWATCH mesure, sur 7, 30 ou 90 jours, ce que sont devenus les signaux de chaque règle et
de chaque source, à partir des tables existantes, sans rien stocker de plus.**

Issues d'un signal, par famille :

| Famille | Unité | Confirmé | Faux positif | Ignoré | Clos par le moteur | En attente |
|---|---|---|---|---|---|---|
| Alerte CVE, par déclencheur (`kev`, `epss`, `nvd`) | alerte | incident ouvert depuis l'alerte, ou CVE associée à un incident après l'alerte | (sans objet) | acquittée sans incident | (sans objet) | non acquittée |
| Corrélation, par règle (CORR-01 à 03) | évènement | incident ouvert | qualifié par un analyste | acquitté sans suite | ne correspondait plus, sans geste d'analyste | ouvert |
| Chasse, par règle (RULE-01 à 06) | observable distinct | IOC associé à un incident | valeur en liste d'exclusion | (sans objet) | (sans objet) | non qualifiée |

Par **source** : IOC distincts à l'origine d'une corrélation ou d'une chasse, IOC associés à
un incident, IOC mis en liste d'exclusion.

Indicateurs dérivés :

- **précision** = confirmés / (confirmés + faux positifs), absente tant qu'aucun signal n'est
  qualifié (on n'affiche pas 0 % ni 100 % sur rien) ;
- **bruit** = (faux positifs + ignorés) / signaux traités par un analyste ;
- **délai de traitement** : de l'apparition du signal au geste de l'analyste (acquittement,
  faux positif, ouverture d'incident), en moyenne et en médiane.

## Justification

1. **Rien de nouveau à saisir.** Les analystes font déjà ces gestes ; les compter ne leur
   demande aucun effort supplémentaire, donc la mesure ne se dégrade pas avec la fatigue.
2. **Calcul à la demande, sans table nouvelle.** Chaque chiffre se recalcule et se vérifie
   ligne à ligne. Une table d'agrégats aurait été plus rapide, mais il aurait fallu la
   maintenir cohérente avec des évènements qui se rouvrent et des exclusions qui expirent.
3. **Agrégats SQL pour la chasse et les sources.** La chasse quotidienne sur toute la base
   peut produire des milliers de correspondances ; on les compte en base, sans les charger.
4. **Observables distincts pour la chasse.** Sans cela, la chasse quotidienne retrouverait
   chaque jour le même IOC et gonflerait artificiellement le volume d'une règle.
5. **Précision plutôt que taux de faux positifs.** C'est la question que pose un analyste :
   « quand cette règle sonne, ai-je raison de m'arrêter ? ».

Options écartées : un bouton « utile / inutile » sur chaque alerte (une saisie de plus,
abandonnée en quelques semaines dans la plupart des SOC) ; une mesure par analyste (la charge
existe déjà dans Pilotage, et noter les personnes n'est pas l'objet).

## Conséquences

**Positives**

- Une règle bruyante ou une source peu fiable se voit en chiffres, et l'on peut agir : régler
  la règle, baisser la fiabilité de la source, compléter l'inventaire.
- Le chiffre de M8 (jeu figé) est complété par son équivalent sur le terrain.

**Négatives**

- Les alertes CVE n'ont pas de qualification « faux positif » : une alerte acquittée compte
  comme « ignorée », même quand l'acquittement voulait dire « non concerné ». La part de bruit
  des alertes CVE est donc une borne haute.
- Une chasse confirmée suppose que l'analyste associe l'IOC à l'incident ; un incident ouvert à
  la main sans association ne crédite pas la règle.
- Une exclusion expirée continue de compter comme faux positif sur sa fenêtre : c'était bien
  un faux positif au moment où elle a été posée.

## Suivi

- Rejouer la mesure sur le poste de test après un mois d'exploitation réelle et publier les
  premiers chiffres dans `Rapport/`.
- Envisager une qualification « non concerné » pour les alertes CVE si le bruit mesuré le
  justifie.
