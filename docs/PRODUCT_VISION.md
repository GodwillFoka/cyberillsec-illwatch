# ILLWATCH : Vision produit

<div class="iw-pdf" markdown>[:octicons-download-16: Télécharger le PDF v2.0](pdf/ILLWATCH_Vision_produit_v2.pdf){ .md-button } [:material-home: Toute la documentation](README.md){ .md-button }</div>

| | |
|---|---|
| **Version** | v2.0 du 30 octobre 2026. Elle remplace la v1.0 de juillet 2026, conservée en PDF. |
| **Auteur** | Godwill FOKA, ingénieur en cybersécurité, à l'origine de CYBERILL, Berlin |
| **Ce que couvre ce document** | la vision et la stratégie. Les exigences précises, celles qui font foi, sont dans le [cahier des charges](CAHIER_DES_CHARGES.md). |

!!! note "D'où viennent les chiffres"
    Les chiffres sur le marché sont des **estimations**, reprises de la première version de ce
    document. Elles nous aident à orienter la stratégie, mais ce n'est pas une étude de marché
    vérifiée. Les chiffres qui concernent ILLWATCH lui-même sont en revanche **mesurés**, sur des
    données réelles, et toujours datés.

## Sommaire

1. [En une phrase](#1-en-une-phrase)
2. [Le problème](#2-le-probleme)
3. [Pour qui](#3-pour-qui)
4. [La proposition de valeur](#4-la-proposition-de-valeur)
5. [Ce que fait ILLWATCH aujourd'hui](#5-ce-que-fait-illwatch-aujourdhui)
6. [Le marché et la concurrence](#6-le-marche-et-la-concurrence)
7. [Le modèle](#7-le-modele)
8. [La trajectoire](#8-la-trajectoire)
9. [Vision 2035](#9-vision-2035)
10. [Ce qui a changé depuis la v1.0](#10-ce-qui-a-change-depuis-la-v10)

---

## 1. En une phrase

**ILLWATCH donne à une petite équipe de sécurité, d'une à dix personnes, ce dont elle a besoin
le lundi matin : savoir quoi corriger d'abord, quoi bloquer, ce qui a changé depuis vendredi, et
pouvoir prouver ce qui a été fait.**

*« Voir la menace avant qu'elle ne vous voie. »*

ILLWATCH est le cœur de CyberillSec, la branche de CYBERILL consacrée au renseignement sur les
menaces. CYBERILL réunit aussi Cyberill Labs pour la recherche, Cyberill Academy pour la
formation, Cyberill Consulting pour le conseil, Cyberill CERT pour la réponse aux incidents et
Cyberill Cloud pour les plateformes hébergées. Six valeurs guident l'ensemble : innovation,
excellence, transparence, souveraineté, collaboration et éthique.

---

## 2. Le problème

Imaginez le responsable sécurité d'une entreprise de 300 personnes. Il est souvent seul, ou
presque. Chaque semaine, des centaines de nouvelles failles sont publiées et des listes de
milliers d'adresses malveillantes circulent. Il ne peut pas tout lire, alors il trie à
l'instinct, et finit par corriger ce qui *paraît* grave plutôt que ce qui est *urgent*.

Ce problème a plusieurs visages :

| Ce qui se passe | Ce que cela coûte |
|---|---|
| **Trop d'informations** : des dizaines de milliers de failles par an et des centaines de milliers d'indicateurs de menace | on traite le « grave » au lieu de l'« urgent » |
| **Des outils éparpillés** : failles, indicateurs, incidents et recherches de traces dans des logiciels séparés | un analyste passe 60 à 70 % de son temps à recopier et à trier |
| **Des prix hors de portée** : de 40 000 à 150 000 € par an pour une plateforme commerciale | les PME, les ETI et les collectivités restent sans outil |
| **Des outils libres trop lourds** : 16 Go de mémoire et plusieurs serveurs pour les plateformes open source complètes | impossibles à installer dans un petit environnement |
| **Des attaques plus rapides** : une faille est souvent exploitée moins de 48 heures après sa publication | corriger une fois par mois ne suffit plus |
| **De nouvelles obligations** : NIS 2 et DORA demandent une veille active et des déclarations d'incident sous 24 à 72 heures | il faut pouvoir prouver ce qui a été fait, et quand |
| **Une question de souveraineté** : beaucoup de services de renseignement sont hébergés hors de l'Union européenne | dépendance et risque juridique |

---

## 3. Pour qui

ILLWATCH s'adresse d'abord à celles et ceux qui n'ont ni le budget ni l'équipe d'un grand
groupe, mais qui portent les mêmes responsabilités.

| Qui | Ce qu'ils cherchent | Ce qu'ILLWATCH leur apporte |
|---|---|---|
| **PME et ETI européennes** | une veille sérieuse sans budget de grand compte | gratuit, léger, installé en une heure |
| **Équipes SOC** (niveaux 1 à 3) | une liste de priorités claire et des incidents bien suivis | tri des alertes, corrélation, incidents selon le NIST, indicateurs de pilotage |
| **Responsables sécurité et directions** | des priorités qu'ils peuvent défendre, et des chiffres | une note expliquée, des délais mesurés, des objectifs de traitement |
| **CERT nationaux ou sectoriels** | partager un renseignement structuré | formats STIX 2.1 et TAXII 2.1, campagnes, contexte MITRE ATT&CK |
| **Prestataires de sécurité et intégrateurs** | une brique de renseignement à opérer pour plusieurs clients | API et ligne de commande complètes ; gestion de plusieurs organisations prévue |
| **Auditeurs** | la preuve des actions menées | des historiques d'incident et un journal d'audit impossibles à modifier |

---

## 4. La proposition de valeur

![De la source à la décision](assets/schemas/pipeline.svg)

Concrètement, ILLWATCH répond à cinq questions que toute équipe de sécurité se pose.

**1. Que dois-je corriger d'abord ?**
Chaque faille reçoit une note de 0 à 100 et une priorité de P0 à P3. La note est calculée de la
même façon pour tout le monde et peut être expliquée ligne par ligne. Surtout, elle repose sur
ce qui se passe réellement : 30 points au plus pour la gravité technique, 70 pour l'exploitation
prévue ou constatée. Résultat, sur les 26 416 failles que nous suivons, seules 6,7 % demandent
une action, et les 1 734 failles dont on sait qu'elles sont déjà exploitées sont toutes classées
P0 ou P1.

**2. Suis-je concerné ?**
Vous décrivez votre parc en quelques minutes dans un fichier Excel. ILLWATCH le compare en
permanence aux failles et aux indicateurs, en tenant compte des versions installées.

**3. Suis-je déjà touché ?**
Vous lui confiez un export de vos journaux, et il le compare à plus de 300 000 indicateurs
actifs et à six règles de détection.

**4. Comment réagir, et comment le prouver ?**
Les incidents suivent la méthode du NIST, sont répartis entre trois niveaux d'analystes, avec
des délais cibles. Leur historique est protégé : même la base de données refuse de le modifier.

**5. Est-ce que je garde la maîtrise ?**
Oui. Le code est ouvert sous licence MIT, l'édition communautaire est gratuite, ILLWATCH
s'installe sur vos propres serveurs, tient dans moins de 256 Mo de mémoire et parle cinq
langues.

![Répartition des CVE par priorité](assets/schemas/chiffres-cve.svg)

---

## 5. Ce que fait ILLWATCH aujourd'hui

Tout ce qui suit fonctionne déjà, dans le code publié :

| Domaine | Ce qui existe |
|---|---|
| Renseignement | neuf sources de référence, cinq formats lus (CSV, JSON, STIX 2.1, TAXII 2.1, OTX), données nettoyées et dédoublonnées, origine et niveau de confiance de chaque indicateur, localisation des adresses IP sans appel extérieur |
| Failles | base du NIST, catalogue des failles exploitées de la CISA, probabilités EPSS, note composite, plancher pour les failles exploitées, alertes et notifications |
| Détection | inventaire importé depuis Excel, corrélation par version, recherche de traces avec six règles, contexte MITRE ATT&CK, campagnes d'attaquants |
| Réponse | incidents selon le NIST, trois niveaux d'analystes, recommandations, gestion des faux positifs, écran de pilotage |
| Partage | exports CSV, JSON et STIX 2.1, serveur TAXII 2.1 |
| Exploitation | interface web en temps réel, ligne de commande, API, sauvegardes, Prometheus et Grafana, HTTPS |

Chaque fonctionnalité est expliquée en détail dans le [manuel fonctionnel](MANUEL_FONCTIONNEL.md).

---

## 6. Le marché et la concurrence

Le renseignement sur les menaces est un marché en forte croissance. Voici les ordres de grandeur
que nous retenons, avec la prudence rappelée plus haut :

| Indicateur (estimation) | Valeur |
|---|---|
| Marché mondial en 2026 | 18,5 milliards de dollars |
| Croissance annuelle | 16,2 % |
| Marché européen | 4,2 milliards de dollars |
| Marché africain | 280 millions de dollars |
| Solutions existantes | plus de 200 |

Face à cette offre, ILLWATCH occupe une place précise : la puissance d'un outil complet, sans son
prix ni sa lourdeur.

| Critère | Plateformes commerciales (CrowdStrike, Recorded Future) | Plateformes libres complètes (MISP, OpenCTI) | **ILLWATCH** |
|---|---|---|---|
| Licence | propriétaire | AGPL, Apache | **MIT** |
| Coût annuel | de 30 000 à 200 000 $ | 0 $, mais il faut l'infrastructure | **0 € en édition communautaire** |
| Infrastructure | service souvent hébergé hors de l'UE | 16 Go et plus, quatre à cinq services | **moins de 256 Mo, PostgreSQL et Redis** |
| Tri des failles selon l'exploitation réelle | oui | par connecteurs à ajouter | **intégré : KEV, EPSS, exploit, rançongiciel** |
| Comparaison avec votre parc | oui | partielle | **intégrée, par version** |
| Suivi des incidents et pilotage SOC | partiel | non | **intégré (NIST, trois niveaux, délais)** |
| Où sont vos données | rarement en Europe | chez vous | **chez vous** |

ILLWATCH ne cherche pas à remplacer une grande base de connaissances comme OpenCTI. Il la
**complète**, en lui transmettant ses indicateurs par TAXII, et il sert les équipes qui n'ont ni
le temps ni l'infrastructure pour en faire tourner une.

---

## 7. Le modèle

Le logiciel est et restera gratuit. Nous vivons des services qui aident à l'installer et à s'en
servir.

| Offre | Ce qu'elle comprend | Prix |
|---|---|---|
| **Édition communautaire** | toute la plateforme, sous licence MIT, installée chez vous | 0 € |
| **Pilote** | installation, déclaration de l'inventaire, formation de l'équipe | à partir de 1 490 € (indicatif) |
| **Accompagnement** | suivi, mises à jour, revue mensuelle des priorités | à partir de 290 € par mois (indicatif) |
| **Cyberill TI Cloud** (prévu) | ILLWATCH hébergé dans l'Union européenne, pour plusieurs organisations | à définir |

Ces prix de lancement ont été fixés le 23 octobre 2026. Ils sont indiqués comme tels sur le site
de présentation, disponible en cinq langues, qui recueille aussi les demandes de démonstration.

---

## 8. La trajectoire

![Jalons M1 à M11](assets/schemas/jalons.svg)

| Étape | Objectif | Où nous en sommes au 30/10/2026 |
|---|---|---|
| M1 à M6 | socle, flux de menaces, failles, incidents, tableau de bord, chasse | vérifiés sur données réelles ; version `v0.1.1` publiée |
| M7 | durcissement pour la production, interface web | livré ; il manque le serveur européen |
| M8 | détection et corrélation | vérifié, terminé le 14 octobre |
| M9 | opérations SOC | livré, à vérifier sur le poste de test |
| M10 | contexte des attaquants (ATT&CK, campagnes, STIX, TAXII) | livré, à vérifier sur le poste de test |
| M11 | supervision et environnements | livré ; il manque sept jours de préproduction |
| **v0.2.0** | première version candidate à la production | dès que M7 et M11 seront terminés |
| Ensuite | assistant d'analyse, plusieurs organisations, connexion unique (SSO), Cyberill TI Cloud | prévu |

Les critères précis de chaque étape sont dans la [feuille de route](ROADMAP.md).

---

## 9. Vision 2035

> En 2035, CyberillSec est la plateforme européenne de référence en renseignement sur les
> menaces.

C'est une ambition, pas une prévision. Voici ce qu'elle voudrait dire concrètement :

| Domaine | Ambition pour 2035 |
|---|---|
| Produit | Cyberill TI Cloud, hébergé dans l'UE, à côté de l'édition communautaire |
| Communauté | plus de 100 000 utilisateurs et plus de 5 000 contributeurs |
| Couverture | l'Europe et l'Afrique |
| Équipe | plus de 100 personnes |
| Revenus | plus de 20 millions d'euros par an |
| Reconnaissance | partenaire de l'ENISA, de FIRST et du CERT-EU |

Plusieurs avenirs sont possibles, et nous les regardons en face :

| Scénario | Probabilité estimée | Ce que cela signifie |
|---|---|---|
| Champion européen | 60 % | ILLWATCH devient la référence européenne du renseignement sur les menaces |
| Pont entre l'Europe et l'Afrique | 25 % | une plateforme de partage entre les deux continents |
| Famille de produits | 10 % | plusieurs produits construits autour du même cœur |
| Niche | 5 % | un projet libre bien entretenu, porté par une communauté restreinte |

---

## 10. Ce qui a changé depuis la v1.0

| Sujet | v1.0 (juillet 2026) | v2.0 (octobre 2026) |
|---|---|---|
| Nom | SENTRY | **ILLWATCH**, depuis le 8 octobre (le nom SENTRY était déjà pris) |
| Identité visuelle | bouclier « S », indigo et orange | écu-radar, couleurs Nuit et Signal, polices Inter et JetBrains Mono (ADR-018) |
| Calcul de la note | CVSS 30 %, EPSS 25 %, KEV 25 %, exploit 10 %, rançongiciel 5 %, CWE 5 % ; seuils 70, 40, 20 | **la formule du cahier des charges** : rançongiciel 10 points, sans CWE ; seuils 80, 60, 40 ; plancher pour les failles exploitées (ADR-001, ADR-014) |
| Interface | API et ligne de commande d'abord | **interface web en temps réel, douze écrans, cinq langues** |
| Inventaire | absent | **import Excel ou CSV**, comparé version par version |
| Hébergement du code | GitHub | GitLab comme référence, GitHub comme miroir (ADR-002, ADR-015) |
| Écriture | | français soigné, sans tiret long |

**Construisons ensemble l'alternative européenne en renseignement sur les menaces.**
