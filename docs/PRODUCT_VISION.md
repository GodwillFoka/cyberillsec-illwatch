# ILLWATCH : Vision produit

<div class="iw-pdf" markdown>[:octicons-download-16: Télécharger le PDF v2.0](pdf/ILLWATCH_Vision_produit_v2.pdf){ .md-button } [:material-home: Toute la documentation](README.md){ .md-button }</div>

| | |
|---|---|
| **Version** | **v2.0 du 30/10/2026** (remplace la v1.0 de juillet 2026, conservée en PDF dans `docs/pdf/`) |
| **Auteur** | Godwill FOKA, Cybersecurity Engineer, initiateur de CYBERILL, Berlin |
| **Portée** | vision et stratégie ; les exigences opposables sont dans le [Cahier des charges](CAHIER_DES_CHARGES.md) |

> Les chiffres de marché de ce document sont des **estimations** reprises de la v1.0 ; ils
> orientent la stratégie et ne constituent pas une étude de marché vérifiée. Les chiffres
> d'ILLWATCH, eux, sont **mesurés** sur données réelles et datés.

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

**ILLWATCH donne à une équipe de sécurité de 1 à 10 personnes ce dont elle a besoin le lundi
matin : quoi corriger d'abord, quoi bloquer, ce qui a changé, et la preuve de ce qui a été fait.**

*« Voir la menace avant qu'elle ne vous voie. »*

ILLWATCH est le moteur de CyberillSec, la branche renseignement de CYBERILL, aux côtés de
Cyberill Labs (recherche), Cyberill Academy (formation), Cyberill Consulting (conseil), Cyberill
CERT (réponse à incident) et Cyberill Cloud (plateformes hébergées). Six valeurs : innovation,
excellence, transparence, souveraineté, collaboration, éthique.

---

## 2. Le problème

| Problème | Ce qu'il coûte |
|---|---|
| **Surcharge** : des dizaines de milliers de CVE par an, des centaines de milliers d'indicateurs | on corrige le « grave » au lieu de l'« urgent » |
| **Fragmentation** : vulnérabilités, indicateurs, incidents et chasse dans des outils séparés | 60 à 70 % du temps d'un analyste passe à recopier et trier |
| **Coût** : 40 000 à 150 000 € par an pour une plateforme commerciale | les PME, ETI et collectivités en sont exclues |
| **Lourdeur** : 16 Go de mémoire et un cluster pour les plateformes open source complètes | inutilisables en environnement contraint |
| **Vitesse** : exploitation en moins de 48 heures après publication | la correction mensuelle ne suffit plus |
| **Obligations** : NIS 2, DORA, veille active et notification sous 24 à 72 heures | il faut prouver ce qui a été fait, et quand |
| **Souveraineté** : renseignement hébergé hors de l'Union européenne | dépendance et exposition juridique |

---

## 3. Pour qui

| Cible | Ce qu'elle cherche | Ce qu'ILLWATCH lui apporte |
|---|---|---|
| **PME et ETI européennes** | une veille sérieuse sans budget de grand compte | gratuit, léger, installé en une heure |
| **Équipes SOC** (L1 à L3) | une file de priorités claire et un cycle d'incident tracé | triage, corrélation, incidents NIST, pilotage |
| **RSSI et direction** | des priorités défendables et des indicateurs | score expliqué, MTTA, MTTR, délais cibles |
| **CERT nationaux ou sectoriels** | partager du renseignement structuré | STIX 2.1, TAXII 2.1, campagnes, ATT&CK |
| **MSSP et intégrateurs** | une brique CTI à opérer pour plusieurs clients | API et CLI complètes ; multi-organisation prévu |
| **Auditeurs** | la preuve des actions | chronologies et journal d'audit immuables |

---

## 4. La proposition de valeur

![De la source à la décision](assets/schemas/pipeline.svg)

1. **Savoir quoi corriger d'abord.** Chaque CVE reçoit un score déterministe de 0 à 100 et une
   priorité P0 à P3 fondée sur l'**exploitation réelle** (30 points pour la gravité, 70 pour
   l'exploitation prévue ou constatée). Sur 26 416 CVE suivies, **6,7 %** demandent une action ;
   les 1 734 failles exploitées connues sont toutes en P0 ou P1.
2. **Savoir si l'on est concerné.** L'inventaire, déclaré en quelques minutes depuis Excel, est
   confronté en continu aux CVE et aux indicateurs, versions comprises.
3. **Savoir si l'on est touché.** La chasse confronte un export de journaux à plus de 300 000
   indicateurs actifs et à six règles de détection.
4. **Répondre et le prouver.** Incidents au cycle NIST, niveaux L1 à L3, délais cibles,
   chronologies que même la base refuse de modifier.
5. **Garder la maîtrise.** Licence MIT, 0 € en édition communautaire, hébergement européen,
   moins de 256 Mo de mémoire, cinq langues.

![Répartition des CVE par priorité](assets/schemas/chiffres-cve.svg)

---

## 5. Ce que fait ILLWATCH aujourd'hui

| Domaine | Fonctionnalités |
|---|---|
| Renseignement | 9 sources de référence, 5 formats (CSV, JSON, STIX 2.1, TAXII 2.1, OTX), normalisation, dédoublonnage, provenance, confiance, géolocalisation hors ligne |
| Vulnérabilités | NVD, CISA KEV, FIRST EPSS, score composite, plancher KEV, alertes et webhook |
| Détection | inventaire (import Excel), corrélation CORR-01 à 03 par version, chasse (6 règles), ATT&CK, campagnes |
| Réponse | incidents NIST, niveaux L1 à L3, recommandations, faux positifs, pilotage |
| Partage | exports CSV, JSON, STIX 2.1 ; serveur TAXII 2.1 |
| Exploitation | interface web temps réel, CLI, API, sauvegardes, Prometheus, Grafana, HTTPS |

Le détail est dans le [Manuel fonctionnel](MANUEL_FONCTIONNEL.md).

---

## 6. Le marché et la concurrence

| Indicateur (estimation v1.0) | Valeur |
|---|---|
| Marché mondial de la CTI en 2026 | 18,5 milliards de dollars |
| Croissance annuelle | 16,2 % |
| Marché européen | 4,2 milliards de dollars |
| Marché africain | 280 millions de dollars |
| Solutions recensées | plus de 200 |

| Critère | Plateformes commerciales (CrowdStrike, Recorded Future) | Plateformes open source complètes (MISP, OpenCTI) | **ILLWATCH** |
|---|---|---|---|
| Licence | propriétaire | AGPL, Apache | **MIT** |
| Coût annuel | 30 000 à 200 000 $ | 0 $, plus l'infrastructure | **0 € (édition communautaire)** |
| Infrastructure | service hors UE le plus souvent | 16 Go et plus, 4 à 5 services | **moins de 256 Mo, PostgreSQL et Redis** |
| Priorisation des CVE par l'exploitation | oui | par connecteurs | **native : KEV, EPSS, exploit, rançongiciel** |
| Corrélation avec l'inventaire | oui | partielle | **native, par version** |
| Cycle d'incident et pilotage SOC | partiel | non | **natif (NIST, L1 à L3, MTTA, MTTR)** |
| Hébergement européen | rarement | auto-hébergé | **auto-hébergé, UE** |

ILLWATCH ne cherche pas à remplacer un graphe de connaissances complet comme OpenCTI : il le
**complète** (partage TAXII) et sert les équipes qui n'ont ni le temps ni l'infrastructure pour
l'exploiter.

---

## 7. Le modèle

| Offre | Contenu | Prix |
|---|---|---|
| **Édition communautaire** | la plateforme complète, licence MIT, auto-hébergée | 0 € |
| **Pilote** | installation, déclaration de l'inventaire, formation de l'équipe | dès 1 490 € (indicatif) |
| **Accompagnement** | suivi, mises à jour, revue mensuelle des priorités | dès 290 € par mois (indicatif) |
| **Cyberill TI Cloud** (prévu) | ILLWATCH hébergé dans l'UE, multi-organisation | à définir |

Les prix du pilote et de l'accompagnement sont des **prix de lancement indicatifs** (décision du
23/10/2026), affichés comme tels sur le site de présentation. Le site
(`Website/`, cinq langues) présente l'offre et recueille les demandes de démonstration.

---

## 8. La trajectoire

![Jalons M1 à M11](assets/schemas/jalons.svg)

| Étape | Objectif | État au 30/10/2026 |
|---|---|---|
| M1 à M6 | fondation, flux, CVE, incidents, tableau de bord, chasse | constatés sur données réelles ; release `v0.1.1` |
| M7 | durcissement de production, interface web | livré ; manque le serveur européen |
| M8 | détection et corrélation | constaté (clos le 14/10) |
| M9 | opérations SOC | livré, à constater sur le poste |
| M10 | contexte adverse (ATT&CK, campagnes, STIX, TAXII) | livré, à constater sur le poste |
| M11 | observabilité et environnements | livré ; manquent 7 jours de préproduction |
| **v0.2.0** | « Production Candidate » | après M7 et M11 |
| Après | assistant d'analyse, multi-organisation et SSO, Cyberill TI Cloud | prévu |

Le détail, avec les critères de sortie, est dans la [Feuille de route](ROADMAP.md).

---

## 9. Vision 2035

> En 2035, CyberillSec est la plateforme européenne de référence en renseignement sur les
> menaces.

| Domaine | Ambition 2035 |
|---|---|
| Produit | Cyberill TI Cloud, hébergé dans l'UE, à côté de l'édition communautaire |
| Communauté | plus de 100 000 utilisateurs, plus de 5 000 contributeurs |
| Couverture | Europe et Afrique |
| Équipe | plus de 100 personnes |
| Revenus | plus de 20 millions d'euros par an |
| Reconnaissance | partenaire de l'ENISA, de FIRST et du CERT-EU |

| Scénario | Probabilité estimée | Description |
|---|---|---|
| Champion européen | 60 % | référence CTI en Europe |
| Pont Europe-Afrique | 25 % | plateforme de partage entre les deux continents |
| Plateforme | 10 % | famille de produits autour du cœur CTI |
| Niche | 5 % | projet open source maintenu, communauté restreinte |

---

## 10. Ce qui a changé depuis la v1.0

| Sujet | v1.0 (juillet 2026) | v2.0 (octobre 2026) |
|---|---|---|
| Nom | SENTRY | **ILLWATCH** (nom affiché « ILL Watch »), renommé le 08/10 |
| Identité | bouclier « S », indigo et orange | écu-radar, palette Nuit et Signal, Inter et JetBrains Mono (ADR-018) |
| Score | CVSS 30 %, EPSS 25 %, KEV 25 %, exploit 10 %, rançongiciel 5 %, CWE 5 % ; seuils 70, 40, 20 | **formule du cahier des charges** : rançongiciel 10, sans CWE ; seuils 80, 60, 40 ; plancher KEV (ADR-001, ADR-014) |
| Interface | API et CLI d'abord | **interface web temps réel, 12 écrans, 5 langues** |
| Inventaire | non prévu en v1.0 | déclaré par **import Excel ou CSV**, corrélé par version |
| Hébergement du code | GitHub | GitLab (référence), GitHub (miroir) (ADR-002, ADR-015) |
| Rédaction | | ni tiret long ni tiret moyen, typographie française |

**Construisons ensemble l'alternative européenne en renseignement sur les menaces.**
