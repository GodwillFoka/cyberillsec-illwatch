# ILLWATCH : présentation globale du projet (10/11/2026)

**Date :** 10/11/2026 · **Auteur :** Godwill FOKA (assisté par Claude) · **Méthode :**
[prompt de présentation globale, version 2](../PROMPT_PRESENTATION_GLOBALE.md) · **État de
référence :** `main` au commit `84fda7a` (30/10/2026)

## 1. Le projet en une minute

ILLWATCH est une plateforme open source (licence MIT) de renseignement sur les menaces, portée
par CyberillSec, une initiative CYBERILL. Elle s'adresse aux équipes de sécurité qui n'ont ni le
budget d'une plateforme commerciale ni le temps de trier seules des dizaines de milliers de
failles et d'indicateurs : PME et ETI, SOC, prestataires de sécurité, CERT. Elle collecte neuf
sources publiques ou gratuites, note chaque faille de 0 à 100 selon son exploitation réelle,
compare le tout à l'inventaire de l'organisation, puis outille le triage, les incidents, la
chasse et le partage STIX et TAXII. Elle s'installe sur les serveurs de l'organisation et tient
dans moins de 256 Mo de mémoire. Elle s'appelait SENTRY jusqu'au 08/10/2026.

## 2. Ce qui est fait

« Livré » signifie présent dans `main` et vérifié par l'intégration continue. « Constaté »
signifie que le critère de sortie du jalon a été vérifié sur des données réelles.

| Jalon | Contenu | Livré | Constaté |
|---|---|---|---|
| M1 Fondation | base, migrations, API, CLI, rôles, audit | ✅ | ✅ |
| M2 Flux de menaces | neuf sources, normalisation, provenance | ✅ | ✅ (06/10, encore le 09/11) |
| M3 Moteur CVE | NVD, KEV, EPSS, note composite, alertes | ✅ | ✅ (09/11 : 507 CVE en P0) |
| M4 Incidents | cycle NIST, chronologie immuable | ✅ | ✅ |
| M5 Tableau de bord | synthèse, activité, exports | ✅ | ✅ |
| M6 Chasse | six règles, sessions | ✅ | ✅ |
| M7 Durcissement | lots 1 à 3, préproduction locale vérifiée en CI | ✅ | ⏳ serveur européen non déployé (workflow du 09/11) |
| M8 Corrélation | confiance des IOC, enrichissement, inventaire, corrélation par version | ✅ | ✅ clos le 14/10 |
| M9 Opérations SOC | niveaux L1 à L3, faux positifs, Pilotage | ✅ | 🟡 en CI ; à rejouer sur le poste |
| M10 Contexte | ATT&CK, campagnes, STIX 2.1 et TAXII 2.1 | ✅ | 🟡 en CI ; à rejouer sur le poste |
| M11 Supervision | Prometheus, Grafana, acceptation, restauration | ✅ | ⏳ sept jours de préproduction sur le serveur |

Livré aussi, hors jalons : interface web temps réel (douze écrans, cinq langues), site de
présentation en cinq langues avec demandes de démonstration (ADR-027), inventaire par fichier
Excel ou CSV (ADR-028), qualité des alertes mesurée par règle et par source (ADR-029),
priorisation expliquée (ADR-030), source, fraîcheur et confiance visibles sur chaque donnée
(ADR-031), documentation v2.0 en ligne et en PDF.

## 3. Ce qui est en cours

| Élément | Contenu | État |
|---|---|---|
| Branche `docs/scan-coherence-2026-11` | corrections de ce scan (section 8) et PDF régénérés | demande de fusion ouverte avec ce rapport |
| PR #71 (Dependabot) | image Docker `python:3.12-slim` vers `python:3.15-slim` | à évaluer : changement de version de Python |
| PR #72 (Dependabot) | `actions/download-artifact` 7 vers 8 | à fusionner après CI verte |
| PR #73 (Dependabot) | deux mises à jour de l'interface web | à fusionner après CI verte |
| Pipeline GitLab de `main` | treize jobs en échec sans journal (pipeline #3010260207) | à rétablir : exécution, pas le code |

Aucune fonctionnalité n'a été livrée depuis le 30/10/2026.

## 4. Ce qui va être fait

### Jusqu'à la version 0.2.0, dans l'ordre

| # | Étape | Qui | Après | Effort |
|---|---|---|---|---|
| 1 | Mettre à jour le poste de test (`git pull`, installation, `illwatch db upgrade`, interface, `illwatch attack import`) | porteur | | 30 min |
| 2 | Déclarer l'inventaire réel avec le modèle Excel, puis `illwatch cves refresh-affected` et `illwatch correlate run` | porteur | 1 | 1 à 2 h |
| 3 | Rejouer M9 et M10 sur le poste, puis écrire leurs bilans | porteur, assistant | 1 | 2 h |
| 4 | Suspendre RedEye, régler le fuseau horaire de la machine virtuelle | porteur | | 15 min |
| 5 | Rétablir le pipeline GitLab, traiter les PR Dependabot | porteur | | 30 min |
| 6 | Louer un serveur européen et un domaine, lancer `deploy-vps.sh install`, inscrire le domaine | porteur | | 2 h |
| 7 | Note TLS mesurée par le workflow « Clôture M7 » : **M7 terminé** | intégration continue | 6 | automatique |
| 8 | Sept jours de préproduction et la restauration du mois : **M11 terminé** | serveur | 6 | 7 jours |
| 9 | Étiqueter `v0.2.0`, publier la version et l'image | porteur | 7 et 8 | 1 h |

Le chemin critique passe par l'étape 6 : sans serveur européen, ni M7 ni M11 ne peuvent être
clos, et la version 0.2.0 attend.

### Après la version 0.2.0

Dans l'ordre de la feuille de route : un pilote avec des analystes SOC, l'accessibilité de
l'application (WCAG), plusieurs organisations et la connexion unique (OIDC), l'offre hébergée
Cyberill TI Cloud, puis l'assistant d'analyse, les connecteurs de parc, les règles Sigma et le
type de faille (CWE) dans la note.

## 5. Risques et points ouverts

| Point | Impact | Action prévue |
|---|---|---|
| Serveur européen non loué | M7, M11 et la version 0.2.0 bloqués | étape 6 |
| Pipeline GitLab en échec depuis le 30/10 | plus de constat GitLab (SAST, image, secrets) sur le dépôt de référence | vérifier les minutes de calcul et les exécuteurs, relancer |
| Image en Python 3.15 proposée | changement de version majeure de l'interpréteur | ne fusionner qu'après CI verte ; les tests restent en 3.12 et 3.14 |
| M9 et M10 non rejoués sur données réelles | jalons livrés mais non constatés | étape 3 |
| Sources instables (RedEye sans réponse, DigitalSide hors ligne) | 6 sources saines sur 9 en CI | étape 4, surveiller |
| Qualité des alertes (ADR-029) mesurée seulement après un mois d'exploitation réelle | pas encore de chiffre de terrain | dépend de l'étape 6 |

## 6. Chiffres clés

| Indicateur | Valeur | Date et source |
|---|---|---|
| Tests | 681 réussis, 4 ignorés | 30/10, CI GitHub de `84fda7a` |
| Couverture | 90 % (seuil bloquant 80 %) | 30/10, CI GitHub |
| Scénario SOC | 55 sur 55 | 09/11, validation réelle |
| CVE (base neuve de la validation) | 13 930 ; P0 507 · P1 1 264 · P2 40 · P3 12 119 ; KEV 1 769 | 09/11, validation réelle |
| IOC (poste Kali) | 528 453, dont 334 311 actifs | 08/10, poste de test |
| CVE (poste Kali) | 26 416, dont 6,7 % en P0 à P2 | 07/10, poste de test |
| Export des IOC | 12,0 s pour 528 453 IOC (cible 15 s) | 08/10, poste de test |
| Tableau de bord | 0,63 s (cible 1 s) | 08/10, poste de test |
| Code | 20 migrations, 31 ADR, 61 exigences fonctionnelles | 10/11, dépôt |

## 7. Les trois décisions qui vous attendent

1. **Louez-vous le serveur européen et le nom de domaine cette semaine**, pour lancer la
   clôture de M7 et les sept jours de M11 ? Oui ou non.
2. **Acceptez-vous de reporter l'image Python 3.15 (PR #71)** jusqu'à la version 0.2.0, et de
   ne fusionner d'ici là que les mises à jour mineures (PR #72 et #73) ? Oui ou non.
3. **Fusionnez-vous la demande de fusion de ce scan**, qui corrige la documentation et
   régénère les PDF sans toucher au code ? Oui ou non.

## 8. Incohérences relevées et corrigées

| Document | Écart | Correction |
|---|---|---|
| `README.md`, accueil du site, cahier des charges, feuille de route | « 28 décisions d'architecture » alors que l'ADR-031 est accepté | 31 décisions |
| `README.md` (arborescence) | « 16 ADR », « plus de 510 tests », liste des modules incomplète | 31 ADR, plus de 680 tests, quatorze modules |
| `README.md`, cahier des charges, feuille de route, état d'avancement | couverture « environ 94 % » | 90 %, mesurée par la CI du 30/10 |
| Cahier des charges | aucune exigence pour les ADR-027, 029, 030 et 031, pourtant livrés | exigences RF-58 à RF-61 ajoutées, version 2.1 |
| Vision produit | qualité des alertes, priorisation expliquée, transparence et site de présentation absents du tableau « Ce que fait ILLWATCH aujourd'hui » | lignes « Confiance » et « Présentation » ajoutées, version 2.1 |
| État d'avancement | arrêté au 30/10 à 01 h 30 : PR #63 à #70 absentes, indicateurs du 08/10, tête de migration périmée | mise à jour au 10/11 : position, journal, indicateurs, risques, étapes |
| État d'avancement | plages CIDR « au backlog » alors que le type `NETWORK` est livré le 14/10 ; RedEye confondu avec l'hôte de DigitalSide | lignes de risque corrigées |
| Feuille de route | état « au 30 octobre » ; échec du pipeline GitLab non mentionné | état au 10/11, étape 5 « Rétablir le pipeline GitLab » ajoutée |
| `mkdocs.yml`, ADR-001, ADR-002 | quatre avertissements de construction (entrée de menu, liens vers le code hors du site) | entrée `rapport/index.md`, liens absolus vers le dépôt ; zéro avertissement |
| PDF de `docs/pdf/` | générés le 30/10 à 00 h 48, avant les réécritures du 30/10 et les ADR-029 à 031 | les cinq PDF régénérés (édition du 10/11/2026) ; titre de couverture du cahier des charges rendu lisible |
