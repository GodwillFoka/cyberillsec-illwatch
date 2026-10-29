# Documentation ILLWATCH

![ILLWATCH](assets/illwatch-logo-light.svg#only-light){ width="360" }
![ILLWATCH](assets/illwatch-logo-dark.svg#only-dark){ width="360" }

**ILLWATCH** est la plateforme open source de Cyber Threat Intelligence de CyberillSec : collecte
et déduplication des IOC (STIX/TAXII 2.1, OTX, flux publics), priorisation des CVE (CVSS + EPSS +
KEV), gestion d'incidents NIST SP 800-61, chasse aux menaces et pilotage SOC.

Code : [GitLab (référence)](https://gitlab.com/GodwillFoka/cyberillsec-illwatch) ·
[GitHub (miroir)](https://github.com/GodwillFoka/cyberillsec-illwatch) · Image :
`ghcr.io/godwillfoka/cyberillsec-illwatch`


## Par où commencer

| Vous voulez… | Lisez |
|---|---|
| installer ILLWATCH et l'exploiter au quotidien | [Guide d'installation et d'exploitation](GUIDE_INSTALLATION.md) |
| comprendre chaque fonctionnalité, les acteurs et leurs droits | [Manuel fonctionnel](MANUEL_FONCTIONNEL.md) |
| connaître les exigences et leur statut | [Cahier des charges v2.0](CAHIER_DES_CHARGES.md) |
| comprendre la stratégie | [Vision produit v2.0](PRODUCT_VISION.md) |
| savoir ce qui reste à faire | [Feuille de route v2.0](ROADMAP.md) |

Chaque document existe aussi en PDF mis en page, dans le dossier `pdf/` :
[guide](pdf/ILLWATCH_Guide_installation_exploitation_v2.pdf),
[manuel](pdf/ILLWATCH_Manuel_fonctionnel_v2.pdf),
[cahier des charges](pdf/ILLWATCH_Cahier_des_charges_v2.pdf),
[vision](pdf/ILLWATCH_Vision_produit_v2.pdf),
[feuille de route](pdf/ILLWATCH_Feuille_de_route_v2.pdf).

## Tous les documents

| Document | Contenu |
|---|---|
| [Guide d'installation et d'exploitation](GUIDE_INSTALLATION.md) | Installation de A à Z, inventaire par Excel, travail quotidien en double méthode (application, ligne de commande), administration, sauvegardes, serveur, dépannage. |
| [Manuel fonctionnel](MANUEL_FONCTIONNEL.md) | Acteurs, matrice des droits, chaque fonctionnalité expliquée (score, confiance, corrélation, incidents, chasse, ATT&CK, partage), parcours types, glossaire. |
| [Cahier des charges](CAHIER_DES_CHARGES.md) | **Spécification opposable** v2.0 : exigences RF-01 à RF-57 avec leur statut, exigences non fonctionnelles mesurées, modèle de données, interfaces, critères d'acceptation. |
| [Vision produit](PRODUCT_VISION.md) | Problème, cibles, valeur, concurrence, modèle, trajectoire, vision 2035. |
| [Feuille de route](ROADMAP.md) | Jalons M1 à M11, critères de sortie, tâches restantes dans l'ordre, calendrier. |
| [Architecture](ARCHITECTURE.md) | Organisation du code, décisions structurantes, flux de données, sécurité. |
| [Prise en main](ONBOARDING.md) | Guide du premier jour pour un contributeur : standards, première tâche. |
| [Exploitation](OPERATIONS.md) | Référence de l'opérateur : sondes, journaux, audit, sauvegarde, TLS, mise à jour. |
| [Environnements](ENVIRONNEMENTS.md) | Développement, préproduction, production. |
| [`rapport/`](rapport/index.md) | Rapports d'avancement, bilans d'étape et audits. |
| [`adr/`](adr/README.md) | Décisions d'architecture tracées avec leur contexte et leurs conséquences. |
| `pdf/` | Versions PDF de la documentation v2.0 ; documents fondateurs d'origine (2026, nom SENTRY) conservés pour archive. |

## Hiérarchie des sources

En cas de contradiction entre deux documents, l'ordre de préséance est :

1. un **ADR** accepté, qui tranche explicitement le point ;
2. le **Cahier des charges**, seul document approuvé pour développement ;
3. la **Vision produit**, document stratégique ;
4. les PDF d'origine, conservés pour archive.

Un écart constaté et non tranché doit faire l'objet d'un ADR, pas d'une décision silencieuse dans le
code.
