# Documentation ILLWATCH

![ILLWATCH](assets/illwatch-logo-light.svg#only-light){ width="360" }
![ILLWATCH](assets/illwatch-logo-dark.svg#only-dark){ width="360" }

**ILLWATCH** est la plateforme open source de Cyber Threat Intelligence de CyberillSec : collecte
et déduplication des IOC (STIX/TAXII 2.1, OTX, flux publics), priorisation des CVE (CVSS + EPSS +
KEV), gestion d'incidents NIST SP 800-61, chasse aux menaces et pilotage SOC.

Code : [GitLab (référence)](https://gitlab.com/GodwillFoka/cyberillsec-illwatch) ·
[GitHub (miroir)](https://github.com/GodwillFoka/cyberillsec-illwatch) · Image :
`ghcr.io/godwillfoka/cyberillsec-illwatch`


| Document | Contenu |
|---|---|
| [`CAHIER_DES_CHARGES.md`](CAHIER_DES_CHARGES.md) | **Spécification opposable.** Exigences fonctionnelles (RF-01 à RF-28), exigences non fonctionnelles, modèle de données, contrats d'API, planning des 44 tâches. La référence en cas de doute. |
| [`PRODUCT_VISION.md`](PRODUCT_VISION.md) | Vision stratégique : marché, concurrence, roadmap long terme, vision 2035. |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Comment le code est organisé et pourquoi. Décisions structurantes, flux de données, sécurité. |
| [`ONBOARDING.md`](ONBOARDING.md) | Guide Day-1 : installation, structure du dépôt, standards, première tâche. |
| [`OPERATIONS.md`](OPERATIONS.md) | Exploitation : sondes, journaux, audit, sauvegarde/restauration, reverse proxy, mise à jour, Kali. |
| [`ROADMAP.md`](ROADMAP.md) | Trajectoire M7 → M11 vers la v0.2.0 « Production Candidate », critères de sortie. |
| [`rapport/`](rapport/index.md) | Rapports d'avancement, bilans d'étape et audits (site de documentation). |
| [`adr/`](adr/README.md) | Architecture Decision Records — décisions tracées avec leur contexte et leurs conséquences. |
| `pdf/` | Documents fondateurs d'origine, conservés tels quels : [Cahier des charges](pdf/SENTRY_Cahier_des_Charges.pdf), [Product Vision](pdf/CYBERILL-SENTRY-PRODUCT-VISION_3.pdf). |

## Hiérarchie des sources

En cas de contradiction entre deux documents, l'ordre de préséance est :

1. un **ADR** accepté, qui tranche explicitement le point ;
2. le **Cahier des charges**, seul document approuvé pour développement ;
3. le **Product Vision Document**, document stratégique ;
4. les PDF d'origine, conservés pour archive.

Un écart constaté et non tranché doit faire l'objet d'un ADR, pas d'une décision silencieuse dans le
code.
