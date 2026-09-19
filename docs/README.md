# Documentation SENTRY

| Document | Contenu |
|---|---|
| [`CAHIER_DES_CHARGES.md`](CAHIER_DES_CHARGES.md) | **Spécification opposable.** Exigences fonctionnelles (RF-01 à RF-28), exigences non fonctionnelles, modèle de données, contrats d'API, planning des 44 tâches. La référence en cas de doute. |
| [`PRODUCT_VISION.md`](PRODUCT_VISION.md) | Vision stratégique : marché, concurrence, roadmap long terme, vision 2035. |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Comment le code est organisé et pourquoi. Décisions structurantes, flux de données, sécurité. |
| [`ONBOARDING.md`](ONBOARDING.md) | Guide Day-1 : installation, structure du dépôt, standards, première tâche. |
| [`adr/`](adr/) | Architecture Decision Records — décisions tracées avec leur contexte et leurs conséquences. |
| [`pdf/`](pdf/) | Documents fondateurs d'origine, conservés tels quels. |

## Hiérarchie des sources

En cas de contradiction entre deux documents, l'ordre de préséance est :

1. un **ADR** accepté, qui tranche explicitement le point ;
2. le **Cahier des charges**, seul document approuvé pour développement ;
3. le **Product Vision Document**, document stratégique ;
4. les PDF d'origine, conservés pour archive.

Un écart constaté et non tranché doit faire l'objet d'un ADR, pas d'une décision silencieuse dans le
code.
