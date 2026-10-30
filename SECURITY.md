# Politique de sécurité

Un outil de cybersécurité doit être irréprochable sur sa propre sécurité. Si vous avez trouvé une
faille dans ILLWATCH, merci : vous nous aidez à protéger tous ceux qui l'utilisent. Voici comment
nous la signaler, et ce que nous nous engageons à faire ensuite.

## Versions supportées

| Version | Supportée |
|---|---|
| 0.1.x (pré-v1.0) | ✅ branche de développement active |

## Signaler une vulnérabilité

**N'ouvrez pas d'issue publique pour une vulnérabilité de sécurité.** Une faille exposée avant
d'être corrigée met en danger toutes les instances en service.

Écrivez plutôt à **security@cyberill.com**, en joignant si possible :

- une description de la faille et de son impact ;
- les étapes pour la reproduire, ou une preuve de concept ;
- la version ou le commit concerné ;
- votre estimation de la sévérité, si vous en avez une.

### Nos engagements

| Étape | Délai |
|---|---|
| Accusé de réception | 48 heures |
| Évaluation initiale et qualification | 7 jours |
| Correctif ou plan de remédiation | 30 jours (sévérité critique : 7 jours) |

Nous pratiquons la divulgation coordonnée : nous convenons avec vous du moment où la faille sera
rendue publique. Votre contribution sera créditée dans le CHANGELOG et les notes de version, sauf
si vous préférez rester anonyme.

## Périmètre

**Dans le périmètre** : le code de ce dépôt, ses dépendances directes, la configuration Docker
fournie, et toute fuite de secret dans l'historique git.

**Hors périmètre** : les services tiers interrogés par les collecteurs (NVD, CISA, FIRST, OTX), et
les déploiements opérés par des tiers. Pour ces derniers, adressez-vous directement à leur
exploitant.
