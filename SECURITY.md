# Politique de sécurité

## Versions supportées

| Version | Supportée |
|---|---|
| 0.1.x (pré-v1.0) | ✅ branche de développement active |

## Signaler une vulnérabilité

**N'ouvrez pas d'issue publique pour une vulnérabilité de sécurité.**

Écrivez à **security@cyberill.com** en incluant :

- une description de la faille et de son impact ;
- les étapes de reproduction ou un proof-of-concept ;
- la version ou le commit concerné ;
- votre évaluation de sévérité si vous en avez une.

### Engagements

| Étape | Délai |
|---|---|
| Accusé de réception | 48 heures |
| Évaluation initiale et qualification | 7 jours |
| Correctif ou plan de remédiation | 30 jours (sévérité critique : 7 jours) |

Nous pratiquons la divulgation coordonnée. Votre contribution sera créditée dans le CHANGELOG et
les notes de version, sauf si vous préférez rester anonyme.

## Périmètre

Dans le périmètre : le code de ce dépôt, ses dépendances directes, la configuration Docker fournie,
et toute fuite de secret dans l'historique git.

Hors périmètre : les services tiers interrogés par les collecteurs (NVD, CISA, FIRST, OTX), et les
déploiements opérés par des tiers.
