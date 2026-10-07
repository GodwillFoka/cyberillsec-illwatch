# ADR-003 — Authentification JWT livrée dès la phase 1

- **Statut :** accepté
- **Date :** 2026-09-23
- **Décideurs :** équipe ILLWATCH
- **Concerne :** MOD-01, `illwatch/app/security.py`, `illwatch/app/api/deps.py`, `/api/v1/auth/*`

## Contexte

Le périmètre de MOD-01 (§3.1 du Cahier des charges) inclut l'authentification, mais aucune tâche
T1.x ne la planifie et la phase 1 s'est d'abord close avec le seul modèle `User`, sans hachage ni
jeton. Toutes les routes métier des phases 2 à 6 (`/feeds`, `/cves`, `/incidents`…) exposent des
données sensibles : IOC internes, vulnérabilités non corrigées, incidents en cours. Chaque route
écrite sans protection devrait être reprise plus tard.

## Décision

L'authentification est livrée dans la phase 1 : hachage Argon2id, jeton d'accès JWT HS256,
dépendances `get_current_user` et `require_roles`, routes `/api/v1/auth/token` et `/api/v1/users/me`,
commande `illwatch users create`.

## Justification

- **Argon2id (`pwdlib`)** : recommandé par l'OWASP, résistant aux attaques GPU. `passlib`,
  longtemps standard, n'est plus maintenu.
- **JWT HS256 signé par `SECRET_KEY`** : aucun service externe, une seule clé à gérer, adapté à une
  instance unique. L'algorithme est figé au décodage (`alg: none` et confusion d'algorithmes
  refusés) ; le rôle est relu en base à chaque requête, un jeton ne suffit pas à garder un droit
  retiré.
- **Flux OAuth2 *password*** : bouton *Authorize* de Swagger utilisable tel quel.
- *Écarté* — OIDC / SSO (Keycloak) : prévu au-delà de la v1.0 avec le multi-tenant ; trop lourd
  pour la cible < 256 Mo.

## Conséquences

- Positives : les routes des phases suivantes naissent protégées (`Depends(get_current_user)`).
- Négatives : pas de jeton de rafraîchissement ni de révocation avant expiration (60 min par
  défaut) ; un compte désactivé est néanmoins refusé immédiatement. Pas encore de limitation du
  nombre de tentatives de connexion.
- Dépendances ajoutées : `pyjwt`, `pwdlib[argon2]`, `python-multipart`.

## Suivi

- Limitation des tentatives sur `/auth/token` (Redis) avant toute exposition publique.
- Journal d'audit des connexions, à rattacher au MOD-04.
