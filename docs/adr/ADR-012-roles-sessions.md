# ADR-012 — Rôles PostgreSQL séparés, sessions révocables, rotation de clé (M7, lot 2)

- **Statut :** proposé
- **Date :** 2026-10-04
- **Décideurs :** à valider par le porteur du projet
- **Concerne :** `sentry/app/db_roles.py`, `sentry/modules/foundation/sessions.py`,
  `sentry/app/security.py`, `sentry/app/api/v1/auth.py`, migration `f41c7a9d2e86`,
  `docker-compose.yml`

## Contexte

ADR-011 a rendu la chronologie et l'audit immuables pour l'application, avec une limite
explicite : le compte de connexion de l'application **possédait** les tables. Il pouvait donc
supprimer un déclencheur, modifier la structure, et l'immuabilité reposait sur la bonne conduite
du code. Trois autres faiblesses restaient :

- un jeton d'accès JWT de 60 min n'était pas révocable : un jeton volé restait valable une heure,
  et aucun moyen ne permettait de couper une session ;
- changer `SECRET_KEY` déconnectait tout le monde d'un coup, ce qui décourage la rotation ;
- Redis tournait sans mot de passe.

## Décision

1. **Deux rôles PostgreSQL.** Le propriétaire (`MIGRATION_DATABASE_URL`) exécute les migrations ;
   l'application se connecte avec un rôle (`DATABASE_URL`, `DATABASE_APP_ROLE`) qui n'a que
   `SELECT, INSERT, UPDATE, DELETE` sur les données, **`SELECT, INSERT` seulement** sur
   `incident_events` et `audit_events`, `SELECT` sur `alembic_version`, aucun droit de
   structure. `sentry db upgrade` réapplique ces droits après chaque migration ;
   `sentry db app-role ROLE [--create]` les pose à la demande. Le rôle est refusé s'il est
   superutilisateur ou propriétaire d'une table.
2. **Sessions.** Jeton d'accès de 15 min ; jeton de rafraîchissement opaque (256 bits, empreinte
   SHA-256 seule en base), 7 jours, **rotatif** : chaque usage le remplace. Un jeton déjà
   remplacé qui revient révoque toute la lignée (`reuse_detected`). `POST /auth/refresh`,
   `POST /auth/logout`, `sentry users disable|enable|revoke-sessions`.
3. **Rotation de clé.** Chaque JWT porte `kid` (empreinte SHA-256 tronquée de sa clé).
   `SECRET_KEY` signe ; `SECRET_KEY_PREVIOUS` est acceptée en vérification seulement. Une
   valeur vide vaut « non définie ».
4. **Redis protégé** par mot de passe dans Compose ; en production, SENTRY refuse de démarrer
   sans mot de passe ou avec la valeur de développement.

## Justification

- *Révocation des JWT par liste noire (`jti`)* : écartée. Elle impose une lecture Redis ou SQL à
  chaque requête pour un gain marginal face à un accès de 15 min ; la désactivation du compte,
  relue en base à chaque requête, coupe déjà l'accès immédiatement.
- *Jeton de rafraîchissement JWT* : écarté au profit d'un jeton opaque, révocable par nature et
  sans valeur si la base fuit.
- *Rejeu toléré quelques secondes* (requêtes parallèles d'un même client) : écarté. Un client qui
  rafraîchit deux fois en parallèle est déconnecté ; c'est le comportement strict recommandé par
  l'OAuth 2.0 Security BCP, et SENTRY n'a pas encore de client web.
- *Rôles créés par une migration* : écarté. Un rôle est un objet du cluster, pas de la base, et
  son mot de passe ne doit pas figurer dans l'historique Git.

## Conséquences

- Positives : même un code applicatif compromis ne peut plus altérer la chronologie, l'audit ni
  la structure ; un vol de jeton de rafraîchissement est détecté au premier rejeu ; la clé de
  signature peut changer sans déconnexion générale ; plus aucun service sans mot de passe.
- **Négatives :**
  - deux URL de base à configurer, et un rôle à créer une fois sur les volumes existants ;
  - un mot de passe contenant `:`, `@` ou `%` doit être encodé dans l'URL (`%3A`, `%40`, `%25`) ;
  - la table `refresh_tokens` croît : purge des jetons expirés à prévoir (M11) ;
  - les clients doivent gérer le rafraîchissement (le scénario et la CLI le font ; une future
    interface web aussi).

## Suivi

- Lot 3 : reverse proxy TLS, scan d'image (Trivy), conteneur de migration distinct.
- M11 : purge planifiée de `refresh_tokens`, alerte sur `auth.refresh` DENIED.
