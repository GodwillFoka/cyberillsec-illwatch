# ADR-011 — Durcissement de production (M7, lot 1)

- **Statut :** proposé
- **Date :** 2026-10-03
- **Décideurs :** à valider par le porteur du projet
- **Concerne :** MOD-01, `sentry/app/middleware.py`, `sentry/app/throttle.py`,
  `sentry/modules/foundation/audit.py`, migration `e7b2c9d41f05`, `docker-compose.yml`,
  `constraints.txt`

## Contexte

L'audit global du 03/10/2026 (`Rapport/ETAT_GLOBAL_SENTRY_2026-10-03.md`, § 7) a validé les
six modules sur données réelles et relevé cinq écarts de sécurité, tous hors du code métier :

1. `TRUNCATE incident_events` réussit : un déclencheur de ligne ne voit pas `TRUNCATE`, la
   chronologie « immuable » pouvait être vidée d'une instruction ;
2. aucune trace des actions sensibles (connexions, administration, exports, refus d'accès) ;
3. aucun en-tête de sécurité HTTP, pas d'identifiant de requête, page d'erreur par défaut ;
4. cinq échecs de connexion depuis n'importe quelle adresse verrouillaient le vrai titulaire ;
5. PostgreSQL et Redis (sans mot de passe) exposés sur toutes les interfaces du poste ;

et une dette d'outillage : dépendances bornées par le bas seulement, d'où un `mypy` vert en CI
(SQLAlchemy 2.1) et rouge sur le poste Kali (SQLAlchemy 2.0).

## Décision

1. **Immuabilité étendue** : fonction générique `sentry_refuse_rewrite()`, déclencheurs de
   ligne (`UPDATE`, `DELETE`) et **d'instruction (`TRUNCATE`)** sur `incident_events` et
   `audit_events`.
2. **Journal d'audit** `audit_events`, en ajout seul : `auth.login` (réussite, échec, blocage),
   `authz.denied`, `feed.create|update|delete`, `indicator.submit`, `alert.ack`, `hunt.run`,
   `data.export` (API et CLI), `user.create` (CLI). Chaque ligne porte acteur, cible, adresse IP,
   identifiant de requête et un détail tronqué, secrets masqués. Écriture dans une transaction
   **indépendante** de la requête (une connexion refusée annule la transaction de la requête,
   pas sa trace). Doublée d'une ligne JSON `sentry.audit` pour un SIEM. Consultation :
   `GET /api/v1/audit` (ADMIN), `sentry audit list`.
3. **Politique d'échec de l'audit : ouverture.** Si l'écriture échoue, la requête aboutit et
   l'échec est journalisé en ERROR, la ligne JSON servant de trace de secours.
4. **Couche HTTP** (middleware ASGI pur, compatible avec les exports en flux) : `X-Request-ID`
   repris s'il est sûr, généré sinon ; `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`,
   `Permissions-Policy`, `COOP` partout ; CSP `default-src 'none'` et `Cache-Control: no-store`
   sur l'API ; HSTS en production. Erreur inattendue → 500 JSON sans détail interne, avec
   l'identifiant de requête. Journal d'accès JSON (jamais en-têtes ni corps).
5. **Sondes** : `/health` (vivacité, toujours 200) et `/ready` (503 si base injoignable ou
   schéma différent de la head Alembic ; Redis signalé, non bloquant). `HEAD` accepté.
6. **Limitation des connexions par couple compte × IP** (5), par compte toutes adresses (50),
   par IP tous comptes (20). Derrière un reverse proxy, l'adresse réelle vient de
   `X-Forwarded-For`, accepté des seules adresses `FORWARDED_ALLOW_IPS`.
7. **Production** : documentation interactive masquée par défaut (`DOCS_ENABLED`), refus de
   démarrer avec `CORS_ORIGINS=*`.
8. **Infrastructure** : ports Compose liés à `127.0.0.1` ; `constraints.txt` (résolution
   universelle 3.12–3.14) utilisé par la CI et l'image ; scripts `backup.sh` / `restore.sh`.

## Justification

- *Audit dans la transaction de la requête* : écarté, il perdrait précisément les tentatives
  refusées, les plus utiles.
- *Fermeture en cas d'échec de l'audit* : écartée pour le lot 1. Elle transforme une panne de
  base en panne totale, y compris de la connexion. À reconsidérer pour un déploiement soumis à
  une exigence probatoire forte (DORA), avec une file locale durable.
- *Auditer les 422 de validation* (ex. URL interne refusée par le schéma) : écarté, le volume
  serait dominé par des fautes de saisie ; la ligne d'accès JSON garde la trace du 422.
- *Verrouillage par compte seul* : écarté, c'est le déni de service relevé par l'audit.
- *Fichier de verrouillage `uv.lock`* : écarté pour l'instant, la CI et le Dockerfile utilisent
  `pip` ; `constraints.txt` est lu par `pip`, `uv` et Renovate sans changer d'outil.

## Conséquences

- Positives : chronologie et audit inaltérables par l'application, y compris par `TRUNCATE` ;
  chaque action sensible est attribuable ; poste Kali, CI et image installent les mêmes versions ;
  sauvegarde vérifiée et restaurable.
- **Négatives :**
  - le propriétaire des tables peut toujours supprimer un déclencheur : la séparation des rôles
    PostgreSQL (lot 2) est nécessaire pour une immuabilité opposable ;
  - `audit_events` croît sans limite : rétention et partitionnement à décider (M11) ;
  - une connexion de plus par action auditée (session indépendante) ;
  - `constraints.txt` doit être régénéré à chaque ajout de dépendance (commande dans
    `.gitlab-ci.yml`) ;
  - un attaquant disposant de 50 adresses peut encore verrouiller un compte 15 minutes.

## Suivi

- Lot 2 : rôles PostgreSQL séparés, mot de passe Redis, rotation de `SECRET_KEY`, jetons de
  rafraîchissement révocables.
- Lot 3 : reverse proxy TLS, scan d'image, conteneurs séparés pour migrations et worker.
- M11 : rétention de l'audit, alerte sur rafales d'`auth.login` FAILURE et d'`authz.denied`.
