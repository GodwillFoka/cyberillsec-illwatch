# Changelog

Toutes les évolutions notables de SENTRY sont consignées ici.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et le versionnage
respecte [Semantic Versioning](https://semver.org/lang/fr/).

## [Non publié]

## [0.1.0] — 2026-09-24

Jalon M1 : squelette opérationnel validé (clôture de la phase 1 Foundation).

### Ajouté
- Squelette applicatif complet conforme au §6.2 du Cahier des Charges (MOD-01).
- Configuration Pydantic immuable validée au démarrage (RF-01).
- Moteur asynchrone SQLAlchemy 2.0 et sessions injectées par dépendance FastAPI.
- Modèles relationnels `users`, `threat_feeds`, `indicators`, `cves`, `incidents`,
  `incident_events` conformes au §4.4 (RF-02).
- Moteur de Score de Risque Composite déterministe avec décomposition auditable (RF-14).
- Machine d'état des incidents à 6 étapes avec garde-fous de transition (RF-18).
- Détection et normalisation des IOC — IPv4/IPv6, domaines, URL, hashs, e-mails (RF-07, RF-08).
- CLI `sentry` : `version`, `config`, `db check`, `db init` (RF-03).
- Endpoint `/health` avec diagnostic de connexion base de données.
- Orchestration Docker Compose PostgreSQL 16 + Redis 7.2 et image applicative non privilégiée.
- Pipeline CI GitLab en quatre étapes : qualité (ruff, mypy strict), tests (PostgreSQL et Redis
  réels, seuil de couverture 80 %), build de l'image Docker, et analyses de sécurité natives
  (SAST, détection de secrets, scan de dépendances).
- Gabarits de merge request et d'issues GitLab, configuration Renovate.
- Conversion Markdown versionnable du Cahier des Charges et du Product Vision Document.
- Authentification (MOD-01, ADR-003) : hachage Argon2id, jetons JWT, `POST /api/v1/auth/token`,
  `GET /api/v1/users/me`, dépendances `get_current_user` et `require_roles`.
- CLI (RF-03) : `sentry db upgrade | downgrade | current`, `sentry seed` (flux publics abuse.ch,
  idempotent), `sentry users create`.
- Tests de bout en bout sur PostgreSQL réel : migrations montée/descente, absence de dérive entre
  modèles et migrations (`alembic check`), parcours CLI complet.
- ADR-003 (authentification en phase 1) et ADR-004 (recalage du planning, proposé).

### Corrigé
- **Sécurité** : le validateur de `SECRET_KEY` n'appliquait aucun contrôle. En production, SENTRY
  refuse désormais de démarrer avec la clé par défaut, une clé de moins de 32 caractères ou
  `DEBUG=true`.
- Les tests tournaient toujours sur SQLite, y compris en CI où PostgreSQL était démarré pour rien :
  la base de test suit maintenant `DATABASE_URL`, avec isolation transactionnelle par test.
- `sentry db init` affichait une consigne au lieu d'appliquer les migrations.
- L'image Docker applique les migrations au démarrage avant de lancer l'API (critère M1).
- `alembic.ini` : `version_path_separator` remplacé par `path_separator` (déprécié).
- Tri des imports : le dossier local `alembic/` ne masque plus le paquet tiers pour `ruff`.
- Port PostgreSQL hôte : `docker-compose.yml` expose 5433 ; `.env.example`, la valeur par défaut
  de `DATABASE_URL` et la documentation pointaient encore vers 5432.

### Modifié
- **Dépôt migré de GitHub vers GitLab**, qui devient la plateforme unique du projet
  (voir `docs/adr/ADR-002-hebergement-gitlab.md`). Suppression de `.github/`, des workflows
  GitHub Actions et de Dependabot ; mise à jour de toutes les références dans la documentation.
