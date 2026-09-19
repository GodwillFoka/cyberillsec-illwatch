# Changelog

Toutes les évolutions notables de SENTRY sont consignées ici.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et le versionnage
respecte [Semantic Versioning](https://semver.org/lang/fr/).

## [Non publié]

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
- Pipeline CI GitHub Actions : ruff, mypy strict, pytest, seuil de couverture 80 %.
- Conversion Markdown versionnable du Cahier des Charges et du Product Vision Document.

## [0.1.0] — à venir

Jalon M1 : squelette opérationnel validé.
