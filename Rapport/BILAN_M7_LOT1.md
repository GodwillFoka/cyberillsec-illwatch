# 🛡️ SENTRY — Bilan M7 « Production Hardening », lot 1

**Date :** 03/10/2026 · **Branche :** `feature/m7-production-hardening` (depuis
`release/v0.1.1`) · **Décision :** ADR-011 (proposé)
**Verdict :** les cinq écarts ✘ de l'audit global (§ 7) sont fermés et vérifiés ; M7 reste
ouvert sur ses lots 2 (rôles PostgreSQL, Redis, rotation des clés) et 3 (TLS, déploiement).

---

## 1. Écarts de l'audit → correctifs

| Écart (audit § 7) | Correctif | Preuve |
|---|---|---|
| `TRUNCATE incident_events` accepté | Déclencheurs d'instruction `BEFORE TRUNCATE` (migration `e7b2c9d41f05`) | `TRUNCATE incident_events`, `TRUNCATE incidents CASCADE`, `TRUNCATE audit_events` → « immuable : TRUNCATE refusé » (test PostgreSQL + constat manuel) |
| Aucune trace des actions sensibles | `audit_events` en ajout seul, 10 actions consignées, API + CLI | 12 tests ; scénario : 49 lignes produites, 6 types attendus présents |
| Pas d'en-têtes de sécurité, erreurs brutes | Middleware ASGI : `X-Request-ID`, CSP, `nosniff`, `X-Frame-Options`, `no-store`, HSTS (prod), 500 JSON | 10 tests ; `curl -D -` sur l'API réelle |
| Verrouillage du titulaire en 5 essais | Compteurs compte × IP (5), compte (50), IP (20) | test unitaire + scénario : attaquant 429, titulaire 200 depuis une autre adresse |
| PostgreSQL / Redis exposés sur le LAN | Ports Compose liés à `127.0.0.1` | `docker compose config` |
| Dérive des dépendances poste / CI | `constraints.txt` universel, utilisé par CI et image | installation vérifiée sous Python 3.12, 3.13, 3.14 |

## 2. Ajouts d'exploitation

- **`/ready`** : 503 si base injoignable ou schéma ≠ head Alembic (déploiement sans migration),
  Redis signalé non bloquant ; `HEAD` accepté sur `/health` et `/ready`.
- **Journal JSON** de l'API configuré au démarrage : accès (`sentry.http`), audit, sécurité.
- **Sauvegarde / restauration** : `scripts/backup.sh` (pg_dump `-Fc`, vérification
  `pg_restore --list`, SHA-256, rotation) et `scripts/restore.sh` (contrôle d'empreinte,
  confirmation explicite, transaction unique). Testés : 3 sauvegardes, rotation à 2, restauration
  sur une base vierge (3 867 IOC restaurés, déclencheurs d'immuabilité actifs après restauration).
- **Production** : `/docs` masqué par défaut, `CORS_ORIGINS=*` refusé au démarrage,
  `--proxy-headers --no-server-header`.
- **Documentation** : `docs/OPERATIONS.md`, ADR-011, architecture, README, CHANGELOG.

## 3. Métriques

| Indicateur | `main` (audit) | M7 lot 1 |
|---|---|---|
| Tests | 388 | **410** (+22) |
| Couverture | 94 % | **94 %** |
| `mypy --strict` SQLAlchemy 2.0 / 2.1 | ✘ / ✅ | **✅ / ✅** |
| Environnements CI rejoués | 3 | 3 (3.12 SA 2.1, 3.14, 3.12 SA 2.0) |
| Scénario d'acceptation | 40/40 | **44/44** |
| Tables / migrations | 14 / 6 | **15 / 7** (une seule head) |
| Opérations API / commandes CLI | 31 / 34 | **33 / 35** |
| `pip-audit` (contraintes figées) | 0 | **0** |
| `bandit` haut / moyen | 0 / 0 | **0 / 0** |
| Latence médiane incidents / chasse sur 3 867 IOC | 11,5 ms / 27 ms | 11,6 ms / **32 ms**¹ |

¹ Médiane de 7 exécutions (27 à 114 ms) ; la mesure unique du scénario (126 ms) tombait sur un
pic. Écart de +5 ms attribuable à l'écriture de la ligne d'audit dans sa propre transaction.

## 4. Limites assumées (ADR-011)

- Le propriétaire des tables peut supprimer un déclencheur : immuabilité **applicative**, pas
  encore opposable. Lot 2 : rôle applicatif non propriétaire.
- Audit en **ouverture** sur échec d'écriture (la ligne JSON reste la trace de secours).
- Les rejets de validation (422) ne sont pas audités, seulement journalisés en accès.
- `audit_events` sans rétention : à décider en M11.

## 5. Prochaines étapes

1. Revue puis fusion `release/v0.1.1` → `main`, tag `v0.1.1`.
2. Rebaser si besoin, puis MR `feature/m7-production-hardening` → `main`. Vérification :
   pipeline vert, `sentry db upgrade` puis `curl -fsS localhost:8000/ready` → `"ready"`.
3. Sur Kali : `python scripts/scenario_soc.py` → 44/44.
4. Lot 2 de M7 (rôles PostgreSQL, mot de passe Redis, rotation de `SECRET_KEY`).
