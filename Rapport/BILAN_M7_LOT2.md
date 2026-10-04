# 🛡️ SENTRY — Bilan M7 « Production Hardening », lot 2

**Date :** 04/10/2026 · **Branche :** `feature/m7-production-hardening` (lots 1 et 2) ·
**Décision :** ADR-012 (proposé)
**Verdict :** la limite principale du lot 1 est levée : l'application ne possède plus ses tables
et ne peut plus altérer la structure, l'audit ni la chronologie, même compromise. Les sessions
sont révocables. M7 reste ouvert sur le lot 3 (TLS, scan d'image, déploiement).

---

## 1. Ce qui a été rejoué depuis le lot 1

| Opération non faite le 03/10 | Résultat le 04/10 |
|---|---|
| Construction de l'image Docker | ✅ construite et exécutée en production (migrations par le propriétaire, API en rôle applicatif, `/ready` vert, HSTS, `/docs` masqué, UID 10001, pas d'en-tête `Server`). Docker Hub, GHCR, ECR et le miroir Google étant bloqués depuis le bac à sable, la base `python:3.12-slim` a été remplacée localement par Ubuntu 24.04 + CPython 3.12 ; le Dockerfile, lui, est inchangé. |
| NVD (API) | ❌ toujours bloqué. **Contourné** : import des flux NVD 2.0 réels (miroir fkie-cad) → les 1 733 CVE du catalogue KEV complétées par leur CVSS NVD |
| EPSS | ❌ toujours bloqué, aucun miroir fiable trouvé |
| RULE-01 (Tor) | ✅ validée sur une liste réelle de 1 746 relais (miroir GitHub non officiel) : 2 relais sur 2 détectés, l'IP propre ignorée |
| Copie des livrables sur le poste | à refaire : le poste était hors ligne le 03/10 (voir fin de livraison) |

## 2. Erreurs rencontrées pendant l'exécution réelle, corrigées

| Erreur | Cause | Correctif |
|---|---|---|
| `/ready` en 500 et `sentry db upgrade` en échec avec le rôle applicatif | mot de passe encodé (`%3A`) dans l'URL : `ConfigParser` d'Alembic l'interprète comme une interpolation | `%` doublé avant passage à Alembic (+ test de non-régression). **Défaut antérieur au lot 2** : tout mot de passe de base contenant un caractère spécial cassait les migrations |
| `sentry config` affichait les mots de passe des URL | seules les clés nommées étaient masquées | masquage du mot de passe dans toute URL de connexion |
| Tentative SSRF absente de l'audit | rejet par la validation du schéma (422), avant la route | gestionnaire de validation qui audite les seules `UnsafeFeedURLError`, attribuées au porteur du jeton |
| Scénario non rejouable avant 15 min | l'attaquant simulé utilisait 127.0.0.1, ce qui bloquait le compte de test | adresse d'attaquant aléatoire (RFC 5737) via `X-Forwarded-For` |
| Construction d'image impossible en réseau filtré | `# syntax=docker/dockerfile:1` télécharge un frontal depuis Docker Hub | directive supprimée (aucune syntaxe avancée utilisée) |
| Lignes d'accès doublées | journal d'uvicorn + journal JSON `sentry.http` | `--no-access-log` |
| Import NVD : 1,9 Go de mémoire | `json.load` d'un flux annuel décompressé (> 500 Mo) | lecture en flux objet par objet : **221 Mo** |
| `mypy` en échec sous SQLAlchemy 2.1.1 (Python 3.14) | inférence de type plus faible que 2.1.3 | annotations explicites ; vérifié sous 2.0.54, 2.1.1 et 2.1.3 |

## 3. Contenu du lot 2

**Rôles PostgreSQL.** Constat direct avec le rôle `sentry_app` sur la base d'audit :

| Opération | Résultat |
|---|---|
| `SELECT` / `INSERT` / `UPDATE` sur les données | autorisé |
| `INSERT` dans `audit_events` | autorisé |
| `UPDATE audit_events`, `DELETE FROM incident_events`, `TRUNCATE incident_events` | `permission denied` (avant même les déclencheurs) |
| `DROP TRIGGER`, `ALTER TABLE`, `DROP TABLE` | `must be owner` |
| `CREATE TABLE` | `permission denied for schema public` |
| `UPDATE alembic_version` | `permission denied` |

**Sessions.** Accès 15 min ; jeton de rafraîchissement opaque, empreinte seule en base, rotatif ;
rejeu → lignée révoquée et `auth.refresh` DENIED dans l'audit ; déconnexion ; `sentry users
disable|enable|revoke-sessions`.

**Clés.** `kid` dans chaque JWT ; `SECRET_KEY_PREVIOUS` en vérification seule ; valeur vide
traitée comme absente (sans cela, une clé précédente vide aurait été acceptée).

**Redis.** Mot de passe dans Compose ; démarrage refusé en production sans mot de passe ou avec
celui de développement.

**Import NVD hors ligne** (`sentry cves import`) : utile pour un déploiement isolé et pour
valider M3 sans l'API.

## 4. Constat sur données réelles : le score sans EPSS

Avec le CVSS réel du NVD et sans EPSS, la répartition des 1 733 CVE KEV est :

| Priorité | CVE | Score moyen |
|---|---|---|
| P0 | **0** | — |
| P1 | 617 | 65,9 |
| P2 | 1 100 | 51,6 |
| P3 | 16 | 37,8 |

Sans EPSS, le score plafonne à 75 (CVSS 30 + KEV 25 + exploit 10 + ransomware 10) : **aucune
CVE ne peut atteindre P0**, pas même Log4Shell (75, P1). Avec l'EPSS de Log4Shell (≈ 0,94), elle
passerait à ≈ 98. Conséquence opérationnelle : une panne de l'API EPSS fait disparaître toutes
les P0 sans alerte. Deux mesures à trancher par ADR en M8 :

1. alerte d'exploitation si la dernière synchronisation EPSS date de plus de 48 h ;
2. plancher « KEV ⇒ au moins P1 » (16 CVE KEV sont aujourd'hui en P3).

Confiance : élevée sur les chiffres (calcul déterministe sur données NVD réelles) ; l'effet
d'EPSS sur la répartition reste à mesurer sur Kali.

## 5. Métriques

| Indicateur | Lot 1 | **Lot 2** |
|---|---|---|
| Tests | 410 | **432** (+22) |
| Couverture | 94 % | **94 %** (93 % sous 3.14) |
| Environnements CI rejoués | 3 | 3 (3.12 SA 2.1.3, 3.14 SA 2.1.1, 3.12 SA 2.0.54) |
| Scénario d'acceptation | 44/44 | **48/48**, API en rôle applicatif, rejouable |
| Tables / migrations | 15 / 7 | **16 / 8**, une seule head |
| Opérations API / commandes CLI | 33 / 35 | **35 / 40** |
| Image Docker | non construite | **construite et exécutée** (base de substitution) |
| `pip-audit` / `bandit` haut-moyen | 0 / 0 | **0 / 0** |
| Rafraîchissement de session (latence) | — | 9,8 ms |

## 6. Limites assumées

- Un client qui rafraîchit deux fois en parallèle est déconnecté (rejeu strict).
- `refresh_tokens` sans purge planifiée (M11).
- Base Docker de substitution : la taille d'image mesurée (730 Mo) n'est pas représentative de
  `python:3.12-slim` (≈ 250 Mo attendus) ; le job GitLab `image-docker` reste la référence.

## 7. Prochaines étapes

1. Fusion `release/v0.1.1` → `main`, tag `v0.1.1`.
2. MR `feature/m7-production-hardening` (lots 1 et 2) → `main`.
3. Sur Kali : créer le rôle applicatif, passer `.env` aux nouvelles variables, `sentry db
   upgrade`, scénario 48/48, `sentry cves sync` (NVD + EPSS) pour mesurer la vraie répartition.
4. Lot 3 de M7 : reverse proxy TLS (Caddy), scan d'image Trivy en CI, conteneur de migration.
5. ADR M8 sur la dépendance à EPSS et le plancher KEV.
