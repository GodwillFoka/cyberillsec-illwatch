# 🛡️ SENTRY — Réexécution complète et bilan M7 « Production Hardening », lot 3

**Date :** 04/10/2026 · **Branches :** `release/v0.1.1` (`702a030`) et
`feature/m7-production-hardening` (`HEAD`, lots 1 à 3) · **Décisions :** ADR-013 (proposé),
ADR-014 (à trancher)
**Verdict :** M7 est **codé en entier** et vérifié de bout en bout dans le bac à sable, y compris
derrière TLS. Il reste à le constater sur un VPS européen (critère de sortie du lot 3) et sur
Kali pour NVD, EPSS, OTX et RedEye.

---

## 1. Réexécution des deux dernières demandes : ce qui a été refait

| Étape | Résultat du 04/10 |
|---|---|
| Audit Git de `main` (sur ton poste) | `main` = `266b46e`, inchangé ; aucune nouvelle branche |
| CI baseline `release/v0.1.1`, 3 environnements | 388 ✅ ×3 (3.12 SA 2.1.3, 3.14 SA 2.1.1, 3.12 SA 2.0.54) |
| CI M7, 3 environnements | 437 ✅ ×3, couverture 94 % (93 % sous 3.14) |
| Migrations | une seule head, aller-retour ✅ sur les deux branches |
| Base **vierge**, données réelles (baseline) | 4 063 IOC (IPsum 3 731, C2Intel 245 + 87), 1 733 CVE KEV ; scénario **40/40, rejoué deux fois** |
| Base **vierge**, données réelles (M7, rôle applicatif) | mêmes données + CVSS NVD réel des 1 733 CVE KEV ; scénario **48/48, rejoué deux fois** |
| Répartition des scores (base vierge) | P0 0 · P1 617 · P2 1 100 · P3 16 : identique à la veille, Log4Shell = 75 |
| RULE-01 sur liste Tor réelle | 1 746 relais, 2/2 détectés |
| Image Docker | construite, migrations en conteneur séparé, API en production sans identifiants propriétaire, UID 10001 |
| TLS | Caddy devant le conteneur de production : TLS 1.3, HTTP/2, HSTS, `/docs` masqué, pas d'en-tête `Server` |
| `pip-audit` (contraintes) / `bandit` | 0 vulnérabilité / 0 haut, 0 moyen |
| Copie sur le poste | ✅ faite (dossier `patches`) |

## 2. Erreurs trouvées pendant la réexécution, corrigées

| Erreur | Effet | Correctif |
|---|---|---|
| Tests impossibles à relancer après avoir changé de branche | sur la baseline, **les 392 tests en erreur** (la base de test contenait les tables M7 liées à `users`) | remise à zéro par `DROP SCHEMA public CASCADE` (base `_test` uniquement) |
| Le schéma recréé accordait `CREATE` à tous les rôles | le rôle applicatif aurait pu créer des tables dans la base de test ; **détecté par le test du rôle applicatif** | `GRANT USAGE` seulement, comme PostgreSQL 15+ par défaut |
| `alembic/env.py` : `fileConfig()` désactivait les journaux existants | après `sentry db upgrade` dans le même processus, **le journal d'audit JSON devenait muet** | `disable_existing_loggers=False` |
| Scénario de la baseline : contrôle SSRF non probant | le 422 venait du type de flux en minuscules et du schéma `http` ; le rapport d'audit du 03/10 affirmait un succès non démontré | requête valide, message de l'anti-SSRF vérifié ; **rapport rectifié** |
| Scénario de la baseline non rejouable | compte `viewer` bloqué 15 min | cible aléatoire inexistante (vérifie aussi l'absence d'énumération) |
| Moteur de base global conservé entre tests | un test « production » laissait l'URL fictive au test CLI suivant | réinitialisation dans la fixture |
| Test EPSS dépendant de l'ordre | CVE réelle validée par un test CLI antérieur | identifiant de test dédié |

## 3. Lot 3 : contenu

- **TLS** : `deploy/Caddyfile` (Let's Encrypt, autorité interne pour `localhost`), en-tête
  `Server` retiré, `X-Forwarded-For` réécrit par Caddy. Vérifié : un `X-Forwarded-For: 6.6.6.6`
  envoyé par le client n'apparaît pas dans l'audit, seule l'adresse réelle y figure.
- **`docker-compose.prod.yml`** : Caddy seul exposé ; conteneur `migrate` éphémère (propriétaire) ;
  API et worker sans `MIGRATION_DATABASE_URL` ; secrets obligatoires ; uvicorn n'accepte
  `X-Forwarded-For` que de `172.30.0.10` (Caddy). Validé par `docker compose config`.
- **CI** : image poussée sous son SHA, **Container Scanning** GitLab (non bloquant au départ),
  job `compose-config`.
- **Production** refusée avec un mot de passe de base absent ou de développement.
- **Entretien quotidien** du worker : purge des sessions périmées, `cve.epss_stale` ;
  `sentry status` : « ⚠ EPSS jamais synchronisé : … aucune CVE ne peut atteindre P0 ».
- **ADR-014 (à trancher)** : plancher « KEV ⇒ au moins P1 » et dernière valeur EPSS connue.

## 4. Ce qui reste impossible depuis le bac à sable

| Élément | Raison | Où le faire |
|---|---|---|
| API NVD, EPSS, OTX, RedEye, abuse.ch | refusés par le proxy du bac à sable | Kali, avec les clés |
| Images officielles (`python:3.12-slim`, `postgres`, `redis`, `caddy`) | Docker Hub, GHCR, ECR bloqués | pipeline GitLab, Kali |
| Analyse Trivy locale | binaires et base de vulnérabilités inaccessibles | job `container_scanning` |
| Pousser sur GitLab | 403 depuis le bac à sable, et règle du projet | toi, via le bundle |
| Préproduction 7 jours sur VPS UE | hors de portée d'une session | M11 |

## 5. Métriques

| Indicateur | Lot 2 | **Lot 3** |
|---|---|---|
| Tests | 432 | **437** |
| Couverture | 94 % | **94 %** |
| Scénario d'acceptation | 48/48 | **48/48** sur base vierge, rejouable |
| Opérations API / commandes CLI | 35 / 40 | 35 / 40 |
| Services exposés en production | API + base + Redis (local) | **Caddy seul** |
| Identifiants propriétaire dans l'API | oui (migrations au démarrage) | **non** |

## 6. Prochaines étapes, dans l'ordre

1. Fusionner `release/v0.1.1`, taguer `v0.1.1`.
2. Fusionner `feature/m7-production-hardening` (lots 1 à 3).
3. Sur Kali : migration de `.env` (procédure), scénario 48/48, `sentry cves sync` avec EPSS.
4. Trancher ADR-014 ; si accepté, l'implémenter en ouverture de M8.
5. VPS UE : `docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile full up -d`,
   SSL Labs ≥ A, 7 jours de collecte → M7 clos et M11 entamé.
