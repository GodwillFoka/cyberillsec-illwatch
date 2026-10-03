# 🛡️ SENTRY — État global après intégration M1–M6

**Date :** 03/10/2026 · **Référence auditée :** `main` = `266b46e` (« Merge branch
'feature/phases-4-6' into 'main' ») · **Auteur de l'audit :** Claude (Cowork), pour Godwill FOKA
**Méthode :** reconstitution du dépôt depuis la copie locale (le bac à sable n'a pas accès à
gitlab.com), CI rejouée sur trois environnements, base PostgreSQL neuve alimentée par de vraies
sources, scénario SOC exécuté contre l'API réelle (`uvicorn`), analyses de sécurité outillées.

---

## 1. Synthèse

Les six modules sont **intégrés dans `main` et fonctionnent ensemble sur données réelles** :
3 867 IOC collectés depuis 3 sources publiques, 1 733 CVE du catalogue KEV officiel, un incident
mené de l'ouverture à la clôture avec post-mortem, des exports, deux sessions de chasse. Le
scénario d'acceptation passe **40/40**, la CI **388 tests verts** sur trois environnements.

Ce qui sépare `main` d'une plateforme exploitable n'est plus du code fonctionnel :

1. **un défaut bloquant sur le poste Kali** : `mypy` échoue avec SQLAlchemy 2.0 (corrigé, § 13) ;
2. **une faille d'intégrité** : `TRUNCATE` contourne l'immuabilité de la chronologie (§ 7) ;
3. **la validation des sources sous clé** (OTX, RedEye, NVD, EPSS), impossible depuis ce bac à
   sable et à faire sur Kali.

**Verdict :** baseline `v0.1.1` acceptable après fusion de `release/v0.1.1` (correctif + rapport).
M7 « Production Hardening » est bien la priorité suivante ; la faille `TRUNCATE` et le
verrouillage des dépendances en sont les deux premiers items.

## 2. Architecture actuelle

```
CLI (Click/Rich, 34 commandes)     API REST (FastAPI, 29 routes)
              └──────────────┬──────────────┘
                 Services métier (sentry/modules)
   threat_feeds · cve_tracker · incidents · dashboard · threat_hunting · foundation
                             │
           SQLAlchemy 2 async · Alembic (6 migrations, 1 seule head)
                             │
          PostgreSQL 16 (14 tables)        Redis 7 (verrous, limitation de débit)
```

Un processus API, un worker unique (`sentry feeds worker`) qui planifie flux, CVE et chasse sous
verrou Redis. Couches respectées : aucun service n'importe FastAPI ; les contrôleurs n'accèdent pas
à SQL directement.

## 3. État M1 → M6, sur quatre niveaux

| Niveau | Définition |
|---|---|
| **CODE** | fonctionnalité développée et fusionnée dans `main` |
| **TESTÉ** | tests automatisés verts (CI) |
| **INTÉGRÉ** | exercé contre des composants réels (PostgreSQL, Redis, API HTTP, sources Internet) |
| **OPÉRATIONNEL** | critère de jalon constaté par `sentry status` sur données réelles, en continu |

| Module | CODE | TESTÉ | INTÉGRÉ | OPÉRATIONNEL | Constat de l'audit |
|---|---|---|---|---|---|
| M1 Foundation | ✅ | ✅ | ✅ | ✅ | API, auth, rôles, migrations, CLI vérifiés en conditions réelles |
| M2 Threat Feeds | ✅ | ✅ | ✅ | ◐ 2/4 | 3 sources saines, 3 867 IOC ; OTX (clé) et STIX/TAXII (jeton RedEye) non constatés |
| M3 CVE | ✅ | ✅ | ◐ | ✘ 0/4 | KEV réel importé (1 733) ; NVD et EPSS bloqués par le bac à sable |
| M4 Incidents | ✅ | ✅ | ✅ | ◐ | cycle complet sur données réelles ; faille `TRUNCATE` ; persistance du critère à constater sur Kali |
| M5 Dashboard | ✅ | ✅ | ✅ | ◐ | synthèse, activité, 8 exports ; séries 7 jours absentes |
| M6 Hunting | ✅ | ✅ | ✅ | ◐ | chasse sur observables et sur 3 867 IOC ; RULE-01 (Tor) non testable ici |

**Avancement défendable**

| Mesure | Valeur | Calcul |
|---|---|---|
| Code du périmètre v1.0 | **≈ 88 %** | tâches du plan directeur livrées et testées (inchangé depuis le 03/10 matin) |
| Intégration réelle | **≈ 80 %** | 5 modules sur 6 intégrés, M3 à moitié |
| Jalons opérationnels | **1 / 6** constaté, 4 partiels | `sentry status` sur la base d'audit |

Confiance : élevée pour les trois mesures sur le périmètre testé ici ; moyenne pour M3, dont la
moitié NVD/EPSS n'a jamais reçu de vraie réponse.

## 4. Fonctionnalités implémentées

- **Renseignement** : CSV, JSON, texte, STIX 2.1, TAXII 2.1 (`taxii2-client` durci), OTX ;
  normalisation, déduplication, provenance multi-sources, expiration par type ; sondes
  `sentry feeds probe` et `sentry taxii discover`.
- **Vulnérabilités** : NVD 2.0 incrémental (filtre `hasKev` à la première synchro), KEV, EPSS,
  score composite 0–100, priorités P0–P3, historique, alertes + webhook.
- **Réponse** : machine d'état NIST SP 800-61, assignation, notes, liens IOC/CVE, ouverture depuis
  une alerte (idempotente), post-mortem obligatoire, chronologie immuable.
- **Pilotage** : synthèse temps réel, activité 24 h, MTTR, exports CSV/JSON en flux.
- **Chasse** : 6 règles, deux modes, sessions enregistrées, chasse planifiée.
- **Sécurité transverse** : JWT + Argon2id, RBAC 3 rôles, anti-SSRF, secrets hors base,
  limitation des connexions, anti-injection CSV.

## 5. Tests et couverture

| Environnement | Python | SQLAlchemy | Résultat |
|---|---|---|---|
| Identique au job GitLab (dépendances les plus récentes) | 3.12.3 | 2.1.3 | 388 ✅, 4 ignorés, **94 %** |
| Matrice GitLab 3.14 | 3.14.7 | 2.1.1 | 388 ✅, 4 ignorés, **93 %** |
| Simulation du poste Kali | 3.12.3 | **2.0.54** | `mypy` ✘ sur `main` → ✅ après correctif ; 388 ✅ |

Les 4 tests ignorés sont les tests réseau réels (`SENTRY_LIVE_TESTS=1`), à lancer sur Kali.

**Nouveau test d'acceptation** : `scripts/scenario_soc.py` rejoue le parcours SOC complet contre
une instance réelle et mesure les latences. Résultat : **40/40**.

## 6. CI/CD

Le pipeline GitLab (qualité → tests matrice 3.12/3.14 → migrations aller-retour → image Docker →
SAST, secrets, dépendances) est **vert sur `main`** d'après les MR fusionnées. Rejoué ici :
qualité, tests et migrations ✅. Non rejoué : construction de l'image (démon Docker absent du bac à
sable) et analyses natives GitLab.

**Risque identifié :** les dépendances ne sont bornées que par le bas (`>=`). La CI installe la
dernière version publiée, le poste Kali une version antérieure : c'est exactement ce qui a produit
l'écart `mypy` du § 13. Correctif prévu en M7 (fichier de contraintes partagé CI/Docker/Kali).

## 7. Sécurité

| Contrôle | Résultat |
|---|---|
| `pip-audit` (dépendances installées) | **0 vulnérabilité connue** |
| `bandit` (code applicatif) | 0 haut, 0 moyen, 2 faibles (faux positifs documentés : sentinelle de clé refusée en production, libellé `"access"`) |
| Sans jeton / jeton altéré / `alg=none` | 401 / 401 / 401 ✅ |
| RBAC : VIEWER crée un incident, lance une chasse ; ANALYST crée une source | 403 ✅ |
| SSRF : source vers `169.254.169.254` | 422 ✅ |
| Injection dans un identifiant de CVE | 422 ✅ |
| Force brute : 6ᵉ tentative | 429 ✅ |
| CORS depuis une origine inconnue | refusé (400) ✅ |
| Secrets dans les journaux | aucun ✅ |
| `UPDATE` / `DELETE` sur la chronologie | refusés par le déclencheur ✅ |
| **`TRUNCATE incident_events`** | **accepté ✘** : un déclencheur de ligne ne voit pas `TRUNCATE` |
| **Propriétaire des tables = compte applicatif** | **✘** : ce compte peut aussi supprimer le déclencheur |
| **Ports Compose** | **✘** : PostgreSQL (5433) et Redis (6379, sans mot de passe) écoutent sur toutes les interfaces du poste |
| **En-têtes de sécurité HTTP** | **absents** (HSTS, nosniff, frame-ancestors, no-store) |
| **Verrouillage de compte** | **contournable en déni de service** : 5 échecs depuis n'importe où bloquent le vrai titulaire 15 min |

Les cinq lignes ✘ deviennent le premier lot de M7.

## 8. Validation réelle — Threat Feeds (M2)

| Source | Résultat | Lus | Nouveaux | Cause si échec |
|---|---|---|---|---|
| IPsum niveau 5 | HEALTHY | 3 528 | 3 528 | — |
| C2IntelFeeds IP 30 j | HEALTHY | 252 | 252 | — |
| C2IntelFeeds domaines 30 j | HEALTHY | 89 | 87 | 2 doublons internes |
| abuse.ch Feodo | DEGRADED | — | — | proxy du bac à sable (403), pas la source |
| abuse.ch URLhaus | DEGRADED | — | — | `ABUSECH_AUTH_KEY` absente (attendu) |
| AlienVault OTX | DEGRADED | — | — | `OTX_API_KEY` absente (attendu) |
| RedEye TAXII | DEGRADED | — | — | proxy du bac à sable ; jeton absent |
| DigitalSide ×2 | inactives | — | — | injoignables (constat du 29/09) |

- **Déduplication** : seconde collecte d'IPsum → 0 nouveau, 3 528 mis à jour ✅.
- **Provenance** : chaque IOC expose sa source dans l'API ✅. Recouvrement entre sources : 0
  (C2IntelFeeds et IPsum ne partagent aucune IP ce jour-là).
- **Expiration** : 3 867 / 3 867 actifs, attendu le jour même de la collecte.
- **Performance** : collecte complète en 20 s, pic mémoire 111 Mo (cible 256 Mo).
- **Critères M2** : volume ✅, 3 sources ✅, OTX ✘, STIX ✘ → **non atteint ici, atteignable sur
  Kali** avec la clé OTX et le jeton RedEye.

## 9. Validation réelle — CVE (M3)

- **KEV** : catalogue officiel `2026.10.02`, 1 733 entrées, importé en **3 s** via le dépôt
  GitHub `cisagov/kev-data` (mêmes données que cisa.gov, inaccessible depuis le bac à sable) ;
  le nouveau champ `forensicTriage` est toléré ✅.
- **NVD, EPSS** : non joignables depuis le bac à sable. À constater sur Kali (`sentry cves sync`).
- **Observation de scoring** : sans CVSS ni EPSS, une CVE KEV liée au ransomware vaut 35 → P3.
  Situation transitoire (la première synchro NVD récupère toutes les CVE KEV via `hasKev`), mais
  elle devient durable si ce filtre échoue. Proposition pour M8, à trancher par ADR : plancher
  « KEV ⇒ au moins P1 », cohérent avec les délais de la directive CISA BOD 22-01.

## 10. Incident Management (M4)

Parcours réel : ouverture (ANALYST) → assignation → liaison d'un IOC IPsum et d'une CVE KEV →
NOUVEAU→CLOTURE refusé (409) → ANALYSE → CONFINEMENT → ERADICATION → RECUPERATION → note d'un
second analyste → clôture sans post-mortem refusée (422) → clôture avec post-mortem. Chronologie :
**10 évènements**. Latence médiane des appels incidents : **11,5 ms**.

## 11. SOC Dashboard (M5)

Synthèse 28 ms, activité récente 200 évènements, 8 exports valides (IOC CSV 654 Ko en 190 ms,
CVE CSV 660 Ko en 105 ms). **Fonctionnel techniquement ; pas encore une console SOC** : ni série
temporelle, ni file de triage, ni vue par analyste. Ces manques relèvent de M9.

## 12. Threat Hunting (M6)

- Sur observables (IOC réel, domaine `duckdns.org`, domaine aléatoire, IP propre, valeur invalide) :
  **3 correspondances** (RULE-02, RULE-03, RULE-06), 1 rejet, 12 ms.
- Sur la base complète (3 867 IOC) : **27 ms**, 1 correspondance.
- RULE-01 (Tor) non testée ici : liste torproject.org bloquée par le bac à sable.

## 13. Dette technique

| # | Dette | Gravité | Traitement |
|---|---|---|---|
| D1 | `mypy` échoue avec SQLAlchemy 2.0 (`Select[Any, Any]`) — cause du `stash` local du 03/10 | Moyenne | **corrigé** dans `release/v0.1.1` (annotation `Executable`, valide en 2.0 et 2.1) |
| D2 | Dépendances non verrouillées | Moyenne | M7 |
| D3 | Pas de test d'acceptation en CI (le scénario exige des données réelles) | Moyenne | M7/M11 : jeu de données figé + job dédié |
| D4 | Image Docker jamais construite hors GitLab | Faible | job GitLab existant |
| D5 | Heuristique DGA non calibrée sur corpus | Faible | M8 |
| D6 | RULE-05 par mots-clés, sans CPE | Faible | M8 |
| D7 | Six branches locales obsolètes, trois `stash` | Faible | nettoyage (§ 16) |

## 14. Risques restants

| Risque | Niveau | Parade |
|---|---|---|
| Altération de la chronologie par `TRUNCATE` ou par le propriétaire des tables | **Élevé** pour un usage probatoire | M7 lot 1 |
| Redis/PostgreSQL exposés sur le réseau local du poste Kali | Moyen | M7 lot 1 |
| Dérive des dépendances entre poste et CI | Moyen | M7 lot 1 |
| NVD/EPSS jamais éprouvés en réel | Moyen | `sentry cves sync` sur Kali cette semaine |
| Une seule source STIX, sous jeton | Moyen | jeton RedEye ; budget CrowdSec à évaluer |
| Verrouillage de compte exploitable en déni de service | Faible | M7 lot 1 |

## 15. Feuille de route

| Étape | Objectif | État |
|---|---|---|
| M1–M6 | Socle fonctionnel | ✅ intégré dans `main` |
| Audit global | Validation M1–M6 | ✅ ce rapport |
| `v0.1.1` | Baseline stable | ⏳ fusion de `release/v0.1.1`, puis tag |
| M7 | Production Hardening | 🔄 lot 1 sur `feature/m7-production-hardening` |
| M8 | Detection & Correlation | ⏳ |
| M9 | SOC Operations (triage L1/L2/L3) | ⏳ |
| M10 | CTI Intelligence (acteurs, campagnes, ATT&CK) | ⏳ |
| M11 | Observability & Deployment | ⏳ |
| `v0.2.0` | Production Candidate | ⏳ |

Détail et critères de sortie : `docs/ROADMAP.md`.

## 16. Prochaine phase — actions dans l'ordre

1. **Fusionner `release/v0.1.1` → `main`** (MR, pipeline vert). Vérification : `mypy sentry`
   passe sur Kali **sans** le `stash`.
2. **Taguer** : `git tag -a v0.1.1 -m "SENTRY M1-M6 integrated baseline" && git push origin v0.1.1`.
3. **Constater M2/M3 sur Kali** : clés OTX, NVD, jeton RedEye dans `.env`, puis
   `sentry feeds fetch-all && sentry cves sync && sentry status`. Vérification : M2 et M3 ✅.
4. **Rejouer le scénario sur Kali** : `python scripts/scenario_soc.py` → 40/40.
5. **Nettoyer** : `git stash drop` ×3 (contenu intégré ou corrigé), supprimer les branches
   locales fusionnées (`git branch --merged main`).
6. **Fusionner `feature/m7-production-hardening`** (lot 1) après revue.
