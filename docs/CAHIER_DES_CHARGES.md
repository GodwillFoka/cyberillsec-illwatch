# SENTRY — Cahier des charges & dossier d'ingénierie logicielle

> **Conversion Markdown versionnable** du document maître
> `CYBERILL-SENTRY — Cahier des Charges & Dossier d'Ingénierie v1.0.0`.
> Le PDF d'origine est conservé dans [`pdf/SENTRY_Cahier_des_Charges.pdf`](pdf/SENTRY_Cahier_des_Charges.pdf).
> En cas de divergence, **ce fichier Markdown fait foi** : il est celui que la CI, les revues de
> code et les merge requests référencent.

| | |
|---|---|
| **Projet** | SENTRY — Security Monitoring & Threat Intelligence Platform |
| **Initiative** | CyberillSec — A CYBERILL Initiative |
| **Auteur & architecte** | Godwill FOKA, Lead Architect & Security Engineer |
| **Destinataire** | Équipe d'ingénierie logicielle / développeurs en onboarding |
| **Version** | v1.0.0 (Master Engineering Baseline) |
| **Baseline** | Juillet – Septembre 2026 |
| **Dépôt** | `gitlab.com/GodwillFoka/CYBERILLSEC-SENTRY` (voir [ADR-002](adr/ADR-002-hebergement-gitlab.md)) |
| **Classification** | Interne CYBERILL — document fondateur de référence |
| **Statut** | Approuvé pour développement |

---

## Sommaire

1. [Cadre métier et vulgarisation](#1-cadre-métier-et-vulgarisation)
2. [Phase d'avant-projet et analyse préalable](#2-phase-davant-projet-et-analyse-préalable)
3. [Cahier des charges fonctionnel](#3-cahier-des-charges-fonctionnel-cdcf)
4. [Cahier des charges technique et exigences non fonctionnelles](#4-cahier-des-charges-technique-cdct)
5. [Planning opérationnel et découpage des 44 tâches](#5-planning-opérationnel)
6. [Guide d'onboarding développeur](#6-guide-donboarding-développeur)

---

## 1. Cadre métier et vulgarisation

### 1.1 CYBERILL et l'écosystème CyberillSec

CYBERILL est une initiative d'ingénierie et de résilience numérique fondée à Berlin par Godwill
FOKA, articulée autour de six piliers :

| Branche | Domaine | Périmètre |
|---|---|---|
| **CyberillSec / SENTRY** | Threat Intelligence | Plateforme de veille CTI |
| Cyberill Labs | Recherche | Analyse de malware, offensif, pentest |
| Cyberill Academy | Formation | Certifications, workshops, sensibilisation |
| Cyberill Consulting | Conseil | GRC, audit, advisory |
| Cyberill CERT | Réponse à incident | DFIR, gestion de crise |
| Cyberill Cloud | Cloud | Plateformes SaaS sécurisées |

CyberillSec est le bras armé de veille stratégique : collecter, analyser, corréler et vulgariser les
données relatives aux cyberattaques mondiales.

### 1.2 Mission de SENTRY

SENTRY est le moteur logiciel qui propulse CyberillSec. Dans l'industrie, un analyste sécurité passe
60 à 70 % de son temps à copier-coller des indicateurs entre une dizaine d'outils, lire des bulletins
illisibles et trier des alertes en double.

SENTRY crée un cerveau centralisé qui :

1. collecte automatiquement le renseignement sur les menaces (flux publics, bases gouvernementales,
   flux communautaires) ;
2. normalise ces données dans un format unique ;
3. calcule un score de risque objectif pour chaque vulnérabilité ;
4. expose une interface unifiée (API REST, CLI, dashboard SOC) permettant de décider d'une
   remédiation en quelques secondes plutôt qu'en plusieurs heures.

### 1.3 Lexique du développeur cyber

| Terme | Définition |
|---|---|
| **CTI** | *Cyber Threat Intelligence* — renseignement sur les attaquants, leurs motivations, capacités et méthodes. |
| **IOC** | *Indicator of Compromise* — empreinte numérique laissée par un attaquant : IP malveillante, domaine frauduleux, URL de phishing, hash d'un binaire. |
| **CVE** | *Common Vulnerabilities and Exposures* — identifiant universel d'une faille (ex. `CVE-2026-16812`). |
| **CVSS** | Note technique de 0.0 à 10.0 mesurant la sévérité intrinsèque d'une faille (9.8 = critique, exploitable à distance sans authentification). |
| **EPSS** | *Exploit Prediction Scoring System* — score probabiliste de 0.0 à 1.0 calculé quotidiennement par FIRST, prédisant la probabilité d'exploitation réelle sous 30 jours. Au-delà de 0.7, l'attaque est très probablement imminente. |
| **CISA KEV** | *Known Exploited Vulnerabilities* — catalogue gouvernemental américain des failles dont l'exploitation active a été formellement prouvée. Une CVE au KEV est une urgence absolue. |
| **TTP / MITRE ATT&CK** | Cartographie des comportements d'attaquants : les tactiques disent le *pourquoi* (« Accès initial »), les techniques le *comment* (« T1566 — Phishing »). |
| **Threat Hunting** | Démarche proactive de recherche, dans son propre réseau, de traces d'attaques ayant contourné les défenses classiques. |
| **Sigma** | Règles génériques en YAML pour détecter des comportements suspects dans les journaux d'événements. |
| **YARA** | Signatures textuelles ou binaires identifiant des familles de malwares dans des fichiers. |

### 1.4 La journée type de l'analyste SOC

**Sans SENTRY** — Alex ouvre quinze onglets (CISA, NVD, AlienVault, réseaux sociaux, presse
spécialisée), lit quarante articles, repère une faille Fortinet, cherche manuellement son CVSS,
vérifie l'existence d'un exploit public, croise les IP attaquantes, ouvre un ticket. Il est 11 h 30
et rien n'est encore bloqué.

**Avec SENTRY** — les tâches asynchrones ont tourné toute la nuit. À 08 h 01, `sentry dashboard show`
affiche les trois CVE critiques de la nuit (score > 80 parce que KEV = oui et EPSS > 0.85), les
quarante nouveaux IOC dédupliqués et rattachés à la campagne en cours, et l'incident créé
automatiquement avec sa chronologie pré-remplie. En cinq minutes, le blocage firewall est lancé et
le RSSI notifié.

---

## 2. Phase d'avant-projet et analyse préalable

### 2.1 Contexte et état de l'art en 2026

1. **Industrialisation des ransomwares (RaaS)** — les attaquants exploitent les vulnérabilités moins
   de 48 heures après divulgation publique. Le patching mensuel type « Patch Tuesday » est obsolète.
2. **Inflation normative européenne (NIS 2, DORA)** — obligation légale de veille active sur les
   vulnérabilités et de notification des incidents majeurs sous 24 à 72 heures.
3. **Coût prohibitif du CTI propriétaire** — Recorded Future, Mandiant Advantage, CrowdStrike Falcon
   Intelligence facturent 40 000 € à 150 000 € par an, excluant de fait les PME, ETI et
   organisations publiques régionales.
4. **Lourdeur des outils open source actuels** — OpenCTI et ses pairs exigent des clusters
   (Elasticsearch, Redis, MinIO, RabbitMQ) et 16 Go de RAM minimum au démarrage, ce qui les rend
   inutilisables en environnement contraint.

### 2.2 Problématique d'ingénierie

> Comment concevoir une plateforme de renseignement cyber robuste, légère et modulaire, capable
> d'ingérer de multiples flux hétérogènes en continu, de calculer un score de risque composite
> déterministe et d'orchestrer la réponse à incident, tout en s'exécutant avec une empreinte mémoire
> inférieure à 512 Mo et un déploiement clé en main ?

### 2.3 Besoins utilisateurs

| Réf. | Profil | Besoin |
|---|---|---|
| **BU-01** | Analyste SOC N1/N2 | Une source unique de vérité où chaque alerte est pré-enrichie de son contexte technique et de sa sévérité réelle. |
| **BU-02** | Threat Hunter / analyste CTI | Filtrer rapidement des dizaines de milliers d'indicateurs par famille d'attaque et exporter des listes de blocage (JSON / CSV / STIX). |
| **BU-03** | RSSI | Des métriques de pilotage consolidées (MTTR, MTTD) pour mesurer la vitesse de traitement et prioriser les budgets de remédiation. |
| **BU-04** | Ingénieur système / DevOps | Une image légère pilotable intégralement par API REST et CLI, intégrable en CI/CD. |

### 2.4 Étude de faisabilité

| Axe | Constat | Verdict |
|---|---|---|
| **Technique** | NVD REST 2.0, CISA KEV JSON, FIRST EPSS API et AlienVault OTX REST sont publiquement documentés et stables. L'écosystème Python offre `httpx` pour l'asynchrone non bloquant, `pydantic` pour la validation et `asyncpg`/SQLAlchemy pour la persistance. | ✅ Validé |
| **Opérationnelle** | 9 semaines, 6 phases modulaires, ~50 heures d'ingénierie nette, tâches découpées en unités de 20 à 45 minutes garantissant une progression mesurable. | ✅ Validé |
| **Économique** | Toutes les briques sont sous licence libre (MIT, BSD, Apache 2.0). Développement local sous Docker à coût nul ; production dimensionnable sur un VPS modeste. | ✅ Validé |

### 2.5 Matrice des risques pré-projet

| ID | Risque | Prob. | Impact | Gravité | Atténuation |
|---|---|---|---|---|---|
| **RSK-01** | Rate limiting sévère des API tierces (NVD) | Élevée | Élevé | **Critique** | Cache Redis local, clés API optionnelles, backoff exponentiel (`tenacity`), espacement des requêtes. |
| **RSK-02** | Indisponibilité d'un flux externe | Élevée | Moyen | Majeur | Isoler chaque collecteur dans un worker indépendant : l'échec d'un flux ne doit jamais faire tomber les autres ni l'API. |
| **RSK-03** | Explosion de la volumétrie des IOC | Moyenne | Élevé | Majeur | Cycle de vie strict des indicateurs (aging / TTL), indexation B-Tree et contrainte d'unicité pour déduplication immédiate. |
| **RSK-04** | Dérive du périmètre (scope creep) | Moyenne | Élevé | Majeur | Périmètre v1.0 gelé sur les 44 tâches planifiées. Toute idée nouvelle part au backlog v2.0. |
| **RSK-05** | Régression de code lors des itérations | Moyenne | Moyen | Modéré | Suite `pytest` bloquant tout merge via GitLab CI si le taux de succès n'est pas de 100 %. |

### 2.6 Analyse SWOAT

**Forces** — architecture légère, asynchrone, modulaire ; scoring composite exclusif à quatre
dimensions ; double interface native API + CLI ; indépendance vis-à-vis des solutions propriétaires
fermées.

**Faiblesses** — projet jeune ; dépendance à la connectivité et à la stabilité des API publiques
externes ; absence d'IHM lourde en phase 1 (choix assumé au profit de l'API et de la CLI).

**Opportunités** — NIS 2 impose la surveillance CTI ; forte demande pour des briques CTI autonomes
et transparentes déployables on-premise ; possibilité de fédérer une communauté internationale.

**Aspirations** — positionner SENTRY comme le standard open source européen de surveillance des
menaces d'ici 2030 ; démontrer une excellence technique au niveau des plus grands centres de R&D.

**Menaces** — évolution ou fermeture des points d'accès API gratuits ; concurrence d'outils massifs
mieux financés.

---

## 3. Cahier des charges fonctionnel (CdCF)

### 3.1 Les six modules métier

| Module | Périmètre |
|---|---|
| **MOD-01 Foundation** | Configuration, base SQL, authentification, CLI, migrations Alembic |
| **MOD-02 Threat Feeds** | Collecte multi-sources, normalisation, moteur IOC, déduplication, aging |
| **MOD-03 CVE Tracker** | API NVD 2.0, CISA KEV, EPSS, algorithme de risk score, moteur d'alerting |
| **MOD-04 Incidents** | Modélisation du cycle de vie, workflow à 6 états, timeline, liens IOC/CVE |
| **MOD-05 SOC Dashboard** | Synthèse des métriques, timeline d'activités, export JSON/CSV |
| **MOD-06 Threat Hunting** | Moteur de pattern-matching, règles Sigma/KQL, sessions de chasse |

### 3.2 Matrice des exigences fonctionnelles

| Réf. | Module | Exigence | Priorité |
|---|---|---|---|
| RF-01 | MOD-01 | Charger la configuration de manière immuable depuis l'environnement ou un `.env` typé. | P0 |
| RF-02 | MOD-01 | Initialiser la structure relationnelle via des migrations de schéma automatisées. | P0 |
| RF-03 | MOD-01 | Fournir une CLI d'initialisation, de peuplement (seed) et de diagnostic. | P1 |
| RF-04 | MOD-02 | CRUD complet sur les sources de flux de menaces. | P0 |
| RF-05 | MOD-02 | Collecter les flux distants de façon asynchrone sans bloquer la boucle d'événements. | P0 |
| RF-06 | MOD-02 | Parser les formats JSON, CSV et STIX 2.1. | P0 |
| RF-07 | MOD-02 | Extraire et stocker les IOC : IP v4/v6, domaines, URL, hashs MD5/SHA1/SHA256. | P0 |
| RF-08 | MOD-02 | Dédupliquer automatiquement : une valeur revue met à jour `last_seen` sans dupliquer la ligne. | P0 |
| RF-09 | MOD-02 | Exécuter un worker périodique configurable rafraîchissant les flux actifs. | P1 |
| RF-10 | MOD-02 | Intégrer nativement le connecteur AlienVault OTX via clé API. | P1 |
| RF-11 | MOD-03 | Se synchroniser avec l'API NIST NVD 2.0 (pagination, rate limit). | P0 |
| RF-12 | MOD-03 | Importer le catalogue CISA KEV et marquer les CVE activement exploitées. | P0 |
| RF-13 | MOD-03 | Importer les scores EPSS quotidiens de FIRST. | P0 |
| RF-14 | MOD-03 | Calculer un score de risque composite déterministe entre 0 et 100. | P0 |
| RF-15 | MOD-03 | Offrir une recherche et un filtrage multicritères sur les CVE. | P1 |
| RF-16 | MOD-03 | Générer une alerte dès qu'une vulnérabilité dépasse un seuil de risque prédéfini. | P1 |
| RF-17 | MOD-04 | Modéliser les incidents et leur assigner une sévérité. | P0 |
| RF-18 | MOD-04 | Implémenter une machine d'état stricte à 6 étapes. | P0 |
| RF-19 | MOD-04 | Enregistrer une chronologie immuable rattachée à chaque incident. | P0 |
| RF-20 | MOD-04 | Associer des IOC et des CVE spécifiques à un incident. | P1 |
| RF-21 | MOD-05 | Exposer `/api/v1/dashboard/summary` compilant les indicateurs clés en temps réel. | P0 |
| RF-22 | MOD-05 | Retourner la liste consolidée des menaces et vulnérabilités des dernières 24 heures. | P1 |
| RF-23 | MOD-05 | Fournir `sentry dashboard show` affichant une vue console riche de l'état du SOC. | P1 |
| RF-24 | MOD-05 | Exporter les données du dashboard aux formats JSON et CSV. | P1 |
| RF-25 | MOD-06 | Intégrer un moteur d'évaluation de règles par comparaison de motifs. | P1 |
| RF-26 | MOD-06 | Embarquer un catalogue initial de 5 règles de hunting opérationnelles. | P1 |
| RF-27 | MOD-06 | Permettre l'exécution manuelle ou planifiée d'une session de hunting. | P1 |
| RF-28 | MOD-06 | Enregistrer les résultats et correspondances d'une session de chasse. | P1 |

### 3.3 Spécification des modules

#### MOD-01 — Foundation & Configuration

Socle technique : configuration, pool de connexions PostgreSQL, migrations Alembic, CLI Click.

Commandes clés : `sentry db init`, `sentry db upgrade`, `sentry version`, `sentry seed`.

> **Règle de gestion.** Aucune requête applicative ne s'exécute si la configuration n'est pas validée
> au démarrage par Pydantic.

#### MOD-02 — Threat Feeds & moteur IOC

Formats d'IOC supportés :

| Type | Validation |
|---|---|
| `IPV4` | Regex stricte, exclusion optionnelle des plages privées RFC 1918 |
| `IPV6` | Conforme RFC 4291 |
| `DOMAIN` | FQDN pleinement qualifié |
| `URL` | URI complète incluant le schéma HTTP/HTTPS |
| `HASH_MD5` | Hexadécimal 32 caractères |
| `HASH_SHA1` | Hexadécimal 40 caractères |
| `HASH_SHA256` | Hexadécimal 64 caractères |

**Algorithme de déduplication.** À l'ingestion d'un indicateur *I = (type, value)* :

- si *I* existe déjà → `UPDATE last_seen = now(), hit_count = hit_count + 1` ;
- sinon → `INSERT first_seen = now(), last_seen = now(), hit_count = 1`.

La contrainte `UNIQUE (type, value)` est la garantie structurelle de cette règle : la déduplication
n'est pas laissée à la discipline du code applicatif.

#### MOD-03 — CVE Tracker & Vulnerability Intelligence

**Score de risque composite** — pour chaque CVE, *R* ∈ [0, 100] :

```
R = min(100, CVSS × 3.0 + EPSS × 100 × 0.25 + K × 25 + E × 10 + A × 10)
```

| Symbole | Signification | Domaine | Contribution max |
|---|---|---|---|
| CVSS | Sévérité technique brute | [0.0, 10.0] | 30 |
| EPSS | Probabilité d'exploitation réelle | [0.0, 1.0] | 25 |
| K | Présence au catalogue CISA KEV | {0, 1} | 25 |
| E | Exploit public documenté (Exploit-DB / PoC) | {0, 1} | 10 |
| A | Attaque ou campagne ransomware confirmée | {0, 1} | 10 |

**Grille de décision SOC :**

| Score | Priorité | Action |
|---|---|---|
| R ≥ 80 | **P0 — Critique** | Alerte immédiate, patch sous 24 heures |
| 60 ≤ R < 80 | **P1 — Élevé** | Alerte de quart, patch sous 7 jours |
| 40 ≤ R < 60 | **P2 — Moyen** | Revue hebdomadaire, patch sous 30 jours |
| R < 40 | **P3 — Faible** | Maintenance standard |

> **Écart documenté.** Le *Product Vision Document* v1.0 décrit une pondération différente
> (CVSS 30 % + EPSS 25 % + KEV 25 % + Exploit 10 % + Ransomware 5 % + CWE 5 %) et des seuils
> différents (70/40/20). Le présent cahier des charges fait foi pour la v1.0. Voir
> [`adr/ADR-001-scoring-composite.md`](adr/ADR-001-scoring-composite.md).

Implémentation : [`sentry/modules/cve_tracker/scoring.py`](../sentry/modules/cve_tracker/scoring.py).

#### MOD-04 — Incident Management (NIST SP 800-61 Rev. 2)

```
NOUVEAU → ANALYSE → CONFINEMENT → ERADICATION → RECUPERATION → CLOTURE
```

**Règles de transition :**

- un incident ne peut être clôturé sans note de post-mortem ou résumé de clôture renseigné ;
- chaque transition génère automatiquement un événement immuable dans `incident_events` ;
- un retour en `ANALYSE` est autorisé depuis `CONFINEMENT`, `ERADICATION` et `RECUPERATION` : une
  investigation qui rouvre des questions ne doit pas obliger à créer un nouvel incident ;
- `CLOTURE` est un état terminal.

Implémentation : [`sentry/modules/incidents/state_machine.py`](../sentry/modules/incidents/state_machine.py).

#### MOD-05 — SOC Dashboard & Analytics

Métriques temps réel : nombre total d'IOC actifs, ratio de sévérité des CVE, incidents ouverts par
criticité, santé des collecteurs. Export sérialisé en JSON conforme RFC 8259 ou CSV conforme
RFC 4180.

#### MOD-06 — Threat Hunting Engine

| Règle | Détection |
|---|---|
| **RULE-01** Tor Exit Node | Connexions ou IOC correspondant à des relais de sortie Tor connus |
| **RULE-02** Suspicious Dynamic DNS | Domaines résolus chez des fournisseurs DNS dynamique gratuits (`duckdns.org`, `no-ip.com`) |
| **RULE-03** High-Entropy Domains (DGA) | Noms de domaine générés algorithmiquement, à entropie de Shannon élevée |
| **RULE-04** Known Ransomware Extortion IP | IP associées aux infrastructures de fuite de données (DLS) |
| **RULE-05** Critical CVE + Exploit Match | Corrélation entre un actif exposé et une vulnérabilité à exploit public vérifié |

### 3.4 Cas d'usage UC-01 — Ingestion automatisée d'un flux

**Acteur primaire :** worker périodique (background scheduler)
**Préconditions :** un `ThreatFeed` est configuré avec `is_active = True`
**Déclencheur :** l'intervalle `polling_interval` est écoulé

**Scénario nominal**

1. Le worker sélectionne les flux éligibles dans `threat_feeds`.
2. Le connecteur asynchrone émet un `GET` vers l'URL du flux avec un timeout de 15 s.
3. Le serveur distant répond `200 OK` avec un payload JSON ou STIX.
4. Le parseur valide le format et extrait la liste des indicateurs bruts.
5. Le sous-système de déduplication vérifie l'existence de chaque indicateur.
6. Les nouveaux sont insérés ; les existants voient `last_seen` et `hit_count` mis à jour.
7. Le flux passe à `last_successful_run = now()`, `status = HEALTHY`.
8. Un log structuré est émis avec le nombre d'indicateurs traités.

**Scénarios alternatifs**

- *2a — erreur réseau ou timeout :* jusqu'à 3 tentatives avec backoff exponentiel ; en cas d'échec
  persistant, `status = DEGRADED` et erreur tracée.
- *3a — réponse HTTP 429 :* extraction de l'en-tête `Retry-After`, ou temporisation par défaut de
  60 s ; la collecte est reportée au cycle suivant.

---

## 4. Cahier des charges technique (CdCT)

### 4.1 Exigences non fonctionnelles

| Identifiant | Catégorie | Spécification et métrique d'acceptation |
|---|---|---|
| **RNF-SEC-01** | Sécurité | Communications externes et API chiffrées en TLS 1.3 (ou TLS 1.2 strict). Aucun secret en clair dans le code. |
| **RNF-SEC-02** | Sécurité | Entrées et paramètres strictement typés et sanitizés via Pydantic, éliminant les risques d'injection SQL et XSS. |
| **RNF-PERF-01** | Performance | Latence P95 des lectures API (`/api/v1/cves`, `/api/v1/feeds`) < 250 ms. |
| **RNF-PERF-02** | Performance | Ingestion d'un lot de 1 000 IOC en moins de 5 secondes via insertion groupée (`bulk_insert` / `upsert`). |
| **RNF-DISP-01** | Disponibilité | Taux de disponibilité minimal de 99.5 % hors maintenance programmée. |
| **RNF-MAIN-01** | Maintenabilité | Conformité 100 % au linter `ruff` et couverture `pytest` ≥ 80 %. |
| **RNF-MEM-01** | Ressources | Empreinte mémoire de l'application FastAPI en régime nominal ≤ 256 Mo. |

### 4.2 Stack technologique

| Couche | Choix | Version |
|---|---|---|
| Langage | Python (asyncio natif, typage strict) | 3.12+ |
| Framework API | FastAPI (ASGI, OpenAPI auto) | 0.115+ |
| ORM | SQLAlchemy async | 2.0 |
| Base de données | PostgreSQL | 16 |
| Pilote | asyncpg | 0.29+ |
| Migrations | Alembic | 1.13+ |
| Cache / broker | Redis | 7.2+ |
| Validation | Pydantic (cœur Rust) | 2.7+ |
| Client HTTP | httpx (HTTP/2, SOCKS) | 0.27+ |
| CLI | Click + Rich | 8.1+ / 13.7+ |
| Tests | Pytest, pytest-asyncio, pytest-cov | 8.0+ |
| Conteneurisation | Docker & Docker Compose | 26+ / v2 |

**Pourquoi Python plutôt que Node.js ou Go ?**

1. *L'écosystème CTI.* L'intégralité des standards mondiaux — STIX, TAXII, bindings YARA, parsers
   Sigma — est développée prioritairement en Python.
2. *FastAPI et Pydantic v2.* Le cœur de validation réécrit en Rust rapproche les débits de ceux de
   Go tout en conservant l'expressivité de Python.
3. *SQLAlchemy 2.0 async.* Abstraction relationnelle complète sans blocage de threads sur les accès
   disque ou réseau.

### 4.3 Architecture logicielle

```
  [CLIENTS]           CLI (Click)                 API REST (FastAPI)
                           │                              │
  [CONTROLLERS]      sentry/cli/                   sentry/app/api/
                           └──────────────┬──────────────┘
                                          ▼
  [SERVICES]                      sentry/modules/
                       (logique métier pure, calculateurs,
                         collecteurs, moteur de scoring)
                                          ▼
  [DATA ACCESS]          sentry/app/database.py · sentry/app/models/
                          (modèles SQLAlchemy, sessions async)
                                          ▼
  [PERSISTENCE]                PostgreSQL 16 · Redis
```

> **Règle d'or.** Un contrôleur d'API ne fait jamais de calcul métier ni de requête SQL complexe
> directe. Il valide les paramètres d'entrée, appelle la couche `modules/`, et retourne le schéma
> Pydantic de réponse.

### 4.4 Modèle relationnel

```sql
-- 1. Utilisateurs et analystes
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'ANALYST',   -- ADMIN, ANALYST, VIEWER
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Flux de renseignement
CREATE TABLE threat_feeds (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) UNIQUE NOT NULL,
    url VARCHAR(500) NOT NULL,
    feed_type VARCHAR(20) NOT NULL,                -- STIX, JSON, CSV
    polling_interval INTEGER NOT NULL DEFAULT 3600,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_successful_run TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING', -- PENDING, HEALTHY, DEGRADED
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. Indicateurs de compromission
CREATE TABLE indicators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    feed_id UUID REFERENCES threat_feeds(id) ON DELETE SET NULL,
    type VARCHAR(20) NOT NULL,                     -- IPV4, DOMAIN, URL, HASH_SHA256, …
    value TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    description TEXT,
    hit_count INTEGER NOT NULL DEFAULT 1,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_indicator_type_value UNIQUE (type, value)
);
CREATE INDEX idx_indicators_type_val  ON indicators (type, value);
CREATE INDEX idx_indicators_last_seen ON indicators (last_seen DESC);

-- 4. Vulnérabilités
CREATE TABLE cves (
    id VARCHAR(30) PRIMARY KEY,                    -- ex. CVE-2026-16812
    description TEXT NOT NULL,
    cvss_score NUMERIC(3, 1),
    epss_score NUMERIC(5, 4),
    is_kev BOOLEAN NOT NULL DEFAULT FALSE,
    has_public_exploit BOOLEAN NOT NULL DEFAULT FALSE,
    composite_risk_score NUMERIC(5, 2) NOT NULL DEFAULT 0.0,
    published_date TIMESTAMP WITH TIME ZONE NOT NULL,
    last_modified_date TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_cves_risk_score ON cves (composite_risk_score DESC);

-- 5. Incidents de sécurité
CREATE TABLE incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'NOUVEAU',
    assigned_to UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP WITH TIME ZONE
);

-- 6. Chronologie des incidents
CREATE TABLE incident_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    author_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL,               -- STATUS_CHANGE, COMMENT, IOC_ATTACHED, …
    message TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_incident_events_timeline ON incident_events (incident_id, created_at ASC);
```

L'implémentation SQLAlchemy vit dans [`sentry/app/models/`](../sentry/app/models/) et ajoute trois
colonnes non prévues au DDL d'origine — `cves.cvss_vector`, `cves.has_ransomware_campaign` (requise
par le facteur *A* de la formule de scoring) et `incidents.closure_summary` (requise par la règle de
clôture). Ces ajouts sont tracés dans le CHANGELOG.

### 4.5 Contrats d'interface REST

Tous les endpoints sont préfixés par `/api/v1` et échangent exclusivement du `application/json`.

| Méthode | Route | Description | Succès |
|---|---|---|---|
| `GET` | `/health` | Diagnostic de vivacité et connexion DB | 200 |
| `GET` | `/api/v1/feeds` | Liste paginée des flux configurés | 200 |
| `POST` | `/api/v1/feeds` | Enregistrement d'un nouveau flux | 201 |
| `POST` | `/api/v1/feeds/{id}/fetch` | Déclenchement manuel d'une collecte | 202 |
| `GET` | `/api/v1/indicators` | Recherche filtrée sur les IOC | 200 |
| `GET` | `/api/v1/cves` | Consultation des CVE triées par score de risque | 200 |
| `GET` | `/api/v1/cves/critical` | Extraction directe des CVE prioritaires (R ≥ 75) | 200 |
| `GET` | `/api/v1/incidents` | Liste des incidents actifs | 200 |
| `POST` | `/api/v1/incidents` | Déclaration d'un nouvel incident | 201 |
| `PATCH` | `/api/v1/incidents/{id}/status` | Transition vers un nouvel état | 200 |
| `GET` | `/api/v1/dashboard/summary` | Indicateurs consolidés du tableau de bord SOC | 200 |
| `POST` | `/api/v1/hunt/run` | Exécution d'une session de hunting | 200 |

---

## 5. Planning opérationnel

### 5.1 Macro-planning

Période globale : **30 juillet 2026 → 30 septembre 2026** (63 jours, 9 semaines).

| Phase | Jours | Fenêtre | Charge |
|---|---|---|---|
| **P1** Foundation & squelette applicatif | J01–J07 | 30/07 – 06/08 | 8 h |
| **P2** Threat Feeds & moteur IOC | J08–J21 | 06/08 – 20/08 | 12 h |
| **P3** CVE Tracker & surveillance vulnérabilités | J22–J35 | 20/08 – 03/09 | 10 h |
| **P4** Incident Management & workflow | J36–J49 | 03/09 – 17/09 | 10 h |
| **P5** SOC Dashboard & analytics | J50–J56 | 17/09 – 24/09 | 6 h |
| **P6** Threat Hunting & clôture v1.0 | J57–J63 | 24/09 – 01/10 | 5 h |

### 5.2 Jalons d'acceptation

| Jalon | Date | Critères de validation |
|---|---|---|
| **M1** Squelette opérationnel | 05/08/2026 | FastAPI démarre sous Docker ; PostgreSQL migre via Alembic sans erreur ; `/health` retourne 200 avec DB connectée ; suite de tests à 100 %. |
| **M2** Ingestion opérationnelle | 19/08/2026 | Collecteur OTX et flux STIX connectés ; déduplication fonctionnelle ; ≥ 500 indicateurs réels en base. |
| **M3** Moteur CVE & alerting | 02/09/2026 | NVD 2.0 synchronisée ; EPSS intégrés ; risk score vérifié par tests unitaires ; alerte déclenchée sur CVE critique. |
| **M4** Gestion des incidents | 16/09/2026 | Workflow testé sur les 6 états ; timeline persistée ; liaison bidirectionnelle incidents ↔ IOC/CVE validée. |
| **M5** Dashboard & reporting | 23/09/2026 | `/dashboard/summary` avec métriques exactes ; `sentry dashboard show` opérationnel ; exports JSON/CSV conformes. |
| **v1.0** 🚀 | 30/09/2026 | 6 modules intégrés ; couverture ≥ 80 % ; documentation à jour ; tag Git `v1.0.0` poussé. |

### 5.3 Découpage des 44 tâches

#### Phase 1 — Foundation (J1–J7)

| Tâche | Date | Contenu |
|---|---|---|
| T1.1 | 30/07 | Arborescence standard, `pyproject.toml`, dépendances, squelette FastAPI |
| T1.2 | 30/07 | Module `database.py`, modèle `User`, migration Alembic initiale |
| T1.3 | 31/07 | CLI Click racine (`sentry`) avec `db init`, `db upgrade`, `version` |
| T1.4 | 31/07 | `docker-compose.yml` : PostgreSQL 16 et Redis 7 avec volumes persistants |
| T1.5–1.7 | 01/08 | Isolation des répertoires modules (`threat_feeds`, `cve_tracker`, `incidents`) |
| T1.8 | 01/08 | Framework `pytest`, fixtures asynchrones, premier test sur `/health` |

#### Phase 2 — Threat Feeds (J8–J21)

| Tâche | Date | Contenu |
|---|---|---|
| T2.1 | 06/08 | Modèle `ThreatFeed` et migration |
| T2.2 | 06/08 | Contrôleurs CRUD `/api/v1/feeds` avec schémas Pydantic |
| — | 07/08 | *Activité externe :* création du compte AlienVault OTX et récupération de la clé API |
| T2.3 | 07/08 | Client HTTP asynchrone générique, parseurs JSON / CSV / STIX |
| T2.4 | 08/08 | Modèle `Indicator` et migration |
| T2.5 | 08/08 | Insertion optimisée et déduplication automatique (upsert) |
| T2.6 | 09/08 | Background task worker ordonnançant les collectes |
| T2.7 | 10/08 | CLI `sentry feeds list / add / fetch / fetch-all` |
| T2.8 | 10/08 | Tests unitaires et mocks réseau du module `threat_feeds` |
| T2.9 | 15/08 | Connecteur AlienVault OTX, extraction des pulses récents |
| T2.10 | 16/08 | Parseur STIX/TAXII |

#### Phase 3 — CVE Tracker (J22–J35)

| Tâche | Date | Contenu |
|---|---|---|
| T3.1 | 20/08 | Table `cves`, migration, injection du token NVD |
| T3.2 | 21/08 | Collecteur NVD REST 2.0 avec gestion fine du débit |
| T3.3 | 22/08 | Pipeline de normalisation (descriptions, vecteurs CVSS, métriques) |
| T3.4 | 23/08 | Moteur de recherche et filtrage multicritères |
| T3.5 | 24/08 | Endpoints `/api/v1/cves` et `/api/v1/cves/{cve_id}` |
| T3.6 | 25/08 | Fonction de risk score composite et moteur d'alertes |
| T3.7 | 26/08 | CLI `sentry cves list / search / alert` |
| T3.8 | 27/08 | Tests de précision du scoring et de tolérance aux pannes réseau |

#### Phase 4 — Incident Management (J36–J49)

| Tâche | Date | Contenu |
|---|---|---|
| T4.1 | 03/09 | Modèle `Incident` et migration |
| T4.2 | 04/09 | Table `incident_events` matérialisant la timeline |
| T4.3 | 05/09 | Machine d'état à 6 étapes avec garde-fous |
| T4.4 | 06/09 | Contrôleurs REST `/api/v1/incidents` |
| T4.5 | 07/09 | Endpoint d'enrichissement et lecture de la timeline |
| T4.6 | 08/09 | Tables de liaison incidents ↔ IOC / CVE |
| T4.7 | 09/09 | CLI `sentry incidents list / create / close` |
| T4.8 | 10/09 | Tests d'intégrité de la machine d'état et des transitions interdites |

#### Phase 5 — SOC Dashboard (J50–J56)

| Tâche | Date | Contenu |
|---|---|---|
| T5.1 | 17/09 | Service d'agrégation et endpoint `/api/v1/dashboard/summary` |
| T5.2 | 18/09 | Contrôleur d'extraction des menaces des dernières 24 heures |
| T5.3 | 19/09 | Endpoint d'historique consolidé sur 7 jours glissants |
| T5.4 | 20/09 | Tableau de bord console `rich` (`sentry dashboard show`) |
| T5.5 | 21/09 | Moteur de sérialisation et d'export JSON / CSV |
| T5.6 | 22/09 | Tests d'intégration des métriques et formats d'export |

#### Phase 6 — Threat Hunting (J57–J63)

| Tâche | Date | Contenu |
|---|---|---|
| T6.1 | 24/09 | Moteur d'évaluation de règles par pattern matching |
| T6.2 | 25/09 | Intégration des 5 règles opérationnelles |
| T6.3 | 26/09 | Routes `/api/v1/hunt/rules` et `/api/v1/hunt/run` |
| T6.4 | 27/09 | CLI `sentry hunt run / list-rules / results` |
| T6.5 | 28/09 | Tests finaux de détection et de précision des correspondances |

### 5.4 Bilan hebdomadaire du jeudi

Chaque jeudi soir, sans exception, l'avancement est compilé dans `Rapport/NN_date.md` et poussé sur
le dépôt. Le gabarit normé est fourni dans [`../Rapport/TEMPLATE.md`](../Rapport/TEMPLATE.md).

---

## 6. Guide d'onboarding développeur

Le guide pratique complet — prérequis, installation pas à pas, structure du dépôt expliquée dossier
par dossier, standards d'ingénierie, GitFlow et première tâche — vit dans un fichier dédié :
[`ONBOARDING.md`](ONBOARDING.md).

---

<div align="center">

**FIN DU CAHIER DES CHARGES SENTRY**

*« Engineering Cyber Resilience. Empowering Digital Trust. »*

</div>
