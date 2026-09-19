# SENTRY — Product Vision Document

> **Conversion Markdown versionnable** du document
> `CYBERILL-SENTRY — Product Vision Document v1.0` (Godwill FOKA, Berlin, juillet 2026).
> Le PDF d'origine est conservé dans [`pdf/CYBERILL-SENTRY-PRODUCT-VISION_3.pdf`](pdf/CYBERILL-SENTRY-PRODUCT-VISION_3.pdf).
>
> Ce document porte la **vision produit et stratégique**. Pour les spécifications opposables au
> développement, c'est le [Cahier des charges](CAHIER_DES_CHARGES.md) qui fait foi — il est le seul
> document marqué « approuvé pour développement ».

---

## Tome 1 — Vision & stratégie

### CYBERILL

CYBERILL est né d'une conviction : la cybersécurité n'est pas un luxe mais une nécessité. Fondé par
Godwill FOKA, Cybersecurity Engineer à Berlin, CYBERILL rassemble six domaines fonctionnant en
synergie — CyberillSec alimente les autres branches en renseignements, Cyberill Labs enrichit
CyberillSec par ses recherches, et chaque projet renforce les autres.

| Projet | Domaine | Description |
|---|---|---|
| CyberillSec / SENTRY | Threat Intelligence | Plateforme de veille CTI |
| Cyberill Labs | Recherche | Analyse de malware, pentest |
| Cyberill Academy | Formation | Certifications, workshops |
| Cyberill Consulting | Conseil | GRC, audit, advisory |
| Cyberill CERT | Réponse à incident | DFIR, gestion de crise |
| Cyberill Cloud | Cloud | Plateformes SaaS sécurisées |

### Les six valeurs

Innovation · Excellence · Transparence · Souveraineté · Collaboration · Éthique

### CyberillSec

Face à un paysage de menace professionnalisé — 1 655 CVE au catalogue KEV, 858 techniques MITRE
ATT&CK, RaaS en expansion — CyberillSec collecte, corrèle et analyse le renseignement pour anticiper
les attaques. SENTRY en est le moteur technologique.

**Cinq problèmes majeurs** : surcharge informationnelle, fragmentation des outils, coût (> 50 k€/an
pour Recorded Future), manque de contexte, dépendance américaine.

**La réponse SENTRY** : 100 % open source, scoring composite CVE + EPSS + KEV, dashboard SOC natif,
hébergement européen.

---

## Tome 2 — Étude de marché

| Indicateur | Valeur |
|---|---|
| Marché CTI mondial 2026 | 18,5 Mds $ |
| CAGR | 16,2 % |
| Marché européen | 4,2 Mds $ |
| Marché africain | 280 M$ |
| Solutions recensées | 200+ |

### Analyse concurrentielle

| Critère | CrowdStrike | Recorded Future | MISP | OpenCTI | **SENTRY** |
|---|---|---|---|---|---|
| Open source | Non | Non | AGPL | Apache | **MIT** |
| Dashboard | Oui | Partiel | Non | Non | **Natif** |
| Scoring | Oui | Oui | Non | Non | **Composite** |
| Prix / an | 50–100 k$ | 30–200 k$ | 0 $ | 0 $ | **0 $ (CE)** |
| Hébergement UE | Non | Non | Oui | Oui | **Oui** |

---

## Tome 3 — Architecture fonctionnelle

### Pipeline de Threat Intelligence

```
Réception → Normalisation → Enrichissement → Scoring → Alerting → Archivage
```

**Sources intégrées :** CISA KEV (1 655 CVE), NIST NVD (230 k CVE), FIRST EPSS (353 k scores),
AlienVault OTX, GreyNoise, MITRE ATT&CK (858 techniques), TheHackerNews, BleepingComputer, CERT-FR,
BSI.

### Algorithme de scoring composite (vision)

CVSS 30 % + EPSS 25 % + KEV 25 % + Exploit 10 % + Ransomware 5 % + CWE 5 %.
Seuils : 0–20 faible · 20–40 moyen · 40–70 élevé · 70–100 critique.

> ⚠️ **Écart avec le cahier des charges.** Le CdC v1.0.0 retient une pondération différente
> (Ransomware 10 %, pas de facteur CWE) et des seuils différents (80/60/40). Le CdC fait foi pour
> l'implémentation v1.0 ; l'écart et sa résolution sont tracés dans
> [`adr/ADR-001-scoring-composite.md`](adr/ADR-001-scoring-composite.md).

### Modules complémentaires

**IOC Management** — base centralisée (IP, domaine, URL, hash, e-mail, certificat) avec cycle de vie
`New → Active → Aged → Expired` et enrichissement automatique.

**Incident Response** — workflow NIST SP 800-61 Rev. 2, 5 playbooks (ransomware, phishing, DDoS,
malware, data breach), génération de rapports PDF.

**SOC Dashboard** — 15 widgets temps réel, KPI (MTTR, MTTD), cartographie mondiale, heatmap.

**AI Assistant (phase 6)** — LLM (Llama 3 / Mistral) + RAG pour résumé automatique, analyse d'IOC et
génération de rapports.

---

## Tome 4 — Cahier des charges général

| Aspect | Valeur |
|---|---|
| Langage | Python 3.12+ / FastAPI |
| Licence | MIT |
| Performance | < 2 s pour 95 % des requêtes |
| Disponibilité | 99 % (P1) → 99,9 % (P7) |
| Sécurité | OWASP Top 10, TLS 1.3, CSP |
| Tests | Couverture ≥ 80 % |

---

## Tome 5 — Cahier des charges fonctionnel

**F-THR-001 — Gestion des menaces.** Entrées : données brutes des collecteurs. Sorties : menace
normalisée et scorée. Critères d'acceptation : normalisation uniforme, alerte si score ≥ 70,
recherche < 500 ms.

**F-CVE-001 — Gestion des CVE.** Réception NVD → enrichissement EPSS/KEV → scoring → actions
(critique : immédiat ; élevé : quotidien).

**F-IR-001 — Gestion des incidents.** Création → analyse → containment → éradication → restauration
→ post-mortem. 5 playbooks, rapport PDF automatique.

---

## Tome 6 — Cahier des charges technique

| Couche | Technologie |
|---|---|
| Backend | Python 3.12+ / FastAPI |
| CLI | Click 8.1+ |
| Validation | Pydantic v2 |
| Frontend | Bootstrap 5.3 + Chart.js |
| Base de données | SQLite → PostgreSQL 16+ |
| Cache | Redis 7+ |
| Conteneurs | Docker |

**API REST** : 27+ endpoints, pagination systématique, versioning `/api/v1/`, Swagger, rate limiting,
JWT à partir de la phase 4.

**Sécurité** : TLS 1.3, CSP strict, OWASP Top 10, audit logging, chiffrement au repos.

---

## Tome 7 — Architecture technique

Architecture en couches : Sources → Collecteurs (8+) → Normalisation et enrichissement → Stockage
(SQLite/PostgreSQL + JSON) → API FastAPI → Sorties (dashboard, CLI, Telegram, e-mail).

La phase 1 reste monolithique. La migration vers des microservices est prévue en phase 7, quand le
volume dépassera 100 000 événements par jour.

---

## Tome 8 — Roadmap

| Phase | Durée | Livrable |
|---|---|---|
| P0 Foundation | S1 | Structure + CLI + CI/CD |
| P1 Threat Feeds | S2–3 | 8 collecteurs + API + dashboard |
| P2 Vuln Intel | S4–5 | CVE + EPSS + KEV + bulletins |
| P3 Incident Response | S6–7 | Playbooks + timeline + rapports |
| P4 SOC Dashboard | S8–9 | KPI + graphiques + cartes |
| P5 Hunting | S10–13 | Sigma + YARA + ATT&CK |
| P6 AI | S14–17 | LLM + RAG + résumé automatique |
| P7 Enterprise | S18–21 | Multi-tenant + SSO |
| P8 Cloud | S22–25+ | Cyberill TI Cloud |

---

## Tome 9 — Gestion de projet

Scrum en sprints de deux semaines, GitHub Projects, GitFlow. Équipe cible phase 1 : PO / lead dev
seul. Équipe cible phase 7 : 15 à 20 personnes.

Risques identifiés : abandon (atténué par la communauté), burn-out (atténué par un rythme durable),
concurrence (atténuée par la différenciation open source).

---

## Tome 10 — Communication & marketing

Identité visuelle : Indigo `#20155C` + Orange `#E6681B`, logo bouclier « S », typographie Inter.
Canaux : GitHub (continu), LinkedIn (2–3 par semaine), blog (1 par semaine), Discord, Telegram.

---

## Tome 11 — Open source

Licence MIT (permissive). Code of Conduct : Contributor Covenant v2.1. Standards : Ruff (PEP 8),
mypy strict, Conventional Commits, couverture ≥ 80 %.

Workflow contributeur : Fork → Branch → Code → Test → Commit → PR → Review → Merge.

---

## Tome 12 — Vision 2035

> En 2035, CyberillSec sera la plateforme européenne de référence en CTI.

| Domaine | Vision 2035 |
|---|---|
| Produit | Cyberill TI Cloud SaaS |
| Communauté | 100 k+ utilisateurs, 5 k+ contributeurs |
| Couverture | Europe + Afrique |
| Équipe | 100+ personnes |
| Revenus | 20 M€+ / an |
| Reconnaissance | Partenaire ENISA, FIRST, CERT-EU |

**Quatre scénarios :** European Champion (60 %) — leader CTI européen ; Africa Bridge (25 %) — pont
Europe-Afrique ; The Platform (10 %) — multi-produits ; The Niche (5 %) — projet maintenu.

---

<div align="center">

**Construisons ensemble l'alternative européenne en Cyber Threat Intelligence.**

*Godwill FOKA — Cybersecurity Engineer, Initiator @ CYBERILL · Berlin, juillet 2026*

</div>
