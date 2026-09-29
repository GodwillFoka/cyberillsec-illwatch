# 🛡️ SENTRY — Bilan : clôture de M2 et phase 3 (moteur CVE)

**Date :** 29/09/2026 · **Base :** votre commit `87bcca6` (branche `security/feed-last-error`)
**Branches livrées :** `feature/sprint3-m2` (`9402bb1`) puis `feature/phase3-cve`
**Rédaction :** Claude (Cowork), pour Godwill FOKA

---

## 1. Verdict

| Jalon | Code | Constat sur données | Ce qui reste |
|---|---|---|---|
| **M2** Ingestion opérationnelle | ✅ complet | ⏳ à faire chez vous | `sentry seed`, `fetch-all`, clé OTX |
| **M3** Moteur CVE & alerting | ✅ complet | ⏳ à faire chez vous | `sentry cves sync` (clé NVD conseillée) |

Votre lecture de l'état « M2 non atteint » était juste : les critères portent sur des données
réelles, pas sur le code. Deux choses empêchaient pourtant M2 d'être atteignable, et elles
relèvent bien du code :

1. **Le seed ne proposait que 2 sources**, dont une exigeant une clé : le critère « ≥ 3 sources
   saines » était inatteignable sans configuration manuelle.
2. **Un défaut d'analyse CSV** aurait rejeté 100 % d'une source réelle (C2IntelFeeds, voir §5).

Les deux sont corrigés. Sans aucune inscription, `sentry seed && sentry feeds fetch-all` doit
maintenant cocher 3 des 4 critères M2 ; seul « OTX connecté » demande la clé gratuite
(inscription de 5 minutes).

## 2. Ce que je n'ai pas pu vérifier

Mon environnement n'a pas accès au réseau des sources (NVD, CISA, FIRST, abuse.ch, DigitalSide,
OTX : connexion refusée par le proxy ; seul GitHub répond). Conséquences :

- les formats **C2IntelFeeds** et **DigitalSide (liste d'URL)** sont vérifiés sur les fichiers
  réels (téléchargés depuis GitHub) ; **Feodo** sur un extrait réel de 2026 ;
- les formats **NVD 2.0, KEV, EPSS, TAXII DigitalSide et OTX** sont vérifiés sur des fixtures
  conformes à leur documentation publique, pas sur une réponse réelle. Confiance : élevée pour
  KEV et EPSS (formats stables et simples), bonne pour NVD, moyenne pour le serveur TAXII
  DigitalSide (disponibilité et contenu non vérifiables d'ici) ;
- le paramètre NVD `hasKev` est envoyé sans valeur, comme le prévoit la documentation du NVD.
  S'il était refusé, la synchronisation continue (repli testé) et les CVE KEV sont créées
  depuis le catalogue CISA.

**Le premier `sentry cves sync` et le premier `sentry feeds fetch-all` chez vous sont donc le
vrai test d'intégration.** Envoyez-moi leur sortie en cas d'échec d'une source.

## 3. Livrables

### 3.1 Clôture M2 (`feature/sprint3-m2`)

| Tâche | Contenu |
|---|---|
| Rebase | Sprint 3 rejoué sur votre `87bcca6` (arbre de `25adf77` identique à `202c6aa`, vérifié) |
| 1.8 TAXII 2.1 | Format `TAXII`, pagination `more`/`next`, `added_after`, identifiants par hôte (`TAXII_AUTH`), jamais envoyés à un autre hôte |
| Sources sans clé | C2IntelFeeds IP et domaines (30 j), DigitalSide URL (7 j), DigitalSide TAXII IoC réseau (STIX 2.1) |
| Correctif CSV | Colonne IOC choisie sur le contenu (§5) |
| Garde-fou | Test : chaque URL du seed passe les règles SSRF de l'API |

### 3.2 Phase 3 — moteur CVE (`feature/phase3-cve`)

| Tâche | Contenu |
|---|---|
| 2.1 NVD 2.0 | KEV complet + CVE modifiées depuis 30 j, puis incrémental ; pages de 500 ; 6 s / 0,6 s entre requêtes ; curseur en base |
| 2.2 KEV + EPSS | Ransomware, échéance, action requise ; retraits du catalogue appliqués ; EPSS score + percentile |
| 2.3 Recalcul | Score et priorité recalculés à chaque changement ; historique `cve_priority_history` |
| 2.4 API | `/api/v1/cves` (tri par risque, 5 filtres), `/api/v1/cves/{id}` (décomposition, historique) |
| 2.5 Alerting | Franchissement du seuil 75, ligne de base sans alerte, `/api/v1/alerts`, acquittement, webhook 5 tentatives |
| 2.6 CLI | `sentry cves sync / list / show / alerts` ; synchro automatique par le worker toutes les 6 h |
| Mesure | `sentry status` affiche les 4 critères M3 |

## 4. Métriques

| Indicateur | `87bcca6` (votre base) | Aujourd'hui |
|---|---|---|
| Tests PostgreSQL 16 (3.12 et 3.14) | 256 | **326**, 0 échec |
| Couverture | 95 % | **≈ 95 %** |
| Routes `/api/v1` | 10 | **14** |
| Commandes CLI | 14 | **19** |
| Migrations | 2 | **4** (montée, `alembic check`, descente, remontée vérifiées) |
| ADR | 5 | **7** |

**Performance (PostgreSQL local, 30 000 CVE synthétiques)** : liste des CVE P95 = 8 ms (sans
filtre), 3 ms (P0), 108 ms (recherche texte). Cible RNF-PERF-01 : 250 ms.
**Données réelles** : la liste DigitalSide (36 995 URL) s'ingère en 24 s, 0 rejet. Pic mémoire
du processus : 120 Mo (cible ≤ 256 Mo).

## 5. Défauts

| Défaut | Gravité | État |
|---|---|---|
| CSV : colonne choisie par son nom seul. C2IntelFeeds publie `#ip,ioc` où `ioc` est un libellé (« Possible Cobaltstrike C2 IP ») : 265 lignes sur 265 rejetées | **Majeure** (source réelle inexploitable) | ✅ choix sur le contenu, libellé repris en description |
| Seed : 2 sources dont 1 à clé → critère M2 « 3 sources » inatteignable | Majeure | ✅ 7 sources, 5 sans clé |
| Masquage de secrets : un mot de passe court (`guest`) aurait masqué ce mot partout | Mineure | ✅ secrets < 8 caractères non masqués |
| URL de requête limitée à 500 caractères (colonne en base) : lots EPSS impossibles | Majeure pour M3 | ✅ 4 000 pour les URL non stockées |

**Connus, non bloquants** : copie GitHub de DigitalSide figée depuis 2024 (le seed utilise
l'URL officielle `osint.digitalside.it`) ; Feodo Tracker ne publie que quelques IP ; CVSS v4.0
et v3.1 mélangés faute d'évaluation NVD complète (ADR-007) ; recherche texte sans index au-delà
de 100 000 CVE.

## 6. SWOAT

| | |
|---|---|
| **Forces** | Deux jalons codés en une passe ; score entièrement justifiable (décomposition + historique) ; alerting qui ne noie pas l'astreinte ; performance très en deçà des cibles |
| **Faiblesses** | Aucune synchronisation réelle faite ; dépendance à des sources gratuites dont la disponibilité varie (DigitalSide, Feodo quasi vide) |
| **Opportunités** | Rapprocher CVE et IOC (pulses OTX citant des CVE) pour le signal « attaque » ; score de confiance IOC par provenance |
| **Menaces** | Changements de conditions des API (NVD a déjà réduit ses débits, abuse.ch a imposé une clé) |
| **Axes d'action** | Pousser, créer les clés NVD et OTX, lancer le worker 24 h, constater M2 et M3 |

## 7. Décisions attendues

- Accepter ou amender **ADR-004** (planning), **ADR-005** (cycle de vie IOC), **ADR-006**
  (provenance, OTX, worker), **ADR-007** (moteur CVE, ligne de base des alertes, seuil 75).
- Choisir le canal d'alerte (webhook Slack / Mattermost / Teams via passerelle).

## 8. Étape suivante — phase 4 : incidents (M4, cible 05/11/2026)

API des incidents sur la machine d'état existante (NIST SP 800-61), chronologie immuable,
liaison incident ↔ IOC et incident ↔ CVE, création d'un incident depuis une alerte CVE. Les
alertes de cette phase en sont la porte d'entrée naturelle.
