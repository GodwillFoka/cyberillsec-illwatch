# ILLWATCH — Audit global du 10/10/2026

**Périmètre :** dépôt complet sur `main` @ `56f12db` (API, worker, CLI, interface web, migrations,
CI GitHub et GitLab, documentation, suivi de projet). **Méthode :** revue indépendante (agent
n'ayant pas écrit le code, lecture seule), puis corrections vérifiées par la CI.
**Corrections fusionnées :** PR #10 (`9a06937`), politique Dependabot (PR #18), typage (PR #20),
mises à jour mineures (#13, #15, #19). `main` @ `12fbe41` : CI et publication vertes.

## 1. Synthèse

| | |
|---|---|
| Santé générale | **bonne** : CI verte sur toutes les plateformes, aucun secret versionné, chaîne de 10 migrations linéaire avec descentes, toutes les routes `/api/v1` authentifiées (sauf `/auth/*`, publiques à dessein), droits d'écriture ADMIN/ANALYST vérifiés, protection SSRF solide |
| Constats | 1 élevé, 6 moyens, 7 faibles, 3 informatifs |
| Corrigés | l'élevé, les 6 moyens, 5 faibles, les 3 informatifs |
| Restent ouverts | 2 faibles (ci-dessous), suppression des branches fusionnées (droits) |

## 2. Constats et suite donnée

| Gravité | Constat | Suite |
|---|---|---|
| **Élevé** | `tests/test_hunting.py` : données datées du 03/10 interrogées par l'API à l'heure réelle ; l'IOC expire après 30 j → la CI aurait échoué à partir du **02/11/2026** | ✅ données relatives à l'horloge réelle ; recherche des autres tests du même type : aucun |
| Moyen | Bus temps réel : écoute Redis perdue définitivement après une coupure ; bus local définitif si Redis absent au démarrage ; l'interface affichait « en direct » sans rien recevoir | ✅ reconnexion automatique (1 → 30 s) avec demande de relecture, publication locale pendant la panne ; 2 tests |
| Moyen | Onglet dupliqué : deux onglets présentent le même jeton de rafraîchissement → le serveur révoque toute la session (faux « rejeu ») | ✅ diffusion des nouveaux jetons entre onglets et verrou de renouvellement |
| Moyen | Double collecte possible : `feeds fetch` rendait le verrou avant le commit ; le worker ne relisait pas l'échéance sous verrou | ✅ commit avant libération ; échéance relue sous verrou |
| Moyen | Infobulle ECharts dépouillée par la politique `style-src 'self'` | ✅ infobulle en classes CSS |
| Moyen | Caddy : compression devant le flux SSE (trames retenues en préproduction) | ✅ flux exclu de la compression, sans tampon (à constater sur le VPS) |
| Faible | Durée du flux SSE comptée depuis la connexion, pas depuis l'expiration du jeton | ✅ bornée à l'expiration réelle |
| Faible | Événements des commandes CLI perdus à la sortie | ✅ publiés avant la sortie (`flush_events`) |
| Faible | Fenêtre de calcul du retrait (7 j) relue à chaque cycle | ✅ ramenée à 2 j |
| Faible | Détail d'une CVE non relu après une alerte | ✅ relu |
| Faible | `aria-selected` sur des lignes de tableau simple | ✅ `aria-current` |
| Faible | `Retry-After` d'une réponse 429 ignoré (retrait à 1 min) | ⏳ ouvert — à traiter avec le lot « sources » (M8) |
| Faible | Événement déduit dans un point de sauvegarde annulé, non oublié | ⏳ ouvert — impact nul en pratique (l'interface relit), à reprendre si un cas réel apparaît |
| Info | GitLab (référence) ne contrôlait pas l'interface | ✅ jobs `openapi` et `interface`, image vérifiée servant l'interface |
| Info | Repli `npm install` si le verrouillage manque ; artefact obsolète | ✅ `npm ci` obligatoire (CI et image) |
| Info | npm non suivi par Dependabot | ✅ suivi ; mineures regroupées, majeures planifiées à la main |

Points vérifiés sans défaut : service de l'interface (aucun parcours de chemin), routage interne
(aucune redirection ouverte), aucun `text()` SQL construit avec une donnée utilisateur, aucun
datetime naïf, filtrage SSE par rôle cohérent, modèle et migration `collection_runs` concordants.

## 3. Documentation

Mise en cohérence avec l'ADR-016 (l'interface passe avant l'hébergement) : README (chiffres,
interface, arborescence), feuille de route (ligne « Interface » de M7), état d'avancement
(contradiction « reste uniquement le VPS » levée), ONBOARDING (`illwatch db upgrade`),
architecture, design system (couleurs `warning` et `grid`), addendum à l'ADR-016 (routage
interne, `node --test`, audit npm, coordination des onglets).

## 4. Dépôts et CI

- GitHub `main` : CI, Documentation, Publication verts. Aucune PR humaine ouverte.
- **Branches fusionnées à supprimer** (droits d'écriture refusés depuis la session) :
  `chore/dev-audit`, `feature/m7-ui-frontend`, `feature/m7-ui-incidents`,
  `feature/m7-ui-lot1-api`, `feature/m7-ui-triage`, `fix/audit-2026-10-10`,
  `fix/collect-backoff`, `fix/collection-journal-resilience`, `fix/web-dev-deps`,
  `fix/web-tests-portable`, `rename/illwatch`. `release/v0.1.1` est conservée (maintenance).
- Dependabot (premier passage npm) : #13 (police) et #15 (`setup-node` 7) fusionnées ; les
  mineures regroupées en #19 (TypeScript 5.9, TanStack Query 5.104, openapi-typescript 7.13,
  `@types/node` 22.20, police Inter) fusionnées après correction d'un typage révélé par
  TypeScript 5.9 (#20). Majeures fermées avec explication : React 19 (#17, CI rouge),
  `@vitejs/plugin-react` 6 (#12, CI rouge), image Node 25 non LTS (#11), `@types/node` 26 (#16).
  Migration React 19 + Vite 8 à planifier après le lot 1. **Aucune PR ouverte.**
- GitLab : pipeline non consultable depuis la session (connecteur non autorisé) ; à vérifier
  au prochain `git push gitlab main` (nouveaux jobs `openapi` et `interface`).

## 5. Jalon M7

| Fait | Reste |
|---|---|
| Lots 1 à 3 de durcissement ; interface : socle, temps réel, vue d'ensemble, triage, incidents et investigation | Écrans IOC, CVE, chasse ; préproduction VPS UE (SSL Labs ≥ A, 7 jours de collecte, SSE derrière Caddy) |
