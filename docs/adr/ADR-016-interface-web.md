# ADR-016 — Interface web : React + TypeScript, temps réel par SSE, système de design v6

- **Statut :** **accepté le 08/10/2026** (décision de Godwill FOKA)
- **Date :** 2026-10-08
- **Décideurs :** Godwill FOKA
- **Concerne :** ARCHITECTURE (« Pas d'IHM web » en v1.0, levé ici), Product Vision tome 6
  (Bootstrap + Chart.js, remplacé), M7 (préproduction reportée après l'interface)

## Contexte

ILLWATCH n'a qu'une API REST et une CLI. Le 08/10, il a été décidé que l'hébergement de
préproduction attendrait une interface graphique. Exigences exprimées : une interface
**dynamique et asynchrone** (mises à jour sans rechargement), capable de suivre les évolutions de
la plateforme, d'aspect professionnel et propre à CYBERILLSEC.

Six itérations de maquette ont été faites (canevas « ILLWATCH — Maquette v6 (système de design) »).
La v6, adoptée, retient une console SOC « premium et sobre » : hiérarchie en trois niveaux
(à traiter, situation, contexte), une seule échelle de priorité P0–P3, tableaux et panneaux de
détail uniformes, mouvement discret.

## Décision

1. **Technologie** : React + TypeScript, construit par Vite ; données par **TanStack Query** ;
   temps réel par **Server-Sent Events** (`GET /api/v1/stream`) ; types TypeScript **générés depuis
   le schéma OpenAPI** de FastAPI ; graphiques ECharts. L'interface est compilée dans l'image Docker
   et servie par FastAPI (même origine, même conteneur).
2. **Système de design v6** (référence : `docs/DESIGN_SYSTEM.md`) : fond `#0A0E1A`, panneaux
   `#121A2B`, indigo `#20155C` (structure, sélection), orange `#E6681B` (action principale, une par
   vue), rouge réservé au critique ; Inter et JetBrains Mono ; espacements 4/8/12/16/24/32.
3. **Navigation** : Vue d'ensemble · Opérations SOC (Triage, Incidents) · Renseignement (IOC,
   Sources) · Vulnérabilités (CVE) · Chasse · Administration séparée.
4. **Honnêteté de l'affichage** : l'interface n'affiche que ce que le serveur fournit ; une donnée
   datée est marquée comme telle ; une action « déclarée » par un analyste n'est jamais présentée
   comme exécutée par ILLWATCH.

## Justification

- **React + TypeScript** plutôt que Bootstrap + Chart.js (Product Vision) ou HTMX : l'interface
  demandée est très interactive (sélection, panneaux, filtres, temps réel) ; TypeScript plus la
  génération des types depuis OpenAPI fait échouer la compilation quand l'API change, au lieu de
  casser l'écran en silence. Coût : une chaîne Node en CI et dans l'image.
- **SSE** plutôt que WebSocket : le flux est descendant (serveur → navigateur) ; SSE passe par HTTP
  standard, derrière Caddy, avec reconnexion native. Les actions restent des requêtes REST.
- **Même origine** : pas de CORS en production, jetons sur le même domaine, un seul conteneur.
- **Design v6** plutôt que v4/v5 (plus « spectaculaires ») : un analyste lit l'écran des heures ;
  pulsations, halos et cartes d'attaques sans données réelles nuisent à la lecture et à la confiance.

## Conséquences

- Positives : interface réactive, typée de bout en bout ; évolutions de l'API détectées à la
  compilation ; une identité visuelle stable et documentée.
- Négatives : deuxième langage et deuxième chaîne de construction (Node) ; image Docker plus longue
  à construire ; compétences front à entretenir ; la préproduction (fin de M7) est décalée d'autant.
- Le flux SSE doit respecter les rôles : un VIEWER ne reçoit que ce qu'il peut lire.

## Suivi

| Lot | Contenu | Jalon |
|---|---|---|
| 1 | Socle `frontend/` (Vite, TS, TanStack Query, génération OpenAPI), connexion, Vue d'ensemble, Triage (alertes CVE), IOC, CVE, Incidents, Investigation, Chasse ; côté serveur : flux SSE, séries temporelles, journal de collecte | M7 |
| 2 | Comptes, paramètres modifiables, profil, double authentification (TOTP), écran mural | M7–M9 |
| 3 | Alertes de chasse dans le triage, score de confiance des IOC, géolocalisation, graphe de relations | M8 |
| 4 | Faux positifs, niveaux L1/L2/L3, tâches d'incident, délais mesurés | M9 |
| 5 | ATT&CK, inventaire d'actifs et exposition | M10 |
