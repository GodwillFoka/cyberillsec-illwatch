# Interface web d'ILL Watch

React + TypeScript (Vite), données par TanStack Query, temps réel par Server-Sent Events
(`GET /api/v1/stream`). Décision : [ADR-016](../docs/adr/ADR-016-interface-web.md) ; apparence :
[système de design v6](../docs/DESIGN_SYSTEM.md).

## Développer (poste Kali)

Prérequis : Node.js 20 ou plus (`node --version`), l'API ILL Watch lancée sur le port 8000.

```bash
cd ~/Documents/cyberillsec-illwatch && source .venv/bin/activate
uvicorn illwatch.app.main:app --port 8000          # terminal 1 : l'API
illwatch openapi -o frontend/openapi.json          # schéma de l'API (à refaire si l'API change)
cd frontend
npm ci                                             # versions exactes de package-lock.json
npm run gen:api                                    # types TypeScript générés depuis l'API
npm run dev                                        # http://localhost:5173
```

Vite relaie `/api` vers `localhost:8000` : le navigateur ne voit qu'une origine, comme en
production. Une modification du code s'affiche sans recharger la page.

Contrôles (les mêmes qu'en CI) : `npm run typecheck`, `npm test`, `npm run build`.

## Production

L'image Docker compile l'interface (étape Node) et la copie dans `/app/web` ; FastAPI la sert
à la racine du site, l'API restant sous `/api/v1`. Sans image, `./scripts/build-web.sh`
(à la racine) produit `frontend/dist/`, servi automatiquement par `uvicorn` s'il existe (ou
`WEB_DIR=/chemin`). Il régénère d'abord le schéma OpenAPI et les types : `npm run build` seul,
après un changement de l'API, compile avec l'ancien schéma et échoue (`TS2339`).

## Langues (ADR-027)

L'interface parle **français, anglais, allemand, espagnol et chinois simplifié**. À l'ouverture,
la langue est celle choisie dans ce navigateur (sélecteur de l'écran de connexion et de la
barre supérieure) ; sinon celle que décide l'API (`GET /api/v1/locale` : pays de l'adresse IP,
ou pays de l'instance `INSTANCE_COUNTRY` sur un réseau interne, le navigateur départageant
les pays bilingues) ; sinon la langue du navigateur ; sinon l'anglais.

- Chaque écran déclare ses textes dans un fichier voisin `*.i18n.ts`, les cinq langues côte
  à côte (`defineMessages`, `src/i18n/core.ts`). **Une clé absente ou en trop dans une langue
  est une erreur de compilation.** Les textes partagés sont dans `src/i18n/common.i18n.ts`,
  `src/lib/labels.i18n.ts` (niveaux, statuts, unités, journal d'audit) et
  `src/components/components.i18n.ts`.
- Pluriels : clés `x_one` / `x_other` et `t.plural("x", n)` (règles `Intl.PluralRules` : le
  français met 0 au singulier). Variables `{nom}` ; un nombre est formaté selon la langue.
- Nombres, dates courtes, durées et pays suivent la langue (`Intl`) ; l'heure reste sur 24 h.
- Changer de langue remonte l'application sous la session : on reste connecté, le cache des
  requêtes est conservé.
- Les contenus produits par le serveur (titres d'incident, descriptions de règles,
  recommandations, messages d'erreur détaillés de l'API) restent dans la langue où ils ont été
  écrits.

Ajouter une langue : l'ajouter à `LANGS` (`src/i18n/core.ts`), puis compiler : TypeScript
liste chaque fichier `*.i18n.ts` à compléter.

## Organisation

| Dossier | Rôle |
|---|---|
| `src/api/` | client HTTP (jeton, renouvellement), requêtes partagées, types générés |
| `src/auth/` | session : connexion, renouvellement anticipé, déconnexion |
| `src/realtime/` | flux SSE : analyse, reconnexion, pause, relecture des données concernées |
| `src/layout/` | menu latéral, barre supérieure (direct, pause, UTC/local) |
| `src/components/` | carte indicateur, badges P0–P3, graphique, états de chargement, pagination, association à un incident, score de CVE |
| `src/pages/` | écrans du lot 1 : vue d'ensemble, triage, incidents (et investigation), indicateurs, CVE, chasse |

Règles : aucun type d'échange écrit à la main (`src/api/types.ts` ne fait que nommer les types
générés) ; une donnée absente s'affiche « — », jamais une valeur inventée ; pas de script ni de
style en ligne (politique de sécurité `script-src 'self'; style-src 'self'`).
