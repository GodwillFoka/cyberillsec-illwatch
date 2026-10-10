# Interface web d'ILLWATCH

React + TypeScript (Vite), données par TanStack Query, temps réel par Server-Sent Events
(`GET /api/v1/stream`). Décision : [ADR-016](../docs/adr/ADR-016-interface-web.md) ; apparence :
[système de design v6](../docs/DESIGN_SYSTEM.md).

## Développer (poste Kali)

Prérequis : Node.js 20 ou plus (`node --version`), l'API ILLWATCH lancée sur le port 8000.

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
à la racine du site, l'API restant sous `/api/v1`. Sans image, `npm run build` produit
`frontend/dist/`, servi automatiquement par `uvicorn` s'il existe (ou `WEB_DIR=/chemin`).

## Organisation

| Dossier | Rôle |
|---|---|
| `src/api/` | client HTTP (jeton, renouvellement), requêtes partagées, types générés |
| `src/auth/` | session : connexion, renouvellement anticipé, déconnexion |
| `src/realtime/` | flux SSE : analyse, reconnexion, pause, relecture des données concernées |
| `src/layout/` | menu latéral, barre supérieure (direct, pause, UTC/local) |
| `src/components/` | carte indicateur, badges P0–P3, graphique, états de chargement |
| `src/pages/` | écrans (vue d'ensemble ; les autres arrivent au fil du lot 1) |

Règles : aucun type d'échange écrit à la main (`src/api/types.ts` ne fait que nommer les types
générés) ; une donnée absente s'affiche « — », jamais une valeur inventée ; pas de script ni de
style en ligne (politique de sécurité `script-src 'self'; style-src 'self'`).
