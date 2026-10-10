"""Service de l'interface web compilée — ADR-016 (même origine, même conteneur que l'API).

- `/assets/*` : fichiers produits par Vite, nommés d'après leur contenu (`index-3f2a1c.js`) :
  mis en cache un an, immuables.
- toute autre adresse hors API (`/`, `/incidents/42`…) renvoie `index.html`, jamais mis en
  cache : c'est l'application React qui interprète l'adresse (routage côté navigateur).
- `/api/*`, `/health`, `/ready`, `/docs`… gardent leur comportement : une route d'API inconnue
  répond toujours 404 en JSON, jamais par la page de l'interface.

Politique de sécurité du contenu de la page : tout depuis la même origine, aucun script en
ligne, aucune ressource externe (polices et graphiques sont dans le paquet compilé).
"""

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import FileResponse
from starlette.responses import Response
from starlette.staticfiles import StaticFiles
from starlette.types import Scope

from illwatch.app.config import Settings

_REPO_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"

UI_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; "
    "form-action 'self'; frame-ancestors 'none'"
)
_PUBLIC_CACHE = {"Cache-Control": "public, max-age=3600"}
_RESERVED_PREFIXES = ("/api/", "/docs", "/redoc", "/openapi.json", "/health", "/ready", "/assets/")


class _ImmutableAssets(StaticFiles):
    async def get_response(self, path: str, scope: Scope) -> Response:
        response = await super().get_response(path, scope)
        if response.status_code == status.HTTP_200_OK:
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        return response


def resolve_web_dir(settings: Settings) -> Path | None:
    """Dossier de l'interface compilée, ou `None` si elle n'est pas construite."""
    candidate = Path(settings.web_dir) if settings.web_dir else _REPO_DIST
    return candidate if (candidate / "index.html").is_file() else None


def mount_web_ui(app: FastAPI, web_dir: Path | None) -> None:
    """Branche l'interface (à appeler après les routes de l'API). Sans dossier : rien."""
    if web_dir is None:
        return
    index = web_dir / "index.html"
    assets = web_dir / "assets"
    if assets.is_dir():
        app.mount("/assets", _ImmutableAssets(directory=assets), name="web-assets")

    public_files = {
        entry.name: entry
        for entry in web_dir.iterdir()
        if entry.is_file() and entry.name != "index.html"
    }

    def _page() -> FileResponse:
        return FileResponse(
            index,
            media_type="text/html; charset=utf-8",
            headers={"Content-Security-Policy": UI_CSP, "Cache-Control": "no-cache"},
        )

    @app.get("/", include_in_schema=False)
    async def web_root() -> FileResponse:
        return _page()

    @app.get("/{path:path}", include_in_schema=False)
    async def web_page(path: str) -> Any:
        full = "/" + path
        if full.startswith(_RESERVED_PREFIXES) or full == "/api":
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not Found")
        # Fichier public à la racine (favicon.svg, robots.txt), listé au démarrage : aucun
        # chemin fourni par le client n'est jamais résolu sur le disque.
        if path in public_files:
            return FileResponse(public_files[path], headers=_PUBLIC_CACHE)
        return _page()
