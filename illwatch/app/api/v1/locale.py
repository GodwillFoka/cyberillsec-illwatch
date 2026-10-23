"""Langue d'affichage du visiteur — `GET /api/v1/locale` (ADR-027).

Public (avant connexion : écran de connexion, site de présentation). Ce que la route sait du
visiteur reste minimal et ne quitte jamais le serveur :

- l'adresse IP sert à une **seule** recherche dans la base DB-IP Lite **locale** (aucun service
  tiers), en mémoire ; elle n'est ni journalisée ni conservée, ni renvoyée ;
- la réponse ne contient que la langue choisie et la nature du signal (pas le pays) ;
- l'adresse est celle vue par uvicorn, qui n'accepte `X-Forwarded-For` que de Caddy : un
  client ne peut pas se faire passer pour un autre pays par un en-tête forgé ;
- `Accept-Language` est borné et validé (`illwatch.shared.i18n`) ;
- au plus `_MAX_CONCURRENT_LOOKUPS` recherches simultanées : au-delà, la langue est décidée
  sans la base (navigateur, instance), la route ne peut donc pas saturer le pool de connexions.
"""

import asyncio
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Request, Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.config import Settings, get_settings
from illwatch.app.database import get_db
from illwatch.modules.enrichment.lookup import country_of
from illwatch.shared.i18n import SUPPORTED, Language, Source, choose_language

log = logging.getLogger("illwatch.locale")

router = APIRouter(tags=["langue"])

_MAX_CONCURRENT_LOOKUPS = 8
_lookups = asyncio.Semaphore(_MAX_CONCURRENT_LOOKUPS)


class LocaleResponse(BaseModel):
    lang: Language
    source: Source
    supported: list[Language]


async def _visitor_country(request: Request, session: AsyncSession) -> str | None:
    host = request.client.host if request.client else None
    if not host or _lookups.locked():
        return None
    async with _lookups:
        try:
            return await country_of(session, host)
        except Exception:  # noqa: BLE001 - la langue se décide alors sans le pays
            log.warning("Pays du visiteur indisponible : base d'enrichissement injoignable.")
            return None


@router.get("/locale", response_model=LocaleResponse, summary="Langue d'affichage du visiteur")
async def locale(
    request: Request,
    response: Response,
    session: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
    accept_language: Annotated[str | None, Header()] = None,
) -> LocaleResponse:
    """Pays du visiteur (ou de l'instance), puis navigateur, langue de l'instance, anglais."""
    choice = choose_language(
        visitor_country=await _visitor_country(request, session),
        accept_language=accept_language,
        instance_country=settings.instance_country,
        instance_language=settings.default_language,
    )
    # La réponse dépend du visiteur : jamais mise en cache par un intermédiaire.
    response.headers["Vary"] = "Accept-Language"
    return LocaleResponse(lang=choice.lang, source=choice.source, supported=list(SUPPORTED))
