"""Serveur TAXII 2.1 en lecture seule : `/taxii2/` (M10, incrément 3, ADR-025).

Partage le renseignement d'ILLWATCH avec un SIEM, un pare-feu ou une autre plateforme CTI
(OpenCTI, MISP, `taxii2-client`) au format standard :

- découverte `GET /taxii2/` → API root `GET /taxii2/illwatch/` ;
- deux collections : **indicateurs** (IOC actifs, paginés par curseur, filtre `added_after`)
  et **campagnes** (campagnes, acteurs ATT&CK, relations et IOC de leur infrastructure) ;
- `objects/` (enveloppe `more` / `next`), `manifest/`, en-têtes
  `X-TAXII-Date-Added-First` et `-Last`.

Authentification : jeton Bearer de l'API **ou** HTTP Basic (identifiant et mot de passe d'un
compte ILLWATCH, de préférence un compte LECTEUR dédié au consommateur). Le Basic passe par le
même limiteur de tentatives que la connexion et chaque échec est consigné au journal d'audit.
Aucune écriture : `can_write` est faux sur toutes les collections.
"""

import base64
import binascii
from datetime import datetime
from typing import Annotated, Any
from uuid import uuid5

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from illwatch.app.api.deps import DbSession
from illwatch.app.models import User
from illwatch.app.security import InvalidTokenError, decode_access_token
from illwatch.app.throttle import LoginThrottle, get_login_throttle
from illwatch.modules.foundation.audit import AuditContext, AuditRecorder, get_audit_recorder
from illwatch.modules.foundation.users import authenticate, get_user_by_username
from illwatch.modules.stix import export
from illwatch.shared.enums import AuditOutcome
from illwatch.shared.server_text import tr

TAXII_MEDIA = "application/taxii+json;version=2.1"
STIX_MEDIA = "application/stix+json;version=2.1"
API_ROOT = "illwatch"
MAX_CONTENT_LENGTH = 10 * 1024 * 1024


class _Collection:
    def __init__(self, key: str, title: tuple[str, str], description: tuple[str, str]) -> None:
        self.key = key
        self.id = str(uuid5(export.NAMESPACE, f"collection:{key}"))
        self._title = title  # (français, anglais) : langue de l'instance (ADR-027, décision 12)
        self._description = description

    @property
    def title(self) -> str:
        return tr(*self._title)

    @property
    def description(self) -> str:
        return tr(*self._description)

    def read(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "can_read": True,
            "can_write": False,
            "media_types": [STIX_MEDIA],
        }


INDICATORS = _Collection(
    "indicateurs",
    ("Indicateurs ILLWATCH", "ILLWATCH indicators"),
    (
        "IOC actifs (non expirés, non exclus), confiance 0-100, sévérité en étiquette.",
        "Active IOCs (not expired, not excluded), confidence 0-100, severity as a label.",
    ),
)
CAMPAIGNS = _Collection(
    "campagnes",
    ("Campagnes ILLWATCH", "ILLWATCH campaigns"),
    (
        "Campagnes, acteurs MITRE ATT&CK et IOC de leur infrastructure, avec leurs relations.",
        "Campaigns, MITRE ATT&CK actors and the IOCs of their infrastructure, with relationships.",
    ),
)
COLLECTIONS = {c.id: c for c in (INDICATORS, CAMPAIGNS)}


class TaxiiError(HTTPException):
    """Erreur au format TAXII (« error message » §3.6.1)."""

    def __init__(self, status: int, title: str, description: str | None = None) -> None:
        super().__init__(status_code=status, detail=title)
        self.title = title
        self.description = description


def _error(status: int, title: str, description: str | None = None) -> JSONResponse:
    body: dict[str, Any] = {"title": title, "http_status": str(status)}
    if description:
        body["description"] = description
    headers = {"WWW-Authenticate": 'Basic realm="ILLWATCH TAXII", Bearer'} if status == 401 else {}
    return JSONResponse(body, status_code=status, media_type=TAXII_MEDIA, headers=headers)


def taxii_response(body: dict[str, Any], headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(body, media_type=TAXII_MEDIA, headers=headers)


def _accepts(request: Request) -> bool:
    accept = request.headers.get("accept", "").replace(" ", "").lower()
    if not accept:
        return True
    return any(
        part.split(";")[0] in {"application/taxii+json", "application/json", "*/*", "application/*"}
        and ("version=" not in part or "version=2.1" in part)
        for part in accept.split(",")
    )


async def taxii_user(
    request: Request,
    session: DbSession,
    throttle: Annotated[LoginThrottle, Depends(get_login_throttle)],
    audit: Annotated[AuditRecorder, Depends(get_audit_recorder)],
) -> User:
    """Bearer (jeton de l'API) ou Basic (compte ILLWATCH) ; refus 401 au format TAXII."""
    if not _accepts(request):
        raise TaxiiError(406, "Type de média non pris en charge : " + TAXII_MEDIA)
    header = request.headers.get("authorization", "")
    scheme, _, credentials = header.partition(" ")
    scheme = scheme.lower()
    if scheme == "bearer" and credentials:
        try:
            payload = decode_access_token(credentials.strip())
        except InvalidTokenError:
            raise TaxiiError(401, "Jeton invalide ou expiré.") from None
        user = await session.get(User, payload.user_id)
        if user is None or not user.is_active:
            raise TaxiiError(401, "Compte inconnu ou désactivé.")
        return user
    if scheme == "basic" and credentials:
        try:
            username, _, password = base64.b64decode(credentials.strip()).decode().partition(":")
        except (binascii.Error, UnicodeDecodeError):
            raise TaxiiError(401, "En-tête Basic illisible.") from None
        ip = request.client.host if request.client else "inconnue"
        context = AuditContext.from_request(request)
        if await throttle.blocked(username, ip):
            raise TaxiiError(429, "Trop de tentatives : réessayez plus tard.")
        user = await authenticate(session, username, password)
        if user is None or not user.is_active:
            await throttle.failure(username, ip)
            known = await get_user_by_username(session, username.strip())
            await audit.record(
                "taxii.auth",
                AuditOutcome.FAILURE,
                actor_name=known.username if known else "(inconnu)",
                context=context,
                detail={"reason": "invalid_credentials"},
            )
            raise TaxiiError(401, "Identifiants invalides.")
        await throttle.success(username, ip)
        return user
    raise TaxiiError(401, "Authentification requise (Bearer ou Basic).")


TaxiiUser = Annotated[User, Depends(taxii_user)]

router = APIRouter(prefix="/taxii2", tags=["TAXII 2.1"], include_in_schema=False)


def _collection(collection_id: str) -> _Collection:
    found = COLLECTIONS.get(collection_id.lower())
    if found is None:
        raise TaxiiError(404, "Collection inconnue.", collection_id)
    return found


def _parse_added_after(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise TaxiiError(400, "added_after : horodatage RFC 3339 attendu.", value) from None


def _match_types(raw: str | None) -> set[str] | None:
    return {t.strip() for t in raw.split(",") if t.strip()} if raw else None


@router.get("/")
async def discovery(request: Request, _: TaxiiUser) -> JSONResponse:
    root = str(request.url_for("api_root"))
    return taxii_response(
        {
            "title": "ILLWATCH: TAXII 2.1",
            "description": tr(
                "Renseignement sur les menaces partagé par ILLWATCH (CyberillSec).",
                "Threat intelligence shared by ILLWATCH (CyberillSec).",
            ),
            "contact": "CyberillSec",
            "default": root,
            "api_roots": [root],
        }
    )


@router.get(f"/{API_ROOT}/", name="api_root")
async def api_root(_: TaxiiUser) -> JSONResponse:
    return taxii_response(
        {
            "title": "ILLWATCH",
            "description": tr(
                "Indicateurs et campagnes au format STIX 2.1 (lecture seule).",
                "Indicators and campaigns in STIX 2.1 format (read only).",
            ),
            "versions": [TAXII_MEDIA],
            "max_content_length": MAX_CONTENT_LENGTH,
        }
    )


@router.get(f"/{API_ROOT}/collections/")
async def collections(_: TaxiiUser) -> JSONResponse:
    return taxii_response({"collections": [c.read() for c in COLLECTIONS.values()]})


@router.get(f"/{API_ROOT}/collections/{{collection_id}}/")
async def collection(collection_id: str, _: TaxiiUser) -> JSONResponse:
    return taxii_response(_collection(collection_id).read())


async def _objects(
    session: DbSession,
    target: _Collection,
    *,
    added_after: datetime | None,
    limit: int,
    next_token: str | None,
    types: set[str] | None,
) -> tuple[list[dict[str, Any]], bool, str | None, str | None, str | None]:
    """Objets d'une collection : (objets, more, next, date d'ajout première, dernière)."""
    if target is INDICATORS:
        try:
            page = await export.indicator_page(
                session, added_after=added_after, limit=limit, next_token=next_token
            )
        except ValueError as exc:
            raise TaxiiError(400, "Paramètre next invalide.", str(exc)) from None
        objects = page.objects
        if not next_token and added_after is None:
            objects = [export.identity(), *objects]
        first = export.timestamp(page.first_added) if page.first_added else None
        last = export.timestamp(page.last_added) if page.last_added else None
        if types is not None:
            objects = [o for o in objects if o["type"] in types]
        return objects, page.more, page.next, first, last
    everything = [export.identity(), *await export.campaign_objects(session)]
    if added_after is not None:
        stamp = export.timestamp(added_after)
        everything = [o for o in everything if o["modified"] > stamp]
    if types is not None:
        everything = [o for o in everything if o["type"] in types]
    everything.sort(key=lambda o: (o["modified"], o["id"]))
    try:
        offset = int(next_token) if next_token else 0
    except ValueError:
        raise TaxiiError(400, "Paramètre next invalide.") from None
    window = everything[offset : offset + limit]
    more = offset + limit < len(everything)
    return (
        window,
        more,
        str(offset + limit) if more else None,
        window[0]["modified"] if window else None,
        window[-1]["modified"] if window else None,
    )


def _date_headers(first: str | None, last: str | None) -> dict[str, str]:
    headers = {}
    if first:
        headers["X-TAXII-Date-Added-First"] = first
    if last:
        headers["X-TAXII-Date-Added-Last"] = last
    return headers


@router.get(f"/{API_ROOT}/collections/{{collection_id}}/objects/")
async def objects(
    collection_id: str,
    session: DbSession,
    _: TaxiiUser,
    added_after: str | None = None,
    limit: Annotated[int, Query(ge=1, le=export.MAX_PAGE)] = 500,
    next_token: Annotated[str | None, Query(alias="next", max_length=200)] = None,
    match_type: Annotated[str | None, Query(alias="match[type]", max_length=200)] = None,
) -> JSONResponse:
    target = _collection(collection_id)
    found, more, token, first, last = await _objects(
        session,
        target,
        added_after=_parse_added_after(added_after),
        limit=limit,
        next_token=next_token,
        types=_match_types(match_type),
    )
    body: dict[str, Any] = {"more": more}
    if token:
        body["next"] = token
    if found:
        body["objects"] = found
    return taxii_response(body, _date_headers(first, last))


@router.get(f"/{API_ROOT}/collections/{{collection_id}}/manifest/")
async def manifest(
    collection_id: str,
    session: DbSession,
    _: TaxiiUser,
    added_after: str | None = None,
    limit: Annotated[int, Query(ge=1, le=export.MAX_PAGE)] = 500,
    next_token: Annotated[str | None, Query(alias="next", max_length=200)] = None,
    match_type: Annotated[str | None, Query(alias="match[type]", max_length=200)] = None,
) -> JSONResponse:
    target = _collection(collection_id)
    found, more, token, first, last = await _objects(
        session,
        target,
        added_after=_parse_added_after(added_after),
        limit=limit,
        next_token=next_token,
        types=_match_types(match_type),
    )
    body: dict[str, Any] = {"more": more}
    if token:
        body["next"] = token
    if found:
        body["objects"] = [
            {
                "id": o["id"],
                "date_added": o["modified"],
                "version": o["modified"],
                "media_type": STIX_MEDIA,
            }
            for o in found
        ]
    return taxii_response(body, _date_headers(first, last))


async def taxii_error_handler(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, TaxiiError):  # pragma: no cover - enregistré pour TaxiiError seul
        raise exc
    return _error(exc.status_code, exc.title, exc.description)
