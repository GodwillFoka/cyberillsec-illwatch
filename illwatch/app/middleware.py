"""Couche HTTP transverse — M7 Production Hardening (ADR-011).

Middleware ASGI pur (compatible avec les réponses diffusées en flux des exports) qui :

1. attribue à chaque requête un **identifiant** (`X-Request-ID`) : repris de l'en-tête entrant
   s'il est sûr (≤ 64 caractères `[A-Za-z0-9._-]`), généré sinon ; renvoyé dans la réponse,
   porté par le journal d'audit et par les erreurs ;
2. pose les **en-têtes de sécurité** : `nosniff`, `frame-ancestors 'none'`, `Referrer-Policy`,
   `Permissions-Policy`, `Cache-Control: no-store` sur l'API, HSTS en production ;
3. écrit une ligne JSON d'**accès** par requête (méthode, chemin sans paramètres, statut,
   durée, identifiant) — jamais les en-têtes ni le corps, qui portent jetons et mots de passe.

Le gestionnaire `unhandled_error` remplace la page d'erreur par défaut : réponse JSON stable
avec l'identifiant de requête, trace complète dans le journal seulement.
"""

import logging
import re
import time
from uuid import uuid4

from fastapi import Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

log = logging.getLogger("illwatch.http")

REQUEST_ID_HEADER = "x-request-id"
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_QUIET_PATHS = frozenset({"/health", "/ready"})
# La documentation interactive charge Swagger UI / ReDoc depuis un CDN : la politique stricte
# `default-src 'none'` ne s'applique qu'aux réponses de l'API.
_DOC_PREFIXES = ("/docs", "/redoc", "/openapi.json")

BASE_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
    (b"cross-origin-opener-policy", b"same-origin"),
)
API_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
    (b"cache-control", b"no-store"),
)
HSTS_HEADER = (b"strict-transport-security", b"max-age=31536000; includeSubDomains")


def request_id_from(raw: str | None) -> str:
    return raw if raw and _SAFE_REQUEST_ID.match(raw) else uuid4().hex


class SecurityMiddleware:
    def __init__(self, app: ASGIApp, *, hsts: bool = False) -> None:
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        incoming = dict(scope.get("headers") or []).get(REQUEST_ID_HEADER.encode())
        request_id = request_id_from(incoming.decode("latin-1") if incoming else None)
        scope.setdefault("state", {})["request_id"] = request_id
        path: str = scope.get("path", "")
        is_doc = path.startswith(_DOC_PREFIXES)
        started = time.perf_counter()
        status_holder = [500]

        async def _send(message: Message) -> None:
            if message["type"] == "http.response.start":
                status_holder[0] = int(message["status"])
                present = {name.lower() for name, _ in message.get("headers", [])}
                extra: list[tuple[bytes, bytes]] = [(b"x-request-id", request_id.encode())]
                extra += [h for h in BASE_HEADERS if h[0] not in present]
                if not is_doc:
                    extra += [h for h in API_HEADERS if h[0] not in present]
                if self.hsts:
                    extra.append(HSTS_HEADER)
                message["headers"] = [*message.get("headers", []), *extra]
            await send(message)

        try:
            await self.app(scope, receive, _send)
        finally:
            duration_ms = round((time.perf_counter() - started) * 1000, 1)
            level = logging.DEBUG if path in _QUIET_PATHS else logging.INFO
            client = scope.get("client")
            log.log(
                level,
                "http.request",
                extra={
                    "fields": {
                        "request_id": request_id,
                        "method": scope.get("method"),
                        "path": path,
                        "status": status_holder[0],
                        "duration_ms": duration_ms,
                        "client": client[0] if client else None,
                    }
                },
            )


async def unhandled_error(request: Request, exc: Exception) -> JSONResponse:
    """Erreur inattendue : 500 JSON sans détail interne, trace complète dans le journal."""
    request_id = getattr(request.state, "request_id", None) or uuid4().hex
    log.error(
        "http.unhandled_error",
        exc_info=exc,
        extra={"fields": {"request_id": request_id, "path": request.url.path}},
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Erreur interne du serveur.", "request_id": request_id},
        headers={"X-Request-ID": request_id},
    )


async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    """422 standard de FastAPI, plus l'audit des URL de source refusées par l'anti-SSRF.

    Une URL visant le réseau interne est rejetée dès la validation du schéma, avant la route :
    sans ce gestionnaire, la tentative ne laissait aucune trace d'audit. Seules les erreurs
    portant une `UnsafeFeedURLError` sont consignées ; les fautes de saisie ordinaires restent
    dans le seul journal d'accès.
    """
    from illwatch.app.config import get_settings
    from illwatch.app.security import InvalidTokenError, decode_access_token
    from illwatch.modules.foundation.audit import AuditContext, get_audit_recorder
    from illwatch.modules.threat_feeds.service import UnsafeFeedURLError
    from illwatch.shared.enums import AuditOutcome

    unsafe = [
        err
        for err in exc.errors()
        if isinstance((err.get("ctx") or {}).get("error"), UnsafeFeedURLError)
    ]
    feeds_path = f"{get_settings().api_v1_prefix}/feeds"
    if unsafe and request.url.path.startswith(feeds_path):
        actor_id = None
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() == "bearer" and token:
            try:
                actor_id = decode_access_token(token).user_id
            except InvalidTokenError:
                actor_id = None
        provider = request.app.dependency_overrides.get(get_audit_recorder, get_audit_recorder)
        body = unsafe[0].get("input")
        await provider().record(
            "feed.create" if request.method == "POST" else "feed.update",
            AuditOutcome.FAILURE,
            actor_id=actor_id,
            actor_name=None if actor_id else "(non authentifié)",
            target_type="feed",
            target_id=request.url.path.removeprefix(feeds_path).strip("/") or None,
            detail={
                "reason": "unsafe_url",
                "url": body if isinstance(body, str) else None,
                "error": str((unsafe[0].get("ctx") or {}).get("error")),
            },
            context=AuditContext.from_request(request),
        )
    return await request_validation_exception_handler(request, exc)
