"""Export STIX 2.1 : `/api/v1/stix` (M10, incrément 3, ADR-025).

Un bundle à télécharger ou à importer dans une autre plateforme. Pour un partage continu,
préférer le serveur TAXII 2.1 (`/taxii2/`), paginé et incrémental (`added_after`).
"""

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from illwatch.app.api.deps import Audit, CurrentUser, DbSession
from illwatch.modules.stix.export import export_bundle

router = APIRouter(prefix="/stix", tags=["STIX 2.1"])


@router.get(
    "/bundle",
    summary="Bundle STIX 2.1 des IOC actifs et des campagnes",
    response_model=dict[str, Any],
)
async def stix_bundle(
    session: DbSession,
    user: CurrentUser,
    audit: Audit,
    contenu: Literal["tout", "indicateurs", "campagnes"] = "tout",
    limit: Annotated[int, Query(ge=1, le=50_000)] = 1000,
) -> JSONResponse:
    document = await export_bundle(session, content=contenu, limit=limit)
    await audit.record(
        "stix.export",
        actor=user,
        target_type="stix",
        detail={"contenu": contenu, "objets": len(document["objects"])},
    )
    return JSONResponse(
        document,
        media_type="application/stix+json;version=2.1",
        headers={"Content-Disposition": 'attachment; filename="illwatch-stix.json"'},
    )
