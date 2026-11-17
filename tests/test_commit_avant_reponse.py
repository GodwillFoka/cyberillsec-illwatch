"""La transaction d'une requête est validée avant l'envoi de la réponse.

Régression de la validation réelle du 16/11/2026 : avec la portée par défaut de FastAPI, la
session était validée APRÈS l'envoi. Le scénario SOC recevait 200 pour la transition vers
ANALYSE, envoyait aussitôt la transition vers CONFINEMENT, et la lisait encore en NOUVEAU : 409.
"""

from collections.abc import AsyncGenerator
from uuid import uuid4

from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from illwatch.app.database import get_db
from illwatch.app.main import create_app
from illwatch.app.security import create_access_token
from illwatch.modules.foundation.users import create_user
from illwatch.shared.enums import UserRole


def _record_response_start(app: ASGIApp, order: list[str]) -> ASGIApp:
    async def wrapped(scope: Scope, receive: Receive, send: Send) -> None:
        async def tracking_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                order.append("réponse")
            await send(message)

        await app(scope, receive, tracking_send)

    return wrapped


async def test_ecriture_validee_avant_la_reponse(db_session: AsyncSession) -> None:
    name = f"analyst-{uuid4().hex[:8]}"
    user = await create_user(
        db_session,
        username=name,
        email=f"{name}@cyberill.test",
        password="mot-de-passe-robuste-2026",
        role=UserRole.ANALYST,
    )
    headers = {"Authorization": f"Bearer {create_access_token(user.id, user.role)}"}
    order: list[str] = []

    async def _db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session
        order.append("commit")  # emplacement du `session.commit()` de `get_db`

    app = create_app()
    app.dependency_overrides[get_db] = _db
    transport = ASGITransport(app=_record_response_start(app, order))
    async with AsyncClient(transport=transport, base_url="http://test") as http:
        response = await http.post(
            "/api/v1/incidents",
            headers=headers,
            json={"title": "Commit avant réponse", "description": "x", "severity": "LOW"},
        )

    assert response.status_code == 201, response.text
    assert order == ["commit", "réponse"]
