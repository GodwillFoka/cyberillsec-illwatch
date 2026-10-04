"""Pilotage programmatique d'Alembic — utilisé par la CLI (`sentry db …`) et les tests.

Localisation de `alembic.ini`, dans l'ordre :
  1. variable d'environnement `SENTRY_ALEMBIC_INI` ;
  2. répertoire courant (cas de l'image Docker, WORKDIR=/app) ;
  3. racine du dépôt (installation éditable `pip install -e .`).
"""

import os
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy.engine import Connection

from sentry.app.config import get_settings
from sentry.app.database import get_engine

_REPO_ROOT = Path(__file__).resolve().parents[2]


class AlembicConfigNotFoundError(FileNotFoundError):
    """`alembic.ini` introuvable."""


def find_alembic_ini() -> Path:
    candidates = [Path(p) for p in (os.environ.get("SENTRY_ALEMBIC_INI"),) if p] + [
        Path.cwd() / "alembic.ini",
        _REPO_ROOT / "alembic.ini",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    searched = ", ".join(str(c) for c in candidates)
    raise AlembicConfigNotFoundError(f"alembic.ini introuvable (cherché : {searched}).")


def alembic_config() -> Config:
    ini = find_alembic_ini()
    cfg = Config(str(ini))
    cfg.set_main_option("script_location", str(ini.parent / "alembic"))
    settings = get_settings()
    url = settings.migration_database_url or settings.database_url
    # Alembic stocke l'URL dans un ConfigParser : un mot de passe encodé (« %3A ») y serait
    # pris pour une interpolation et ferait échouer toute migration. « % » doit être doublé.
    cfg.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    return cfg


def upgrade(revision: str = "head") -> None:
    command.upgrade(alembic_config(), revision)


def downgrade(revision: str) -> None:
    command.downgrade(alembic_config(), revision)


def head_revision() -> str | None:
    return ScriptDirectory.from_config(alembic_config()).get_current_head()


async def current_revision() -> str | None:
    """Révision actuellement appliquée à la base (`None` si base vierge)."""

    def _read(connection: Connection) -> str | None:
        return MigrationContext.configure(connection).get_current_revision()

    async with get_engine().connect() as conn:
        return await conn.run_sync(_read)
