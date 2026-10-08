"""Environnement de migration Alembic (mode asynchrone)."""

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy.ext.asyncio import async_engine_from_config
from sqlalchemy import pool

from illwatch.app.config import get_settings
from illwatch.app.database import Base
import illwatch.app.models  # noqa: F401 - enregistre tous les modèles dans Base.metadata

config = context.config
# M7 lot 2 : les migrations s'exécutent avec le rôle propriétaire (MIGRATION_DATABASE_URL)
# quand il est défini ; l'application, elle, n'a pas le droit de modifier la structure.
_settings = get_settings()
# « % » doublé : ConfigParser prendrait un mot de passe encodé (« %3A ») pour une interpolation.
_url = _settings.migration_database_url or _settings.database_url
config.set_main_option("sqlalchemy.url", _url.replace("%", "%%"))

if config.config_file_name is not None:
    # disable_existing_loggers=False : sinon chaque migration lancée dans le processus (CLI,
    # tests) désactive les journaux `illwatch.*` déjà créés, dont le journal d'audit.
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
    if _settings.migration_database_url and not config.attributes.get("illwatch_cli"):
        # `alembic upgrade` seul ne donne aucun droit au rôle applicatif sur une table nouvelle :
        # l'API et le worker échoueraient ensuite sur « permission denied ».
        import sys

        print(
            "\n⚠  Droits du rôle applicatif non réappliqués. Préférez « illwatch db upgrade »,\n"
            "   ou lancez maintenant : illwatch db app-role "
            f"{_settings.database_app_role or 'illwatch_app'}\n",
            file=sys.stderr,
        )
