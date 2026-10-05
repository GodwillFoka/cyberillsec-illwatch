"""Séparation des rôles PostgreSQL — M7 Production Hardening, lot 2 (ADR-012).

Deux rôles :

- **propriétaire** (`MIGRATION_DATABASE_URL`) : crée et modifie la structure (Alembic) ;
- **applicatif** (`DATABASE_URL`, `DATABASE_APP_ROLE`) : lit et écrit les données, rien d'autre.

Le rôle applicatif ne peut ni `ALTER`, ni `DROP`, ni `TRUNCATE`, ni supprimer un déclencheur :
l'immuabilité de `incident_events` et `audit_events` ne dépend plus de la bonne conduite du
code. Sur ces deux tables, il n'a que `SELECT` et `INSERT`.

Les droits sont posés **après chaque migration** (`sentry db upgrade`) : une table créée par une
nouvelle migration n'est jamais accessible sans passer par cette fonction.
"""

import re
from dataclasses import dataclass, field

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine
from sqlalchemy.pool import NullPool

from sentry.app.config import Settings

APPEND_ONLY_TABLES = ("incident_events", "audit_events")
READ_ONLY_TABLES = ("alembic_version",)
_ROLE_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


class AppRoleError(ValueError):
    """Rôle invalide, superutilisateur ou propriétaire des tables."""


@dataclass(slots=True)
class GrantReport:
    role: str
    tables: int = 0
    privileges: dict[str, list[str]] = field(default_factory=dict)


def _check_name(role: str) -> str:
    if not _ROLE_RE.match(role):
        raise AppRoleError(f"Nom de rôle refusé : {role!r} (attendu [a-z_][a-z0-9_]*).")
    return role


def owner_url(settings: Settings) -> str:
    return settings.migration_database_url or settings.database_url


async def _apply(conn: AsyncConnection, role: str) -> GrantReport:
    flags = (
        await conn.execute(text("SELECT rolsuper FROM pg_roles WHERE rolname = :r"), {"r": role})
    ).first()
    if flags is None:
        raise AppRoleError(f"Le rôle {role} n'existe pas (option --create).")
    if flags[0]:
        raise AppRoleError(f"{role} est superutilisateur : la séparation serait sans effet.")
    owned: int = (
        await conn.execute(
            text("SELECT count(*) FROM pg_tables WHERE schemaname = 'public' AND tableowner = :r"),
            {"r": role},
        )
    ).scalar_one()
    if owned:
        raise AppRoleError(
            f"{role} possède {owned} table(s) : il doit être distinct du propriétaire."
        )

    quoted = f'"{role}"'  # nom validé par _ROLE_RE : pas d'injection possible
    database: str = (await conn.execute(text("SELECT current_database()"))).scalar_one()
    database = database.replace('"', '""')  # identifiant entre guillemets : « " » doublé
    statements = [
        f'GRANT CONNECT ON DATABASE "{database}" TO {quoted}',
        f"GRANT USAGE ON SCHEMA public TO {quoted}",
        f"REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {quoted}",
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {quoted}",
        f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {quoted}",
    ]
    existing: set[str] = set(
        (
            await conn.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'"))
        ).scalars()
    )
    for table in APPEND_ONLY_TABLES:
        if table in existing:
            statements.append(f"REVOKE UPDATE, DELETE ON {table} FROM {quoted}")
    for table in READ_ONLY_TABLES:
        if table in existing:
            statements.append(f"REVOKE INSERT, UPDATE, DELETE ON {table} FROM {quoted}")
    for statement in statements:
        await conn.execute(text(statement))

    rows = await conn.execute(
        text(
            "SELECT table_name, privilege_type FROM information_schema.role_table_grants "
            "WHERE grantee = :r AND table_schema = 'public' ORDER BY 1, 2"
        ),
        {"r": role},
    )
    report = GrantReport(role=role)
    for table, privilege in rows.all():
        report.privileges.setdefault(str(table), []).append(str(privilege))
    report.tables = len(report.privileges)
    return report


async def grant_app_role(
    settings: Settings, role: str, *, create_password: str | None = None
) -> GrantReport:
    """Crée éventuellement le rôle, puis pose les droits minimaux (idempotent)."""
    _check_name(role)
    engine = create_async_engine(owner_url(settings), poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            if create_password is not None:
                exists = (
                    await conn.execute(
                        text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": role}
                    )
                ).first()
                if exists is None:
                    statement: str = (
                        await conn.execute(
                            text(
                                "SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', "
                                "CAST(:r AS text), CAST(:p AS text))"
                            ),
                            {"r": role, "p": create_password},
                        )
                    ).scalar_one()
                    await conn.exec_driver_sql(
                        statement
                    )  # pas de text() : un « : » du mot de passe serait pris pour un paramètre
            return await _apply(conn, role)
    finally:
        await engine.dispose()
