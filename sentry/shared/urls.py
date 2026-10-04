"""Affichage sûr des URL de connexion (base, Redis) : le mot de passe n'apparaît jamais."""

from urllib.parse import urlsplit, urlunsplit

MASK = "••••••"


def mask_url_password(url: str) -> str:
    """`postgresql+asyncpg://sentry:secret@db/sentry` → `…://sentry:••••••@db/sentry`."""
    parts = urlsplit(url)
    if parts.password is None:
        return url
    user = parts.username or ""
    host = parts.hostname or ""
    if parts.port is not None:
        host = f"{host}:{parts.port}"
    return urlunsplit(parts._replace(netloc=f"{user}:{MASK}@{host}"))
