"""Tests de la validation de configuration au démarrage — RF-01 / règle de gestion MOD-01."""

import pytest
from pydantic import ValidationError

from sentry.app.config import DEFAULT_SECRET_KEY, Settings

STRONG_SECRET = "a" * 64
PROD_DB = "postgresql+asyncpg://sentry_app:Zq7%3Along-random@db:5432/sentry"


def test_developpement_accepte_la_cle_par_defaut() -> None:
    settings = Settings(environment="development", secret_key=DEFAULT_SECRET_KEY)
    assert settings.is_production is False


def test_production_refuse_la_cle_par_defaut() -> None:
    with pytest.raises(ValidationError, match="SECRET_KEY par défaut"):
        Settings(environment="production", secret_key=DEFAULT_SECRET_KEY)


def test_production_refuse_une_cle_trop_courte() -> None:
    with pytest.raises(ValidationError, match="trop courte"):
        Settings(environment="production", secret_key="x" * 31)


def test_production_refuse_le_mode_debug() -> None:
    with pytest.raises(ValidationError, match="DEBUG"):
        Settings(environment="production", secret_key=STRONG_SECRET, debug=True)


def test_production_accepte_une_configuration_saine() -> None:
    settings = Settings(
        environment="production",
        secret_key=STRONG_SECRET,
        debug=False,
        database_url=PROD_DB,
        redis_url="redis://:Xk29-long-random@redis:6379/0",
    )
    assert settings.is_production is True


@pytest.mark.parametrize(
    "url",
    [
        "postgresql+asyncpg://sentry:sentry@db:5432/sentry",
        "postgresql+asyncpg://sentry_app:sentry-app-dev@db:5432/sentry",
        "postgresql+asyncpg://sentry_app@db:5432/sentry",
    ],
)
def test_production_refuse_un_mot_de_passe_de_base_de_developpement(url: str) -> None:
    with pytest.raises(ValidationError, match="DATABASE_URL"):
        Settings(
            environment="production",
            secret_key=STRONG_SECRET,
            database_url=url,
            redis_url="redis://:Xk29-long-random@redis:6379/0",
        )


def test_configuration_est_immuable() -> None:
    settings = Settings(secret_key=STRONG_SECRET)
    with pytest.raises(ValidationError):
        settings.environment = "production"  # type: ignore[misc]
