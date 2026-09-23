"""Tests de la validation de configuration au démarrage — RF-01 / règle de gestion MOD-01."""

import pytest
from pydantic import ValidationError

from sentry.app.config import DEFAULT_SECRET_KEY, Settings

STRONG_SECRET = "a" * 64


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
    settings = Settings(environment="production", secret_key=STRONG_SECRET, debug=False)
    assert settings.is_production is True


def test_configuration_est_immuable() -> None:
    settings = Settings(secret_key=STRONG_SECRET)
    with pytest.raises(ValidationError):
        settings.environment = "production"  # type: ignore[misc]
