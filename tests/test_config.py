"""Tests de la validation de configuration au démarrage — RF-01 / règle de gestion MOD-01."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from illwatch.app.config import DEFAULT_SECRET_KEY, ENV_FILE_VARIABLE, Settings, _env_file

STRONG_SECRET = "a" * 64
PROD_DB = "postgresql+asyncpg://illwatch_app:Zq7%3Along-random@db:5432/illwatch"


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
        "postgresql+asyncpg://illwatch:illwatch@db:5432/illwatch",
        "postgresql+asyncpg://illwatch_app:illwatch-app-dev@db:5432/illwatch",
        "postgresql+asyncpg://illwatch_app@db:5432/illwatch",
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


# --- Clone neuf : `.env.example` copié tel quel doit démarrer ------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_env_example_copie_tel_quel_se_charge() -> None:
    """`cp .env.example .env` puis démarrage : les booléens vides ne doivent rien casser."""
    settings = Settings(_env_file=REPO_ROOT / ".env.example")  # type: ignore[call-arg]
    assert settings.docs_enabled is None and settings.expose_docs is True
    assert settings.hsts_enabled is None and settings.send_hsts is False
    assert settings.secret_key_previous is None
    assert settings.nvd_api_key is None and settings.otx_api_key is None


def test_variable_vide_vaut_valeur_par_defaut(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOCS_ENABLED", "")
    monkeypatch.setenv("HSTS_ENABLED", "")
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.docs_enabled is None and settings.hsts_enabled is None


def test_illwatch_env_file_choisit_ou_desactive_le_fichier(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_FILE_VARIABLE, raising=False)
    assert _env_file() == ".env"
    monkeypatch.setenv(ENV_FILE_VARIABLE, "/etc/illwatch/env")
    assert _env_file() == "/etc/illwatch/env"
    monkeypatch.setenv(ENV_FILE_VARIABLE, "")
    assert _env_file() is None


def test_les_tests_ne_lisent_aucun_env() -> None:
    """Garde-fou : un `.env` de poste ne doit jamais influencer la suite (ni ses migrations)."""
    assert Settings.model_config.get("env_file") is None
