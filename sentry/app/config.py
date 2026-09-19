"""Configuration applicative immuable — RF-01.

Toute la configuration est chargée depuis l'environnement (ou un fichier `.env`)
et validée par Pydantic au démarrage. Aucune requête applicative ne doit
s'exécuter si la validation échoue (règle de gestion MOD-01).
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Variables d'environnement typées de SENTRY."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        frozen=True,
    )

    # --- Application ---------------------------------------------------------
    app_name: str = "SENTRY"
    app_version: str = "0.1.0"
    environment: Literal["development", "staging", "production"] = "development"
    debug: bool = False
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    # --- Base de données -----------------------------------------------------
    # PostgreSQL 16 en cible ; SQLite/aiosqlite accepté pour les tests locaux.
    database_url: str = Field(
        default="postgresql+asyncpg://sentry:sentry@localhost:5432/sentry",
        description="DSN SQLAlchemy async",
    )
    database_echo: bool = False
    database_pool_size: int = Field(default=10, ge=1, le=100)

    # --- Cache / Broker ------------------------------------------------------
    redis_url: str = "redis://localhost:6379/0"

    # --- API -----------------------------------------------------------------
    api_v1_prefix: str = "/api/v1"
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])

    # --- Sécurité ------------------------------------------------------------
    secret_key: str = Field(
        default="change-me-in-production",
        min_length=8,
        description="Clé de signature JWT — OBLIGATOIREMENT surchargée en production",
    )
    access_token_expire_minutes: int = 60

    # --- Connecteurs CTI externes (clés optionnelles) ------------------------
    nvd_api_key: str | None = None
    otx_api_key: str | None = None

    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    kev_catalog_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    epss_api_url: str = "https://api.first.org/data/v1/epss"

    # --- Collecte ------------------------------------------------------------
    default_polling_interval: int = Field(default=3600, ge=60)
    http_timeout_seconds: float = Field(default=15.0, gt=0)
    http_max_retries: int = Field(default=3, ge=0, le=10)

    # --- Scoring & alerting (§3.3.3 du CdC) ---------------------------------
    risk_alert_threshold: float = Field(default=75.0, ge=0, le=100)

    @field_validator("secret_key")
    @classmethod
    def _reject_default_secret_in_prod(cls, v: str, info: object) -> str:
        return v

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Singleton de configuration (mis en cache pour la durée du process)."""
    return Settings()
