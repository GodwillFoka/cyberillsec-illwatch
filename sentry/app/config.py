"""Configuration applicative immuable — RF-01.

Toute la configuration est chargée depuis l'environnement (ou un fichier `.env`)
et validée par Pydantic au démarrage. Aucune requête applicative ne doit
s'exécuter si la validation échoue (règle de gestion MOD-01).
"""

from functools import lru_cache
from typing import Literal, Self

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_SECRET_KEY = "change-me-in-production"  # noqa: S105 - sentinelle refusée en prod
INSECURE_SECRET_KEYS = frozenset({DEFAULT_SECRET_KEY, "changeme", "secret", "sentry"})
MIN_PRODUCTION_SECRET_LENGTH = 32


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
        default="postgresql+asyncpg://sentry:sentry@localhost:5433/sentry",
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
        default=DEFAULT_SECRET_KEY,
        min_length=8,
        description="Clé de signature JWT — OBLIGATOIREMENT surchargée en production",
    )
    access_token_expire_minutes: int = 60

    # --- Connecteurs CTI externes (clés optionnelles) ------------------------
    nvd_api_key: str | None = None
    otx_api_key: str | None = None
    # Clé abuse.ch (https://auth.abuse.ch/, gratuite) : exigée par URLhaus pour les
    # téléchargements. Injectée dans les URL de flux via le gabarit {ABUSECH_AUTH_KEY}.
    abusech_auth_key: SecretStr | None = None

    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    kev_catalog_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    epss_api_url: str = "https://api.first.org/data/v1/epss"

    # --- Collecte ------------------------------------------------------------
    default_polling_interval: int = Field(default=3600, ge=60)
    http_timeout_seconds: float = Field(default=15.0, gt=0)
    http_max_retries: int = Field(default=3, ge=0, le=10)
    # Taille maximale d'une réponse de flux : au-delà, la collecte est interrompue
    # (protection mémoire contre un flux corrompu ou malveillant).
    feed_max_bytes: int = Field(default=20 * 1024 * 1024, ge=1024)

    # --- Scoring & alerting (§3.3.3 du CdC) ---------------------------------
    risk_alert_threshold: float = Field(default=75.0, ge=0, le=100)

    @model_validator(mode="after")
    def _enforce_production_safety(self) -> Self:
        """Refuse de démarrer en production avec une configuration dangereuse.

        La validation dépend de deux champs (`environment` et `secret_key`) :
        elle doit donc s'exécuter une fois le modèle entièrement construit.
        """
        if not self.is_production:
            return self
        if self.secret_key in INSECURE_SECRET_KEYS:
            raise ValueError(
                "SECRET_KEY par défaut interdite en production. "
                "Générez-en une : openssl rand -hex 32"
            )
        if len(self.secret_key) < MIN_PRODUCTION_SECRET_LENGTH:
            raise ValueError(
                f"SECRET_KEY trop courte pour la production "
                f"({len(self.secret_key)} < {MIN_PRODUCTION_SECRET_LENGTH} caractères)."
            )
        if self.debug:
            raise ValueError("DEBUG doit être désactivé en production.")
        return self

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Singleton de configuration (mis en cache pour la durée du process)."""
    return Settings()
