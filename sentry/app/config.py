"""Configuration applicative immuable — RF-01.

Toute la configuration est chargée depuis l'environnement (ou un fichier `.env`)
et validée par Pydantic au démarrage. Aucune requête applicative ne doit
s'exécuter si la validation échoue (règle de gestion MOD-01).
"""

import os
from functools import lru_cache
from typing import Literal, Self
from urllib.parse import unquote, urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from sentry import __version__

DEFAULT_SECRET_KEY = "change-me-in-production"  # noqa: S105 - sentinelle refusée en prod
INSECURE_SECRET_KEYS = frozenset({DEFAULT_SECRET_KEY, "changeme", "secret", "sentry"})
MIN_PRODUCTION_SECRET_LENGTH = 32
INSECURE_REDIS_PASSWORDS = frozenset({"sentry-dev-redis", "redis", "password", "changeme"})
INSECURE_DB_PASSWORDS = frozenset({"sentry", "sentry-app-dev", "postgres", "password", "changeme"})
ENV_FILE_VARIABLE = "SENTRY_ENV_FILE"


def _env_file() -> str | None:
    """Fichier de configuration lu au démarrage : `.env` par défaut.

    `SENTRY_ENV_FILE=/etc/sentry/env` désigne un autre fichier ; `SENTRY_ENV_FILE=` (vide)
    n'en lit aucun. La suite de tests et `scripts/ci-local.sh` s'en servent : un `.env` de
    développement ne doit jamais rediriger les tests (ni leurs migrations) vers une autre base.
    """
    value = os.environ.get(ENV_FILE_VARIABLE, ".env")
    return value or None


class Settings(BaseSettings):
    """Variables d'environnement typées de SENTRY."""

    model_config = SettingsConfigDict(
        env_file=_env_file(),
        env_file_encoding="utf-8",
        # `DOCS_ENABLED=` (vide, comme dans .env.example) vaut « non défini » : valeur par défaut.
        # Sans cette règle, une variable vide faisait échouer la validation au démarrage.
        env_ignore_empty=True,
        case_sensitive=False,
        extra="ignore",
        frozen=True,
    )

    # --- Application ---------------------------------------------------------
    app_name: str = "SENTRY"
    app_version: str = __version__  # source unique : sentry/__init__.py
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
    # M7 lot 2 — séparation des rôles PostgreSQL. `DATABASE_URL` sert l'application (rôle
    # sans droit de structure) ; `MIGRATION_DATABASE_URL`, s'il est défini, sert Alembic avec
    # le rôle propriétaire des tables. `DATABASE_APP_ROLE` : rôle à qui `sentry db upgrade`
    # réapplique les droits minimaux après chaque migration.
    migration_database_url: str | None = None
    database_app_role: str | None = Field(default=None, pattern=r"^[a-z_][a-z0-9_]{0,62}$")

    # --- Cache / Broker ------------------------------------------------------
    redis_url: str = "redis://localhost:6379/0"  # production : mot de passe obligatoire

    # --- API -----------------------------------------------------------------
    api_v1_prefix: str = "/api/v1"
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])
    # Documentation interactive (/docs, /redoc, /openapi.json). Par défaut : exposée hors
    # production, masquée en production (surface d'attaque, inventaire des routes).
    docs_enabled: bool | None = None
    # En-tête HSTS : par défaut en production uniquement (l'API y est servie derrière TLS).
    hsts_enabled: bool | None = None

    # --- Sécurité ------------------------------------------------------------
    secret_key: str = Field(
        default=DEFAULT_SECRET_KEY,
        min_length=8,
        description="Clé de signature JWT — OBLIGATOIREMENT surchargée en production",
    )
    # Rotation (M7 lot 2) : l'ancienne clé reste acceptée en vérification, jamais en signature,
    # le temps que les jetons émis avec elle expirent.
    secret_key_previous: SecretStr | None = None
    # Jeton d'accès court + jeton de rafraîchissement révocable (M7 lot 2).
    access_token_expire_minutes: int = Field(default=15, ge=1, le=24 * 60)
    refresh_token_expire_days: int = Field(default=7, ge=1, le=90)
    # Force brute : échecs de connexion tolérés par identifiant sur la fenêtre (secondes).
    login_max_failures: int = Field(default=5, ge=1, le=100)
    login_window_seconds: int = Field(default=900, ge=60)

    # --- Connecteurs CTI externes (clés optionnelles) ------------------------
    # Clé NVD (https://nvd.nist.gov/developers/request-an-api-key, gratuite) : 50 requêtes
    # par 30 s au lieu de 5. Envoyée en en-tête `apiKey`, jamais en base.
    nvd_api_key: SecretStr | None = None
    # Clé AlienVault OTX (https://otx.alienvault.com/, gratuite) : envoyée en en-tête
    # X-OTX-API-KEY, uniquement vers otx.alienvault.com. Jamais en base.
    otx_api_key: SecretStr | None = None
    # Plafond de pages de 50 pulses lues par collecte OTX (mémoire et durée bornées).
    otx_max_pages: int = Field(default=20, ge=1, le=200)
    # Identifiants TAXII 2.1 par hôte : "hote=utilisateur:motdepasse;hote2=…". Envoyés en
    # Basic uniquement à l'hôte nommé. Valeur par défaut : accès invité public documenté
    # de DigitalSide (https://osint.digitalside.it/taxiiserver.html).
    taxii_auth: SecretStr = SecretStr("osint.digitalside.it=guest:guest")
    taxii_max_pages: int = Field(default=20, ge=1, le=200)
    # Client TAXII : `library` = taxii2-client (OASIS, défaut) ; `builtin` = transport HTTP
    # maison (async), repli si un serveur sort des clous de la bibliothèque.
    taxii_client: Literal["library", "builtin"] = "library"
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
    # Durée de vie d'un verrou de collecte (Redis) : doit dépasser la plus longue collecte.
    collect_lock_ttl_seconds: int = Field(default=900, ge=60)
    # Période de réveil de `sentry feeds worker` (recherche des flux échus).
    worker_tick_seconds: int = Field(default=60, ge=5)

    # --- Moteur CVE (phase 3, ADR-007) --------------------------------------
    # Profondeur de la première synchronisation NVD (CVE modifiées depuis N jours) ;
    # les CVE du catalogue KEV sont toujours importées, quelle que soit leur date.
    nvd_initial_days: int = Field(default=30, ge=1, le=3650)
    nvd_results_per_page: int = Field(default=500, ge=1, le=2000)
    # Période de synchronisation CVE par le worker (KEV + NVD incrémental + EPSS).
    cve_sync_interval_seconds: int = Field(default=6 * 3600, ge=600)

    # --- Threat hunting (phase 6, ADR-009) ----------------------------------
    # Liste officielle des relais de sortie Tor (RULE-01), texte, une IP par ligne.
    tor_exit_list_url: str = "https://check.torproject.org/torbulkexitlist"
    # Chasse planifiée sur la base d'IOC par le worker (s) ; 0 = désactivée.
    hunt_interval_seconds: int = Field(default=24 * 3600, ge=0)

    # --- Scoring & alerting (§3.3.3 du CdC) ---------------------------------
    risk_alert_threshold: float = Field(default=75.0, ge=0, le=100)
    # Webhook (Slack, Mattermost, Teams via passerelle…) appelé à chaque alerte. Configuré
    # par l'exploitant dans `.env` : il peut viser un relais interne. Jamais journalisé.
    alert_webhook_url: SecretStr | None = None

    @field_validator(
        "secret_key_previous", "migration_database_url", "database_app_role", mode="before"
    )
    @classmethod
    def _empty_is_unset(cls, value: object) -> object:
        """`SECRET_KEY_PREVIOUS=` (vide, comme dans .env.example) vaut « non défini ».

        Sans cette règle, une clé précédente vide serait acceptée en vérification : n'importe
        qui pourrait signer un jeton avec la chaîne vide.
        """
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("secret_key_previous")
    @classmethod
    def _previous_key_length(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and len(value.get_secret_value()) < 16:
            raise ValueError("SECRET_KEY_PREVIOUS trop courte (16 caractères au moins).")
        return value

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
        previous = self.secret_key_previous
        if previous is not None and len(previous.get_secret_value()) < MIN_PRODUCTION_SECRET_LENGTH:
            raise ValueError("SECRET_KEY_PREVIOUS trop courte pour la production.")
        db_password = unquote(urlsplit(self.database_url).password or "")
        if self.database_url.startswith("postgresql") and (
            not db_password or db_password in INSECURE_DB_PASSWORDS
        ):
            raise ValueError(
                "DATABASE_URL sans mot de passe ou avec un mot de passe de développement "
                "interdit en production."
            )
        redis_password = urlsplit(self.redis_url).password
        if not redis_password or redis_password in INSECURE_REDIS_PASSWORDS:
            raise ValueError(
                "REDIS_URL sans mot de passe (ou mot de passe de développement) interdit en "
                "production : redis://:MOT_DE_PASSE@hote:6379/0"
            )
        if "*" in self.cors_origins:
            raise ValueError(
                "CORS_ORIGINS='*' interdit en production : les requêtes portent un jeton."
            )
        return self

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def expose_docs(self) -> bool:
        return not self.is_production if self.docs_enabled is None else self.docs_enabled

    @property
    def send_hsts(self) -> bool:
        return self.is_production if self.hsts_enabled is None else self.hsts_enabled


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Singleton de configuration (mis en cache pour la durée du process)."""
    return Settings()
