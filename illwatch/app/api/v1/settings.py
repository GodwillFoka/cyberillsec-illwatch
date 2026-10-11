"""Paramètres en vigueur — `GET /api/v1/settings` (ADMIN), écran Administration.

Lecture seule : la configuration se change dans `.env` (12-factor) puis au redémarrage. Aucun
secret n'est renvoyé, seulement sa **présence** (clé NVD configurée : oui/non).
"""

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from illwatch.app.api.deps import require_roles
from illwatch.app.config import get_settings
from illwatch.app.models import User
from illwatch.modules.cve_tracker.scoring import remediation_sla_hours
from illwatch.shared.enums import RiskPriority, UserRole

router = APIRouter(prefix="/settings", tags=["administration"])

AdminUser = Annotated[User, Depends(require_roles(UserRole.ADMIN))]


class SettingsRead(BaseModel):
    version: str
    environment: str
    access_token_minutes: int
    refresh_token_days: int
    login_max_failures: int
    login_window_seconds: int
    default_polling_interval: int
    worker_tick_seconds: int
    cve_sync_interval_seconds: int
    hunt_interval_seconds: int
    risk_alert_threshold: float
    remediation_sla_hours: dict[str, int]
    feed_max_bytes: int
    http_timeout_seconds: float
    docs_enabled: bool
    hsts_enabled: bool
    secrets_configured: dict[str, bool]


@router.get("", response_model=SettingsRead, summary="Paramètres en vigueur (ADMIN, sans secret)")
async def read_settings(_: AdminUser) -> SettingsRead:
    s = get_settings()
    return SettingsRead(
        version=s.app_version,
        environment=s.environment,
        access_token_minutes=s.access_token_expire_minutes,
        refresh_token_days=s.refresh_token_expire_days,
        login_max_failures=s.login_max_failures,
        login_window_seconds=s.login_window_seconds,
        default_polling_interval=s.default_polling_interval,
        worker_tick_seconds=s.worker_tick_seconds,
        cve_sync_interval_seconds=s.cve_sync_interval_seconds,
        hunt_interval_seconds=s.hunt_interval_seconds,
        risk_alert_threshold=s.risk_alert_threshold,
        remediation_sla_hours={p.value: remediation_sla_hours(p) for p in RiskPriority},
        feed_max_bytes=s.feed_max_bytes,
        http_timeout_seconds=s.http_timeout_seconds,
        docs_enabled=s.expose_docs,
        hsts_enabled=s.send_hsts,
        secrets_configured={
            "nvd_api_key": s.nvd_api_key is not None,
            "otx_api_key": s.otx_api_key is not None,
            "abusech_auth_key": s.abusech_auth_key is not None,
            "alert_webhook_url": s.alert_webhook_url is not None,
            "secret_key_previous": s.secret_key_previous is not None,
        },
    )
