"""Journal structuré JSON — UC-01 étape 8, RNF d'exploitabilité.

Une ligne JSON par événement, sur la sortie d'erreur : lisible par `jq`, par journald
et par n'importe quel collecteur (Loki, Elastic, Graylog) sans analyseur dédié.

    {"ts": "2026-09-28T14:00:03.412Z", "level": "INFO", "logger": "sentry.collector",
     "event": "feed.collected", "feed_name": "…", "inserted": 12, "duration_ms": 840}

Les champs métier passent par `extra={"fields": {...}}` : ils restent des valeurs
typées (nombres, booléens) au lieu d'être noyés dans une phrase.
"""

import json
import logging
import sys
from datetime import UTC, datetime
from typing import IO, Any

_HANDLER_NAME = "sentry-json"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            payload.update(fields)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


def configure_logging(level: str = "INFO", *, stream: IO[str] | None = None) -> None:
    """Installe (ou remplace) le gestionnaire JSON du journal `sentry`.

    Idempotent : un second appel remplace le gestionnaire précédent au lieu d'en
    empiler un autre (chaque ligne serait sinon écrite plusieurs fois).
    """
    logger = logging.getLogger("sentry")
    for handler in [h for h in logger.handlers if h.get_name() == _HANDLER_NAME]:
        logger.removeHandler(handler)
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.set_name(_HANDLER_NAME)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False


def peak_rss_mb() -> float | None:
    """Pic de mémoire résidente du processus, en Mo (RNF-MEM-01 : cible ≤ 256 Mo).

    `None` là où la mesure n'existe pas (Windows : pas de module `resource`).
    """
    try:
        import resource
    except ImportError:  # pragma: no cover - Windows
        return None
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux : kilo-octets ; macOS : octets.
    divisor = 1024 * 1024 if sys.platform == "darwin" else 1024
    return round(usage / divisor, 1)
