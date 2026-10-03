"""Secrets de flux : jamais en base, résolus au moment de la requête.

Certaines sources imposent une clé dans l'URL même (abuse.ch URLhaus :
`…/exports/<Auth-Key>/recent.csv`). Stocker cette URL telle quelle mettrait la clé
dans `threat_feeds.url`, lisible par tous les rôles via `GET /api/v1/feeds` et
recopiée dans les messages d'erreur.

La base stocke donc un **gabarit** : `…/exports/{ABUSECH_AUTH_KEY}/recent.csv`.
Le paramètre est remplacé par la valeur de l'environnement (`.env`) juste avant la
requête, et toute valeur secrète est masquée dans les messages enregistrés.
"""

import re
from urllib.parse import quote

from sentry.app.config import Settings

PLACEHOLDER_RE = re.compile(r"\{([A-Z][A-Z0-9_]*)\}")
MASK = "***"
MIN_MASKED_LENGTH = 8


class MissingFeedSecretError(ValueError):
    """Le gabarit d'URL réclame un secret absent de la configuration."""


KNOWN_PLACEHOLDERS = frozenset({"ABUSECH_AUTH_KEY"})


def _available(settings: Settings) -> dict[str, str | None]:
    key = settings.abusech_auth_key
    return {"ABUSECH_AUTH_KEY": key.get_secret_value() if key is not None else None}


def placeholders(url_template: str) -> list[str]:
    return PLACEHOLDER_RE.findall(url_template)


def resolve_feed_url(url_template: str, settings: Settings) -> str:
    """Remplace chaque `{NOM}` par le secret configuré, encodé pour un chemin d'URL.

    Raises:
        MissingFeedSecretError: paramètre inconnu ou secret non configuré.
    """
    values = _available(settings)

    def _substitute(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in values:
            raise MissingFeedSecretError(f"Paramètre d'URL inconnu : {{{name}}}.")
        value = values[name]
        if not value:
            raise MissingFeedSecretError(
                f"Secret {name} non configuré : renseignez-le dans .env pour collecter ce flux."
            )
        return quote(value, safe="")

    return PLACEHOLDER_RE.sub(_substitute, url_template)


def _all_secret_values(settings: Settings) -> list[str]:
    """Tous les secrets de connecteurs, y compris ceux qui ne sont jamais dans une URL
    (clé OTX, transmise en en-tête) : aucun ne doit apparaître dans un message stocké."""
    from sentry.modules.threat_feeds.taxii import taxii_secrets  # import tardif : cycle

    values = [v for v in _available(settings).values() if v]
    if settings.otx_api_key is not None and settings.otx_api_key.get_secret_value():
        values.append(settings.otx_api_key.get_secret_value())
    values.extend(taxii_secrets(settings))
    for secret in (settings.nvd_api_key, settings.alert_webhook_url):
        if secret is not None and secret.get_secret_value():
            values.append(secret.get_secret_value())
    # Un secret très court (ex. mot de passe invité « guest ») masquerait des mots ordinaires.
    return [v for v in values if len(v) >= MIN_MASKED_LENGTH]


def mask_secrets(text: str, settings: Settings) -> str:
    """Retire toute valeur secrète configurée d'un message (erreurs, journaux)."""
    for value in _all_secret_values(settings):
        if value:
            text = text.replace(value, MASK).replace(quote(value, safe=""), MASK)
    return text
