"""Langue des textes écrits par le serveur (ADR-027, décision 12).

Titres de corrélation, règles de chasse, recommandations de réponse, messages de la
chronologie, jeu de démonstration : ces textes sont **enregistrés** ou servis tels quels,
ils ne passent pas par les dictionnaires de l'interface. Ils suivent la langue de l'instance :

- `DEFAULT_LANGUAGE` absente ou `fr` → français (comportement historique) ;
- toute autre langue (`en`, `de`, `es`, `zh`) → **anglais**, langue commune des équipes SOC
  internationales, en attendant une traduction complète côté serveur.

Un texte déjà enregistré n'est pas réécrit si la langue de l'instance change.
"""

from typing import Literal

ServerLanguage = Literal["fr", "en"]


def server_language() -> ServerLanguage:
    from illwatch.app.config import get_settings  # import local : pas de cycle au chargement

    return "fr" if get_settings().default_language in (None, "fr") else "en"


def tr(fr: str, en: str) -> str:
    """Texte dans la langue de l'instance (français, sinon anglais)."""
    return fr if server_language() == "fr" else en
