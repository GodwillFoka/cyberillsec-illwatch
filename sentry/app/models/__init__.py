"""Modèles relationnels SQLAlchemy — §4.4 du Cahier des Charges.

L'import de tous les modèles ici garantit qu'Alembic découvre l'intégralité du
métamodèle via `Base.metadata`.
"""

from sentry.app.models.cve import CVE, CollectorState, CVEAlert, CVEPriorityChange
from sentry.app.models.hunting import HuntingMatch, HuntingSession
from sentry.app.models.incident import Incident, IncidentCVE, IncidentEvent, IncidentIndicator
from sentry.app.models.threat_feed import Indicator, IndicatorSource, ThreatFeed
from sentry.app.models.user import User

__all__ = [
    "CVE",
    "CVEAlert",
    "CVEPriorityChange",
    "CollectorState",
    "HuntingMatch",
    "HuntingSession",
    "Incident",
    "IncidentCVE",
    "IncidentEvent",
    "IncidentIndicator",
    "Indicator",
    "IndicatorSource",
    "ThreatFeed",
    "User",
]
