"""Modèles relationnels SQLAlchemy — §4.4 du Cahier des Charges.

L'import de tous les modèles ici garantit qu'Alembic découvre l'intégralité du
métamodèle via `Base.metadata`.
"""

from illwatch.app.models.audit import AuditEvent
from illwatch.app.models.cve import CVE, CollectorState, CVEAlert, CVEPriorityChange
from illwatch.app.models.hunting import HuntingMatch, HuntingSession
from illwatch.app.models.incident import Incident, IncidentCVE, IncidentEvent, IncidentIndicator
from illwatch.app.models.refresh_token import RefreshToken
from illwatch.app.models.threat_feed import CollectionRun, Indicator, IndicatorSource, ThreatFeed
from illwatch.app.models.user import User

__all__ = [
    "AuditEvent",
    "CVE",
    "CVEAlert",
    "CVEPriorityChange",
    "CollectionRun",
    "CollectorState",
    "HuntingMatch",
    "HuntingSession",
    "Incident",
    "IncidentCVE",
    "IncidentEvent",
    "IncidentIndicator",
    "Indicator",
    "IndicatorSource",
    "RefreshToken",
    "ThreatFeed",
    "User",
]
