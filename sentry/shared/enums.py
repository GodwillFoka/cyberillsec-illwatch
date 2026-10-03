"""Énumérations transverses — vocabulaire métier partagé par tous les modules."""

from enum import StrEnum


class Severity(StrEnum):
    """Sévérité générique (IOC, incident)."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class UserRole(StrEnum):
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"


class FeedType(StrEnum):
    """Formats de flux supportés — RF-06.

    `OTX` désigne l'API AlienVault OTX (pulses abonnés) : JSON paginé, clé en en-tête.
    `TAXII` désigne une collection TAXII 2.1 (objets STIX 2.1 paginés, `added_after`).
    """

    JSON = "JSON"
    CSV = "CSV"
    STIX = "STIX"
    OTX = "OTX"
    TAXII = "TAXII"


class FeedStatus(StrEnum):
    PENDING = "PENDING"
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"


class IndicatorType(StrEnum):
    """Types d'IOC supportés — RF-07 / §3.3.2."""

    IPV4 = "IPV4"
    IPV6 = "IPV6"
    DOMAIN = "DOMAIN"
    URL = "URL"
    HASH_MD5 = "HASH_MD5"
    HASH_SHA1 = "HASH_SHA1"
    HASH_SHA256 = "HASH_SHA256"
    EMAIL = "EMAIL"


class IncidentStatus(StrEnum):
    """Machine d'état à 6 étapes — RF-18 (NIST SP 800-61 Rev. 2)."""

    NOUVEAU = "NOUVEAU"
    ANALYSE = "ANALYSE"
    CONFINEMENT = "CONFINEMENT"
    ERADICATION = "ERADICATION"
    RECUPERATION = "RECUPERATION"
    CLOTURE = "CLOTURE"


class IncidentEventType(StrEnum):
    """Événements de la chronologie immuable d'un incident — RF-19."""

    CREATED = "CREATED"
    STATUS_CHANGE = "STATUS_CHANGE"
    ASSIGNED = "ASSIGNED"
    COMMENT = "COMMENT"
    IOC_ATTACHED = "IOC_ATTACHED"
    CVE_ATTACHED = "CVE_ATTACHED"
    ACTION_TAKEN = "ACTION_TAKEN"


class RiskPriority(StrEnum):
    """Grille de décision SOC — §3.3.3 du Cahier des Charges."""

    P0_CRITIQUE = "P0_CRITIQUE"
    P1_ELEVE = "P1_ELEVE"
    P2_MOYEN = "P2_MOYEN"
    P3_FAIBLE = "P3_FAIBLE"


class HuntStatus(StrEnum):
    """Session de threat hunting — RF-27."""

    EN_COURS = "EN_COURS"
    TERMINEE = "TERMINEE"
    PARTIELLE = "PARTIELLE"  # au moins une règle en échec, les autres exécutées
    ECHEC = "ECHEC"


class HuntTrigger(StrEnum):
    MANUAL = "MANUAL"
    SCHEDULED = "SCHEDULED"
