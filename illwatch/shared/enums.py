"""Énumérations transverses : vocabulaire métier partagé par tous les modules."""

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
    """Formats de flux supportés : RF-06.

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


class SourceReliability(StrEnum):
    """Fiabilité d'une source (échelle de l'Amirauté, OTAN AJP-2.1) : M8, ADR-017.

    A : totalement fiable · B : habituellement fiable · C : assez fiable ·
    D : pas toujours fiable · E : peu fiable · F : fiabilité inconnue.
    """

    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"
    F = "F"


class IndicatorType(StrEnum):
    """Types d'IOC supportés : RF-07 / §3.3.2."""

    IPV4 = "IPV4"
    IPV6 = "IPV6"
    DOMAIN = "DOMAIN"
    URL = "URL"
    HASH_MD5 = "HASH_MD5"
    HASH_SHA1 = "HASH_SHA1"
    HASH_SHA256 = "HASH_SHA256"
    EMAIL = "EMAIL"
    NETWORK = "NETWORK"  # plage CIDR (/16 à /31 en IPv4, /32 à /127 en IPv6), ex. 203.0.113.0/24


class EnrichmentDataset(StrEnum):
    """Bases d'enrichissement hors ligne des adresses IP : M8, ADR-017 (incrément 2)."""

    COUNTRY = "country"  # plage → pays (ISO 3166-1 alpha-2)
    ASN = "asn"  # plage → système autonome et son opérateur


class CorrelationRule(StrEnum):
    """Règles de corrélation : M8, ADR-020 (incrément 3)."""

    KEV_ASSET = "CORR-01"  # CVE exploitée activement (KEV) sur un produit de l'inventaire
    EXPLOIT_ASSET = "CORR-02"  # CVE P0/P1 avec exploit public sur un produit de l'inventaire
    ASSET_IN_IOC = "CORR-03"  # adresse ou domaine de l'organisation présent dans un IOC


class SocTier(StrEnum):
    """Niveau SOC qui porte l'incident: M9 (ADR-022). L1 qualifie, L2 investigue, L3 traite
    (ingénierie de détection, réponse avancée). L'escalade ne fait que monter."""

    L1 = "L1"
    L2 = "L2"
    L3 = "L3"


class IncidentStatus(StrEnum):
    """Machine d'état à 6 étapes : RF-18 (NIST SP 800-61 Rev. 2)."""

    NOUVEAU = "NOUVEAU"
    ANALYSE = "ANALYSE"
    CONFINEMENT = "CONFINEMENT"
    ERADICATION = "ERADICATION"
    RECUPERATION = "RECUPERATION"
    CLOTURE = "CLOTURE"


class IncidentEventType(StrEnum):
    """Événements de la chronologie immuable d'un incident: RF-19."""

    CREATED = "CREATED"
    STATUS_CHANGE = "STATUS_CHANGE"
    ASSIGNED = "ASSIGNED"
    COMMENT = "COMMENT"
    IOC_ATTACHED = "IOC_ATTACHED"
    CVE_ATTACHED = "CVE_ATTACHED"
    ACTION_TAKEN = "ACTION_TAKEN"
    ESCALATED = "ESCALATED"  # M9 (ADR-022) : passage au niveau SOC supérieur
    HUNT_RUN = "HUNT_RUN"  # M9 : chasse lancée depuis l'incident
    IOC_EXCLUDED = "IOC_EXCLUDED"  # M9 : IOC qualifié de faux positif, mis en liste d'exclusion


class RiskPriority(StrEnum):
    """Grille de décision SOC : §3.3.3 du Cahier des Charges."""

    P0_CRITIQUE = "P0_CRITIQUE"
    P1_ELEVE = "P1_ELEVE"
    P2_MOYEN = "P2_MOYEN"
    P3_FAIBLE = "P3_FAIBLE"


class HuntStatus(StrEnum):
    """Session de threat hunting: RF-27."""

    EN_COURS = "EN_COURS"
    TERMINEE = "TERMINEE"
    PARTIELLE = "PARTIELLE"  # au moins une règle en échec, les autres exécutées
    ECHEC = "ECHEC"


class HuntTrigger(StrEnum):
    MANUAL = "MANUAL"
    SCHEDULED = "SCHEDULED"
    INCIDENT = "INCIDENT"  # M9 : lancée depuis un incident, sur ses IOC


class AuditOutcome(StrEnum):
    """Issue d'une action consignée au journal d'audit: M7 (ADR-011)."""

    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"  # tentative invalide (mauvais mot de passe, entrée refusée)
    DENIED = "DENIED"  # refus de sécurité (limitation de débit, droits insuffisants)


class DemoInterest(StrEnum):
    """Objet d'une demande reçue par le site de présentation (ADR-027, lot S4)."""

    DEMO = "DEMO"  # démonstration
    PILOT = "PILOT"  # pilote accompagné
    SUPPORT = "SUPPORT"  # accompagnement, intégration
    OTHER = "OTHER"


class DemoRequestStatus(StrEnum):
    NEW = "NEW"
    CONTACTED = "CONTACTED"
    CLOSED = "CLOSED"
