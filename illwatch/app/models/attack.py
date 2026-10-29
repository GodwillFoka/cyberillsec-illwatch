"""Référentiel MITRE ATT&CK (Enterprise) : M10, ADR-023.

Importé depuis le bundle STIX 2.1 publié par MITRE (`illwatch attack import`) : techniques
(et sous-techniques), groupes d'attaquants et logiciels malveillants, et les relations
« utilise » qui les relient. Lecture seule pour l'application ; réimporté à chaque nouvelle
version d'ATT&CK. © The MITRE Corporation, reproduit avec son autorisation (conditions
d'utilisation d'ATT&CK).
"""

from sqlalchemy import JSON, Boolean, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from illwatch.app.database import Base


class AttackTechnique(Base):
    __tablename__ = "attack_techniques"

    id: Mapped[str] = mapped_column(String(16), primary_key=True)  # T1190, T1568.002
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    tactics: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class AttackActor(Base):
    """Groupe d'attaquants (G…) ou logiciel (S…, malware ou outil)."""

    __tablename__ = "attack_actors"

    id: Mapped[str] = mapped_column(String(16), primary_key=True)  # G0102, S0650
    kind: Mapped[str] = mapped_column(String(10), nullable=False)  # group | malware | tool
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    aliases: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)


class AttackUse(Base):
    """Relation « utilise » : un groupe ou un logiciel emploie une technique."""

    __tablename__ = "attack_uses"
    __table_args__ = (Index("ix_attack_uses_technique", "technique_id"),)

    actor_id: Mapped[str] = mapped_column(
        ForeignKey("attack_actors.id", ondelete="CASCADE"), primary_key=True
    )
    technique_id: Mapped[str] = mapped_column(
        ForeignKey("attack_techniques.id", ondelete="CASCADE"), primary_key=True
    )
