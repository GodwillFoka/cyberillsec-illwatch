"""feed names without long dash

Noms des sources de référence sans tiret long (30/10/2026) : « AlienVault OTX \u2014 pulses
abonnés » devient « AlienVault OTX : pulses abonnés » (en anglais : « AlienVault OTX: subscribed
pulses »). Seules les sources qui portent encore le nom d'origine sont renommées, et seulement si
le nouveau nom est libre : un nom modifié à la main n'est jamais touché. Données seulement, aucun
changement de schéma.

Revision ID: b6e2f4a8c1d3
Revises: a3d9e1f7c2b4
Create Date: 2026-10-30 09:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "b6e2f4a8c1d3"
down_revision: str | None = "a3d9e1f7c2b4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# (ancien nom, nouveau nom) ; le tiret long est écrit en échappement \u2014.
RENAMES: tuple[tuple[str, str], ...] = (
    (
        "abuse.ch URLhaus \u2014 URL malveillantes récentes",
        "abuse.ch URLhaus : URL malveillantes récentes",
    ),
    ("abuse.ch URLhaus \u2014 recent malicious URLs", "abuse.ch URLhaus: recent malicious URLs"),
    (
        "abuse.ch Feodo Tracker \u2014 serveurs C2 botnet",
        "abuse.ch Feodo Tracker : serveurs C2 botnet",
    ),
    (
        "abuse.ch Feodo Tracker \u2014 botnet C2 servers",
        "abuse.ch Feodo Tracker: botnet C2 servers",
    ),
    ("C2IntelFeeds \u2014 IP de serveurs C2 (30 j)", "C2IntelFeeds : IP de serveurs C2 (30 j)"),
    ("C2IntelFeeds \u2014 C2 server IPs (30 d)", "C2IntelFeeds: C2 server IPs (30 d)"),
    (
        "C2IntelFeeds \u2014 domaines de serveurs C2 (30 j)",
        "C2IntelFeeds : domaines de serveurs C2 (30 j)",
    ),
    ("C2IntelFeeds \u2014 C2 server domains (30 d)", "C2IntelFeeds: C2 server domains (30 d)"),
    (
        "IPsum \u2014 IP malveillantes (≥ 5 listes noires)",
        "IPsum : IP malveillantes (≥ 5 listes noires)",
    ),
    ("IPsum \u2014 malicious IPs (≥ 5 blocklists)", "IPsum: malicious IPs (≥ 5 blocklists)"),
    (
        "RedEye \u2014 indicateurs de menace STIX 2.1 (TAXII)",
        "RedEye : indicateurs de menace STIX 2.1 (TAXII)",
    ),
    (
        "RedEye \u2014 STIX 2.1 threat indicators (TAXII)",
        "RedEye: STIX 2.1 threat indicators (TAXII)",
    ),
    ("DigitalSide \u2014 URL malveillantes (7 j)", "DigitalSide : URL malveillantes (7 j)"),
    ("DigitalSide \u2014 malicious URLs (7 d)", "DigitalSide: malicious URLs (7 d)"),
    (
        "DigitalSide \u2014 IoC réseau STIX 2.1 (TAXII, 24 h)",
        "DigitalSide : IoC réseau STIX 2.1 (TAXII, 24 h)",
    ),
    (
        "DigitalSide \u2014 STIX 2.1 network IoCs (TAXII, 24 h)",
        "DigitalSide: STIX 2.1 network IoCs (TAXII, 24 h)",
    ),
    ("AlienVault OTX \u2014 pulses abonnés", "AlienVault OTX : pulses abonnés"),
    ("AlienVault OTX \u2014 subscribed pulses", "AlienVault OTX: subscribed pulses"),
)

_RENAME = sa.text(
    "UPDATE threat_feeds SET name = :new WHERE name = :old "
    "AND NOT EXISTS (SELECT 1 FROM threat_feeds AS t WHERE t.name = :new)"
)


def upgrade() -> None:
    connection = op.get_bind()
    for old, new in RENAMES:
        connection.execute(_RENAME, {"old": old, "new": new})


def downgrade() -> None:
    connection = op.get_bind()
    for old, new in RENAMES:
        connection.execute(_RENAME, {"old": new, "new": old})
