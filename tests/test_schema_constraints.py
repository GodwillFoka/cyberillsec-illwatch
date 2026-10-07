"""Intégrité du schéma MOD-02 : contraintes CHECK, expiration des IOC, conservation des IOC.

La validation applicative (`validators.py`, schémas Pydantic) filtre les entrées ; la base
garantit l'intégrité même si un chemin de code l'oublie. Ces tests vérifient la seconde
barrière, indépendamment de la première.
"""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.database import Base
from illwatch.app.models import Indicator, ThreatFeed
from illwatch.shared.enums import FeedType, IndicatorType, Severity

NOW = datetime.now(UTC)


def _ioc(**overrides: object) -> Indicator:
    fields: dict[str, object] = {
        "type": IndicatorType.IPV4,
        "value": "203.0.113.7",
        "severity": Severity.HIGH,
        "first_seen": NOW,
        "last_seen": NOW,
    }
    fields.update(overrides)
    return Indicator(**fields)


@pytest.mark.parametrize(
    "obj",
    [
        pytest.param(lambda: _ioc(type="IP"), id="type-inconnu"),
        pytest.param(lambda: _ioc(severity="URGENT"), id="severite-inconnue"),
        pytest.param(
            lambda: ThreatFeed(name="f", url="https://a.example.org/f", feed_type="XML"),
            id="format-inconnu",
        ),
        pytest.param(
            lambda: ThreatFeed(
                name="f", url="https://a.example.org/f", feed_type=FeedType.CSV, status="OK"
            ),
            id="statut-inconnu",
        ),
    ],
)
async def test_valeurs_hors_enumeration_refusees_par_la_base(
    db_session: AsyncSession, obj: object
) -> None:
    db_session.add(obj())  # type: ignore[operator]
    with pytest.raises(IntegrityError, match="(?i)check"):
        async with db_session.begin_nested():
            await db_session.flush()


async def test_expires_at_facultatif_et_persiste(db_session: AsyncSession) -> None:
    permanent = _ioc(type=IndicatorType.HASH_SHA256, value="a" * 64)
    ephemere = _ioc(expires_at=NOW + timedelta(days=30))
    db_session.add_all([permanent, ephemere])
    await db_session.flush()

    rows = {i.value: i.expires_at for i in (await db_session.execute(select(Indicator))).scalars()}
    assert rows["a" * 64] is None
    stored = rows["203.0.113.7"]
    assert stored is not None
    assert abs(stored.replace(tzinfo=UTC) - (NOW + timedelta(days=30))) < timedelta(seconds=1)


@pytest.mark.postgres
async def test_suppression_d_un_flux_conserve_ses_ioc_en_base(db_session: AsyncSession) -> None:
    """ON DELETE SET NULL appliqué par PostgreSQL lui-même, sans passer par l'ORM."""
    feed = ThreatFeed(name="Source", url="https://a.example.org/f.csv", feed_type=FeedType.CSV)
    db_session.add(feed)
    await db_session.flush()
    db_session.add(_ioc(feed_id=feed.id))
    await db_session.flush()

    await db_session.execute(delete(ThreatFeed).where(ThreatFeed.id == feed.id))
    db_session.expire_all()
    ioc = (await db_session.execute(select(Indicator))).scalar_one()
    assert ioc.feed_id is None


@pytest.mark.postgres
async def test_contraintes_check_identiques_entre_modele_et_base(
    db_session: AsyncSession,
) -> None:
    """`alembic check` ne compare pas les contraintes CHECK : ce test comble ce trou.

    Chaque CHECK déclarée dans le modèle doit exister en base sous le même nom, et
    autoriser exactement les mêmes valeurs.
    """
    rows = await db_session.execute(
        text(
            "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE contype = 'c' AND conrelid::regclass::text IN ('indicators', 'threat_feeds')"
        )
    )
    in_db = {str(row[0]): str(row[1]) for row in rows.all()}

    declared = {
        c.name: str(c.sqltext)
        for table in ("indicators", "threat_feeds")
        for c in Base.metadata.tables[table].constraints
        if c.__class__.__name__ == "CheckConstraint"
    }
    assert set(declared) == set(in_db)
    for name, expression in declared.items():
        allowed = {v.strip(" '") for v in expression.split("(", 1)[1].rstrip(")").split(",")}
        for value in allowed:
            assert f"'{value}'" in in_db[name], (name, value)
