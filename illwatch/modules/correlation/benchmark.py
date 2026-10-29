"""Mesure de la corrélation sur un jeu de données figé : M8, incrément 4 (ADR-017, ADR-020).

`benchmark.json` (versionné) décrit des actifs, des CVE et des IOC fictifs, et la liste des
évènements attendus ; tout autre évènement produit est un faux positif. La mesure tourne
dans une base SQLite en mémoire, jamais sur la base de travail : elle est reproductible,
en CI comme sur un poste (`illwatch correlate evaluate`).

Critère de sortie de M8 : 100 % des cas attendus détectés, taux de faux positifs publié.
"""

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from illwatch.app.database import Base
from illwatch.app.models import CVE, Asset, CorrelatedEvent, Indicator, IndicatorSource, ThreatFeed
from illwatch.modules.correlation.engine import run_correlation
from illwatch.shared.enums import FeedType, Severity

DATASET = Path(__file__).with_name("benchmark.json")


@dataclass
class Evaluation:
    version: str
    expected: int
    produced: int
    true_positives: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    missed: list[str] = field(default_factory=list)
    cases: int = 0

    @property
    def recall(self) -> float:
        return len(self.true_positives) / self.expected if self.expected else 1.0

    @property
    def false_positive_rate(self) -> float:
        return len(self.false_positives) / self.produced if self.produced else 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "cases": self.cases,
            "expected": self.expected,
            "produced": self.produced,
            "recall": round(self.recall, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "false_positives": self.false_positives,
            "missed": self.missed,
        }


async def _load(session: AsyncSession, data: dict[str, Any], now: datetime) -> dict[str, str]:
    """Charge le jeu ; rend la correspondance identifiant d'IOC → valeur."""
    for spec in data["assets"]:
        session.add(
            Asset(
                name=spec["name"],
                product=spec["product"],
                vendor=spec.get("vendor"),
                version=spec.get("version"),
                criticality=spec.get("criticality", Severity.MEDIUM),
                addresses=spec.get("addresses", []),
                domains=spec.get("domains", []),
                is_active=spec.get("is_active", True),
            )
        )
    for spec in data["cves"]:
        session.add(
            CVE(
                id=spec["id"],
                description=spec["description"],
                is_kev=spec["kev"],
                has_public_exploit=spec["exploit"],
                priority=spec["priority"],
                composite_risk_score=spec["score"],
                affected=spec.get("affected"),
                published_date=now - timedelta(days=30),
                last_modified_date=now - timedelta(days=1),
            )
        )
    feeds: dict[str, ThreatFeed] = {}
    for cote in sorted({c for spec in data["iocs"] for c in spec["sources"]}):
        feeds[cote] = ThreatFeed(
            name=f"référence {cote}",
            url=f"https://benchmark.example/{cote.lower()}",
            feed_type=FeedType.CSV,
            reliability=cote,
        )
        session.add(feeds[cote])
    await session.flush()
    values: dict[str, str] = {}
    for spec in data["iocs"]:
        seen = now - timedelta(days=spec["days_ago"])
        expired = spec.get("expired", False)
        ioc = Indicator(
            type=spec["type"],
            value=spec["value"],
            severity=Severity.HIGH,
            hit_count=spec["hits"],
            first_seen=seen,
            last_seen=seen,
            expires_at=now - timedelta(hours=1) if expired else now + timedelta(days=30),
        )
        session.add(ioc)
        await session.flush()
        values[str(ioc.id)] = spec["value"]
        # Sources distinctes : une ligne par flux (deux « C » = deux flux de cote C).
        for index, cote in enumerate(spec["sources"]):
            feed = feeds[cote]
            if index > 0 and cote in spec["sources"][:index]:
                feed = ThreatFeed(
                    name=f"référence {cote} n°{index + 1} {spec['value']}",
                    url=f"https://benchmark.example/{cote.lower()}/{index}",
                    feed_type=FeedType.CSV,
                    reliability=cote,
                )
                session.add(feed)
                await session.flush()
            session.add(
                IndicatorSource(
                    indicator_id=ioc.id,
                    feed_id=feed.id,
                    first_seen=seen,
                    last_seen=seen,
                    hit_count=spec["hits"],
                )
            )
    await session.flush()
    return values


def load_dataset(path: Path = DATASET) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


async def evaluate(data: dict[str, Any] | None = None, *, min_confidence: int = 40) -> Evaluation:
    """Mesure la corrélation sur le jeu figé (par défaut `benchmark.json`)."""
    data = data if data is not None else load_dataset()
    now = datetime(2026, 10, 13, 12, 0, tzinfo=UTC)
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        async with factory() as session:
            values = await _load(session, data, now)
            await run_correlation(session, now=now, min_confidence=min_confidence)
            rows = await session.execute(
                select(
                    CorrelatedEvent.rule_id,
                    Asset.name,
                    CorrelatedEvent.cve_id,
                    CorrelatedEvent.indicator_id,
                ).join(Asset, Asset.id == CorrelatedEvent.asset_id)
            )
            produced = {
                f"{rule} · {asset} · {cve or values.get(str(ioc), str(ioc))}"
                for rule, asset, cve, ioc in rows.tuples().all()
            }
            await session.rollback()
    finally:
        await engine.dispose()
    expected = {f"{e['rule']} · {e['asset']} · {e['target']}" for e in data["expected"]}
    return Evaluation(
        version=data["version"],
        expected=len(expected),
        produced=len(produced),
        true_positives=sorted(produced & expected),
        false_positives=sorted(produced - expected),
        missed=sorted(expected - produced),
        cases=len(data["cves"]) + len(data["iocs"]),
    )
