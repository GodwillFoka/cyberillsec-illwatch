"""Tableau de bord SOC (phase 5) : synthèse, activité, exports, API (RF-21 à RF-24)."""

import csv
import io
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import CVE, CVEAlert, CVEPriorityChange, Incident, ThreatFeed
from illwatch.app.security import create_access_token
from illwatch.modules.dashboard.service import (
    COLUMNS,
    Dataset,
    compute_summary,
    csv_lines,
    export_rows,
    recent_activity,
)
from illwatch.modules.foundation.users import create_user
from illwatch.modules.threat_feeds.indicators import Observation, ingest_indicators
from illwatch.shared.enums import (
    FeedStatus,
    FeedType,
    IncidentStatus,
    RiskPriority,
    Severity,
    UserRole,
)

NOW = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)


async def _populate(session: AsyncSession) -> None:
    session.add_all(
        [
            ThreatFeed(
                name="Saine",
                url="https://a.example.org/f",
                feed_type=FeedType.CSV,
                status=FeedStatus.HEALTHY,
                last_successful_run=NOW - timedelta(hours=1),
            ),
            ThreatFeed(
                name="En panne",
                url="https://b.example.org/f",
                feed_type=FeedType.CSV,
                status=FeedStatus.DEGRADED,
            ),
        ]
    )
    await ingest_indicators(
        session,
        [
            Observation("fresh.example.com"),
            Observation("relay.example.net", description="=cmd|' /C calc'!A0"),
        ],
        now=NOW - timedelta(hours=2),
    )
    await ingest_indicators(session, [Observation("198.51.100.9")], now=NOW - timedelta(days=60))
    for cve_id, score, priority in (
        ("CVE-2026-0001", 92.0, RiskPriority.P0_CRITIQUE),
        ("CVE-2026-0002", 65.0, RiskPriority.P1_ELEVE),
        ("CVE-2026-0003", 12.0, RiskPriority.P3_FAIBLE),
    ):
        session.add(
            CVE(
                id=cve_id,
                description=f"=HYPERLINK({cve_id})",
                published_date=NOW,
                last_modified_date=NOW,
                composite_risk_score=score,
                priority=priority,
                is_kev=score > 90,
            )
        )
    await session.flush()
    session.add(
        CVEPriorityChange(
            cve_id="CVE-2026-0001",
            old_priority="P1_ELEVE",
            new_priority="P0_CRITIQUE",
            old_score=70,
            new_score=92,
            reason="kev",
            changed_at=NOW - timedelta(hours=3),
        )
    )
    session.add(
        CVEAlert(
            cve_id="CVE-2026-0001",
            score=92,
            priority="P0_CRITIQUE",
            reason="kev",
            delivery_attempts=0,
            created_at=NOW - timedelta(hours=3),
        )
    )
    session.add_all(
        [
            Incident(
                title="Ouvert",
                description="x",
                severity=Severity.CRITICAL,
                status=IncidentStatus.ANALYSE,
                created_at=NOW - timedelta(hours=5),
            ),
            Incident(
                title="Clos",
                description="x",
                severity=Severity.LOW,
                status=IncidentStatus.CLOTURE,
                created_at=NOW - timedelta(days=3),
                closed_at=NOW - timedelta(days=2),
            ),
        ]
    )
    await session.flush()


async def test_synthese(db_session: AsyncSession) -> None:
    await _populate(db_session)
    s = await compute_summary(db_session, now=NOW)
    assert (s.iocs["total"], s.iocs["active"], s.iocs["new_24h"]) == (3, 2, 2)
    assert s.cves["by_priority"] == {
        "P0_CRITIQUE": 1,
        "P1_ELEVE": 1,
        "P2_MOYEN": 0,
        "P3_FAIBLE": 1,
    }
    assert s.cves["critical_ratio"] == round(2 / 3, 4) and s.cves["kev"] == 1
    assert s.cves["escalated_24h"] == 1
    assert s.incidents["open"] == 1 and s.incidents["open_by_severity"] == {"CRITICAL": 1}
    assert s.incidents["mttr_hours_90d"] == 24.0
    assert s.alerts["unacknowledged"] == 1 and s.alerts["undelivered"] == 1
    assert s.feeds["degraded"] == ["En panne"] and s.feeds["by_status"]["HEALTHY"] == 1
    json.dumps(s.as_dict(), default=str)  # sérialisable


async def test_base_vide(db_session: AsyncSession) -> None:
    s = await compute_summary(db_session, now=NOW)
    assert s.cves["critical_ratio"] == 0.0 and s.incidents["mttr_hours_90d"] is None
    assert await recent_activity(db_session, now=NOW) == []


async def test_activite_recente_triee(db_session: AsyncSession) -> None:
    await _populate(db_session)
    items = await recent_activity(db_session, hours=24, now=NOW)
    assert [i.at for i in items] == sorted((i.at for i in items), reverse=True)
    assert {i.kind for i in items} == {"ioc", "cve", "alert", "incident"}
    assert all(i.at >= NOW - timedelta(hours=24) for i in items)


async def test_exports_et_injection_csv(db_session: AsyncSession) -> None:
    await _populate(db_session)
    iocs = [row async for row in export_rows(db_session, Dataset.IOCS, now=NOW)]
    assert len(iocs) == 2  # l'IP expirée n'est pas exportée
    cves = [row async for row in export_rows(db_session, Dataset.CVES)]
    assert [r["id"] for r in cves] == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]
    assert cves[0]["composite_risk_score"] == 92.0 and isinstance(cves[0]["published_date"], str)

    text = "".join(csv_lines(COLUMNS[Dataset.CVES], cves))
    assert text.startswith("id,composite_risk_score,priority") and "\r\n" in text
    parsed = list(csv.DictReader(io.StringIO(text)))
    assert parsed[0]["description"].startswith("'=HYPERLINK")  # formule neutralisée
    ioc_text = "".join(csv_lines(COLUMNS[Dataset.IOCS], iocs))
    assert "'=cmd|" in ioc_text and ",=cmd" not in ioc_text


async def test_api_tableau_de_bord(client: AsyncClient, db_session: AsyncSession) -> None:
    await _populate(db_session)
    name = f"viewer-{uuid4().hex[:6]}"
    user = await create_user(
        db_session,
        username=name,
        email=f"{name}@cyberill.test",
        password="mot-de-passe-robuste-2026",
        role=UserRole.VIEWER,
    )
    headers = {"Authorization": f"Bearer {create_access_token(user.id, user.role)}"}

    summary = (await client.get("/api/v1/dashboard/summary", headers=headers)).json()
    assert summary["cves"]["kev"] == 1 and "generated_at" in summary
    recent = await client.get("/api/v1/dashboard/recent?hours=168", headers=headers)
    assert recent.status_code == 200 and len(recent.json()) >= 4

    exported = await client.get("/api/v1/dashboard/export?dataset=cves&format=csv", headers=headers)
    assert exported.status_code == 200
    assert exported.headers["content-type"].startswith("text/csv")
    assert 'filename="illwatch-cves-' in exported.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(exported.text)))
    assert rows[0][0] == "id" and len(rows) == 4

    as_json: Any = (
        await client.get("/api/v1/dashboard/export?dataset=incidents&format=json", headers=headers)
    ).json()
    assert {i["title"] for i in as_json} == {"Ouvert", "Clos"}
    empty = await client.get("/api/v1/dashboard/export?dataset=alerts&format=json", headers=headers)
    assert len(empty.json()) == 1
    assert (
        await client.get("/api/v1/dashboard/export?dataset=x", headers=headers)
    ).status_code == 422
    assert (await client.get("/api/v1/dashboard/summary")).status_code == 401


# --- Export sur gros volume (07/10 : 89 s pour 300 000 IOC) ------------------------------------


async def test_export_pagine_par_cle_sans_perte_ni_doublon(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pages de 2 lignes : chaque ligne une seule fois, dans l'ordre, ex æquo compris."""
    from illwatch.modules.dashboard import service

    monkeypatch.setattr(service, "EXPORT_CHUNK", 2)
    await ingest_indicators(
        db_session, [Observation(f"h{i}.example.org") for i in range(7)], now=NOW
    )
    scores = [80.0, 80.0, 80.0, 50.0, 50.0, 10.0, 10.0]  # ex æquo à cheval sur deux pages
    for i, score in enumerate(scores):
        db_session.add(
            CVE(
                id=f"CVE-2026-1{i:03d}",
                description="x",
                published_date=NOW,
                last_modified_date=NOW,
                composite_risk_score=score,
                priority=RiskPriority.P2_MOYEN,
            )
        )
    await db_session.flush()

    iocs = [row async for row in export_rows(db_session, Dataset.IOCS, now=NOW)]
    ids = [r["id"] for r in iocs]
    assert len(ids) == 7 and len(set(ids)) == 7 and ids == sorted(ids)

    cves = [row async for row in export_rows(db_session, Dataset.CVES)]
    assert [r["id"] for r in cves] == [f"CVE-2026-1{i:03d}" for i in range(7)]
    assert [r["composite_risk_score"] for r in cves] == scores


async def test_flux_regroupe_les_lignes(monkeypatch: pytest.MonkeyPatch) -> None:
    from illwatch.modules.dashboard import service

    monkeypatch.setattr(service, "STREAM_BATCH", 3)

    async def rows() -> AsyncIterator[dict[str, Any]]:
        for i in range(10):
            yield {"id": i, "value": f"v{i}"}

    chunks = [c async for c in service.csv_stream(("id", "value"), rows())]
    assert len(chunks) == 4  # en-tête + 10 lignes, par 3
    assert list(csv.reader(io.StringIO("".join(chunks))))[-1] == ["9", "v9"]
    as_json = "".join([c async for c in service.json_stream(rows())])
    assert [r["id"] for r in json.loads(as_json)] == list(range(10))
    assert "".join([c async for c in service.json_stream(_empty())]) == "[]"


async def _empty() -> AsyncIterator[dict[str, Any]]:
    return
    yield {}
