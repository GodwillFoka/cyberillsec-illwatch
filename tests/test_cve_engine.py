"""Moteur CVE (phase 3) : analyse NVD / KEV / EPSS, synchronisation, recalcul, alertes."""

import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentry.app.config import Settings
from sentry.app.models import CVE, CollectorState, CVEAlert, CVEPriorityChange
from sentry.modules.cve_tracker.alerts import (
    MAX_DELIVERY_ATTEMPTS,
    AlertNotFoundError,
    acknowledge,
    alert_payload,
    deliver_pending,
)
from sentry.modules.cve_tracker.engine import cve_sync_due, mark_cve_sync_attempt, sync_cves
from sentry.modules.cve_tracker.sources import (
    fetch_epss,
    fetch_nvd,
    nvd_windows,
    parse_epss,
    parse_kev,
    parse_nvd_page,
)
from sentry.modules.threat_feeds.fetcher import FetchError
from sentry.modules.threat_feeds.parsers import FeedParseError
from sentry.shared.enums import RiskPriority

FIXTURES = Path(__file__).parent / "fixtures" / "cve"
T0 = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)


def _bytes(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _settings(**kw: Any) -> Settings:
    return Settings(secret_key="k" * 64, **kw)


async def _no_sleep(_: float) -> None:
    return None


# --- Analyse -------------------------------------------------------------------


def test_page_nvd() -> None:
    page = parse_nvd_page(_bytes("nvd_page.json"))
    assert page.total == 4 and page.rejected == 1  # CVE « Rejected »
    log4j, cms, lib = page.records
    assert log4j.id == "CVE-2021-44228"
    assert (log4j.cvss_score, log4j.has_public_exploit) == (10.0, True)
    assert log4j.cvss_vector is not None and log4j.cvss_vector.startswith("CVSS:3.1/")
    assert log4j.description.startswith("Apache Log4j2")  # description anglaise
    assert log4j.published == datetime(2021, 12, 10, 10, 15, 9, 143000, tzinfo=UTC)
    assert str(log4j.kev_date_added) == "2021-12-10"
    # Sans CVSS v3, la v4.0 du CNA est retenue ; la version reste lisible dans le vecteur.
    assert cms.cvss_score == 9.3 and cms.cvss_vector is not None
    assert cms.cvss_vector.startswith("CVSS:4.0/")
    assert not cms.has_public_exploit
    # L'évaluation du NVD (« Primary ») prime sur celle du CNA.
    assert lib.cvss_score == 3.7


@pytest.mark.parametrize("content", [b"{", b'{"message": "rate limited"}'])
def test_reponse_nvd_illisible(content: bytes) -> None:
    with pytest.raises(FeedParseError):
        parse_nvd_page(content)


def test_fenetres_de_120_jours() -> None:
    windows = list(nvd_windows(T0 - timedelta(days=300), T0))
    assert len(windows) == 3
    assert windows[0][1] - windows[0][0] == timedelta(days=120)
    assert windows[-1][1] == T0
    assert list(nvd_windows(T0, T0)) == []


def test_catalogue_kev() -> None:
    catalog = parse_kev(_bytes("kev.json"))
    assert set(catalog) == {"CVE-2021-44228", "CVE-2020-1472"}
    assert catalog["CVE-2021-44228"].ransomware is True
    assert catalog["CVE-2020-1472"].ransomware is False
    assert catalog["CVE-2020-1472"].description.startswith("Microsoft Netlogon")
    with pytest.raises(FeedParseError, match="vide"):
        parse_kev(b'{"vulnerabilities": []}')


def test_scores_epss() -> None:
    scores = parse_epss(_bytes("epss.json"))
    assert scores["CVE-2021-44228"].score == pytest.approx(0.94424)
    assert scores["CVE-2020-1472"].percentile == pytest.approx(0.9998)
    bad = b'{"data": [{"cve": "CVE-1", "epss": "abc", "percentile": "0.1"}, {"cve": "CVE-2"}]}'
    assert parse_epss(bad) == {}


class _Recorder:
    def __init__(self, pages: list[bytes]) -> None:
        self.pages = pages
        self.calls: list[tuple[str, Mapping[str, str] | None]] = []

    async def __call__(self, url: str, *, headers: Mapping[str, str] | None = None) -> bytes:
        self.calls.append((url, headers))
        return self.pages[min(len(self.calls), len(self.pages)) - 1]


def _nvd(total: int, ids: list[str]) -> bytes:
    return json.dumps(
        {
            "totalResults": total,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": i,
                        "published": "2026-09-01T00:00:00.000",
                        "lastModified": "2026-09-02T00:00:00.000",
                        "descriptions": [{"lang": "en", "value": i}],
                        "metrics": {},
                        "references": [],
                    }
                }
                for i in ids
            ],
        }
    ).encode()


async def test_pagination_nvd_et_debit_sans_cle() -> None:
    fetch = _Recorder([_nvd(3, ["CVE-2026-1", "CVE-2026-2"]), _nvd(3, ["CVE-2026-3"])])
    pauses: list[float] = []

    async def sleep(seconds: float) -> None:
        pauses.append(seconds)

    seen: list[str] = []

    async def on_page(page: Any) -> None:
        seen.extend(r.id for r in page.records)

    received = await fetch_nvd(
        _settings(nvd_results_per_page=2),
        fetch,
        sleep,
        window=(T0 - timedelta(days=1), T0),
        on_page=on_page,
    )
    assert received == 3 and seen == ["CVE-2026-1", "CVE-2026-2", "CVE-2026-3"]
    assert pauses == [6.0]  # 5 requêtes / 30 s sans clé
    assert "startIndex=2" in fetch.calls[1][0]
    assert "lastModStartDate=2026-09-28T12%3A00%3A00.000%2B00%3A00" in fetch.calls[0][0]
    assert all("apiKey" not in (h or {}) for _, h in fetch.calls)


async def test_cle_nvd_en_en_tete_et_filtre_kev() -> None:
    fetch = _Recorder([_nvd(1, ["CVE-2026-1"])])

    async def on_page(page: Any) -> None:
        return None

    await fetch_nvd(
        _settings(nvd_api_key=SecretStr("cle-nvd-0123456789")),
        fetch,
        _no_sleep,
        has_kev=True,
        on_page=on_page,
    )
    url, headers = fetch.calls[0]
    assert url.endswith("&hasKev") and "cle-nvd" not in url
    assert headers is not None and headers["apiKey"] == "cle-nvd-0123456789"


async def test_epss_par_lots_de_100() -> None:
    fetch = _Recorder([_bytes("epss.json")])
    ids = [f"CVE-2026-{i}" for i in range(250)]
    await fetch_epss(_settings(), fetch, _no_sleep, ids)
    assert len(fetch.calls) == 3
    assert fetch.calls[0][0].count("CVE-2026-") == 100


# --- Synchronisation -----------------------------------------------------------


class _Sources:
    """Faux NVD / KEV / EPSS, modifiables entre deux synchronisations."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.kev = json.loads(_bytes("kev.json"))
        self.epss = json.loads(_bytes("epss.json"))
        self.nvd = _bytes("nvd_page.json")
        self.fail: set[str] = set()

    async def __call__(self, url: str, *, headers: Mapping[str, str] | None = None) -> bytes:
        for name, prefix in (
            ("kev", self.settings.kev_catalog_url),
            ("nvd", self.settings.nvd_api_url),
            ("epss", self.settings.epss_api_url),
        ):
            if url.startswith(prefix):
                if name in self.fail:
                    raise FetchError(f"HTTP 503 renvoyé par {name}")
                if name == "nvd":
                    return self.nvd
                return json.dumps(self.kev if name == "kev" else self.epss).encode()
        raise AssertionError(url)


async def _cve(session: AsyncSession, cve_id: str) -> CVE:
    cve = await session.get(CVE, cve_id, populate_existing=True)
    assert cve is not None
    return cve


async def test_premiere_synchro_ligne_de_base_sans_alerte(db_session: AsyncSession) -> None:
    settings = _settings()
    report = await sync_cves(
        db_session, settings=settings, fetch=_Sources(settings), sleep=_no_sleep, clock=lambda: T0
    )

    assert report.succeeded and report.baseline
    assert (report.kev, report.epss, report.alerts) == (2, 4, 0)
    assert report.created == 4  # 3 CVE NVD + Netlogon créée depuis le catalogue KEV

    log4j = await _cve(db_session, "CVE-2021-44228")
    assert log4j.is_kev and log4j.has_ransomware_campaign and log4j.has_public_exploit
    assert float(log4j.composite_risk_score) >= 80
    assert log4j.priority == RiskPriority.P0_CRITIQUE

    netlogon = await _cve(db_session, "CVE-2020-1472")
    assert netlogon.cvss_score is None and netlogon.is_kev
    assert float(netlogon.composite_risk_score) == pytest.approx(48.58, abs=0.01)
    assert netlogon.priority == RiskPriority.P2_MOYEN

    assert await db_session.get(CVE, "CVE-2026-10002") is None  # rejetée par le NVD
    nvd = await db_session.get(CollectorState, "nvd")
    assert nvd is not None and nvd.cursor is not None and nvd.last_error is None
    history = (
        (
            await db_session.execute(
                select(CVEPriorityChange)
                .where(CVEPriorityChange.cve_id == "CVE-2021-44228")
                .order_by(CVEPriorityChange.changed_at, CVEPriorityChange.new_score)
            )
        )
        .scalars()
        .all()
    )
    # Créée par le KEV, complétée par le NVD, puis par l'EPSS : chaque étape est tracée.
    assert [(h.old_priority, h.new_priority, h.reason) for h in history] == [
        (None, "P3_FAIBLE", "kev"),
        ("P3_FAIBLE", "P1_ELEVE", "nvd"),
        ("P1_ELEVE", "P0_CRITIQUE", "epss"),
    ]
    assert (await db_session.execute(select(CVEAlert))).first() is None


async def test_franchissement_du_seuil_alerte_et_historise(db_session: AsyncSession) -> None:
    settings = _settings(risk_alert_threshold=75)
    sources = _Sources(settings)
    await sync_cves(db_session, settings=settings, fetch=sources, sleep=_no_sleep, clock=lambda: T0)

    # La CISA ajoute la faille du CMS au KEV (ransomware), puis l'EPSS s'envole.
    sources.kev["vulnerabilities"].append(
        {
            "cveID": "CVE-2026-10001",
            "vulnerabilityName": "ExampleCMS SQL Injection",
            "dateAdded": "2026-09-29",
            "shortDescription": "SQL injection.",
            "requiredAction": "Apply mitigations.",
            "dueDate": "2026-10-20",
            "knownRansomwareCampaignUse": "Known",
        }
    )
    sources.epss["data"][1]["epss"] = "0.970000000"
    sources.nvd = _nvd(0, [])
    later = T0 + timedelta(hours=6)
    report = await sync_cves(
        db_session, settings=settings, fetch=sources, sleep=_no_sleep, clock=lambda: later
    )

    assert report.succeeded and not report.baseline
    cms = await _cve(db_session, "CVE-2026-10001")
    assert cms.is_kev and cms.priority == RiskPriority.P0_CRITIQUE
    assert float(cms.composite_risk_score) == pytest.approx(87.15, abs=0.01)

    alerts = (await db_session.execute(select(CVEAlert))).scalars().all()
    assert [(a.cve_id, a.reason) for a in alerts] == [("CVE-2026-10001", "epss")]
    assert float(alerts[0].previous_score or 0) == pytest.approx(63.2, abs=0.01)

    changes = (
        (
            await db_session.execute(
                select(CVEPriorityChange)
                .where(CVEPriorityChange.cve_id == "CVE-2026-10001")
                .order_by(CVEPriorityChange.changed_at, CVEPriorityChange.new_score)
            )
        )
        .scalars()
        .all()
    )
    assert [(c.old_priority, c.new_priority, c.reason) for c in changes] == [
        (None, "P3_FAIBLE", "nvd"),
        ("P3_FAIBLE", "P1_ELEVE", "kev"),
        ("P1_ELEVE", "P0_CRITIQUE", "epss"),
    ]

    # Rester au-dessus du seuil ne réalerte pas.
    await sync_cves(
        db_session,
        settings=settings,
        fetch=sources,
        sleep=_no_sleep,
        clock=lambda: later + timedelta(hours=6),
    )
    assert len((await db_session.execute(select(CVEAlert))).scalars().all()) == 1


async def test_une_source_en_panne_n_empeche_pas_les_autres(db_session: AsyncSession) -> None:
    settings = _settings(nvd_api_key=SecretStr("cle-secrete-nvd-42"))
    sources = _Sources(settings)
    sources.fail = {"nvd"}

    async def leaky(url: str, *, headers: Mapping[str, str] | None = None) -> bytes:
        if url.startswith(settings.nvd_api_url):
            raise FetchError("refus pour la clé cle-secrete-nvd-42")
        return await sources(url, headers=headers)

    report = await sync_cves(
        db_session, settings=settings, fetch=leaky, sleep=_no_sleep, clock=lambda: T0
    )

    assert set(report.errors) == {"nvd"}
    assert "cle-secrete" not in report.errors["nvd"] and "***" in report.errors["nvd"]
    assert (await _cve(db_session, "CVE-2021-44228")).is_kev  # KEV importé malgré tout
    assert (await _cve(db_session, "CVE-2020-1472")).epss_score is not None
    baseline = await db_session.get(CollectorState, "cve_baseline")
    assert baseline is None or baseline.last_success_at is None  # ligne de base non établie
    nvd = await db_session.get(CollectorState, "nvd")
    assert nvd is not None and nvd.cursor is None and nvd.last_error


async def test_retrait_du_catalogue_kev(db_session: AsyncSession) -> None:
    settings = _settings()
    sources = _Sources(settings)
    await sync_cves(db_session, settings=settings, fetch=sources, sleep=_no_sleep, clock=lambda: T0)
    sources.kev["vulnerabilities"] = sources.kev["vulnerabilities"][:1]  # Netlogon retirée
    await sync_cves(
        db_session,
        settings=settings,
        fetch=sources,
        sleep=_no_sleep,
        clock=lambda: T0 + timedelta(hours=1),
        steps=("kev",),
    )
    netlogon = await _cve(db_session, "CVE-2020-1472")
    assert not netlogon.is_kev
    assert netlogon.priority == RiskPriority.P3_FAIBLE


async def test_cadence_de_synchronisation(db_session: AsyncSession) -> None:
    assert await cve_sync_due(db_session, interval_seconds=3600, now=T0)
    await mark_cve_sync_attempt(db_session, T0)
    assert not await cve_sync_due(db_session, interval_seconds=3600, now=T0 + timedelta(minutes=59))
    assert await cve_sync_due(db_session, interval_seconds=3600, now=T0 + timedelta(hours=1))


# --- Alertes -------------------------------------------------------------------


async def _alert(session: AsyncSession) -> CVEAlert:
    session.add(
        CVE(
            id="CVE-2026-9",
            description="x",
            published_date=T0,
            last_modified_date=T0,
            composite_risk_score=90,
            priority=RiskPriority.P0_CRITIQUE,
        )
    )
    alert = CVEAlert(
        cve_id="CVE-2026-9",
        score=90,
        previous_score=50,
        priority=RiskPriority.P0_CRITIQUE,
        reason="kev",
        delivery_attempts=0,
        created_at=T0,
    )
    session.add(alert)
    await session.flush()
    return alert


async def test_livraison_webhook_et_nouvelles_tentatives(db_session: AsyncSession) -> None:
    alert = await _alert(db_session)
    settings = _settings(alert_webhook_url=SecretStr("https://hooks.example.org/T0K3N-secret"))
    sent: list[tuple[str, dict[str, Any]]] = []
    failing = True

    async def post(url: str, payload: dict[str, Any]) -> None:
        if failing:
            raise RuntimeError(f"connexion refusée par {url}")
        sent.append((url, payload))

    assert await deliver_pending(db_session, settings=settings, post=post) == (0, 1)
    assert alert.delivery_attempts == 1 and alert.delivered_at is None
    assert alert.last_delivery_error is not None and "T0K3N" not in alert.last_delivery_error

    failing = False
    assert await deliver_pending(db_session, settings=settings, post=post, clock=lambda: T0) == (
        1,
        0,
    )
    assert alert.delivered_at == T0
    payload = sent[0][1]
    assert payload["cve"] == "CVE-2026-9" and payload["sla_hours"] == 24
    assert "CVE-2026-9" in payload["text"] and "24 h" in payload["text"]
    assert await deliver_pending(db_session, settings=settings, post=post) == (0, 0)


async def test_abandon_apres_cinq_echecs_et_sans_webhook(db_session: AsyncSession) -> None:
    alert = await _alert(db_session)

    async def post(url: str, payload: dict[str, Any]) -> None:
        raise RuntimeError("HTTP 500")

    assert await deliver_pending(db_session, settings=_settings(), post=post) == (0, 0)
    settings = _settings(alert_webhook_url=SecretStr("https://hooks.example.org/x"))
    for _ in range(MAX_DELIVERY_ATTEMPTS + 2):
        await deliver_pending(db_session, settings=settings, post=post)
    assert alert.delivery_attempts == MAX_DELIVERY_ATTEMPTS


async def test_acquittement_idempotent(db_session: AsyncSession) -> None:
    from uuid import uuid4

    from sentry.modules.foundation.users import create_user

    alert = await _alert(db_session)
    users = [
        await create_user(
            db_session,
            username=f"analyste-{n}",
            email=f"analyste-{n}@cyberill.test",
            password="mot-de-passe-robuste-2026",
        )
        for n in (1, 2)
    ]
    first, second = users[0].id, users[1].id
    await acknowledge(db_session, alert.id, first, clock=lambda: T0)
    await acknowledge(db_session, alert.id, second, clock=lambda: T0 + timedelta(hours=1))
    acked_at = alert.acknowledged_at
    assert acked_at is not None
    assert (alert.acknowledged_by, acked_at.replace(tzinfo=UTC)) == (first, T0)
    with pytest.raises(AlertNotFoundError):
        await acknowledge(db_session, uuid4(), first)
    assert alert_payload(alert)["priority"] == "P0_CRITIQUE"


async def test_filtre_haskev_refuse_n_arrete_pas_la_synchro(db_session: AsyncSession) -> None:
    settings = _settings()
    sources = _Sources(settings)

    async def no_haskev(url: str, *, headers: Mapping[str, str] | None = None) -> bytes:
        if url.endswith("&hasKev"):
            raise FetchError("HTTP 404 renvoyé par la source.")
        return await sources(url, headers=headers)

    report = await sync_cves(
        db_session, settings=settings, fetch=no_haskev, sleep=_no_sleep, clock=lambda: T0
    )
    assert report.succeeded
    assert (await _cve(db_session, "CVE-2021-44228")).cvss_score is not None  # fenêtre NVD
