"""Tests réseau réels (T9) — désactivés par défaut ; lancés chaque semaine par la validation réelle.

À lancer sur le poste (Kali) pour valider la chaîne complète contre les vraies sources :

    SENTRY_LIVE_TESTS=1 pytest tests/test_live_sources.py -v --no-cov

Un échec ici décrit l'état d'une source externe (indisponible, format changé, identifiants
refusés), pas un défaut du code : comparer avec `sentry feeds probe`.
"""

import pytest

from sentry.app.config import get_settings
from sentry.modules.threat_feeds.probe import probe_source
from sentry.modules.threat_feeds.taxii import discover
from sentry.shared.enums import FeedType

pytestmark = pytest.mark.live

DIGITALSIDE = (
    "https://osint.digitalside.it/taxii2reports/collections/"
    "c1f43330-103b-11ee-9ee3-4b022e286589/objects/"
)


@pytest.mark.xfail(
    reason=(
        "DigitalSide injoignable depuis le 29/09/2026 (délai de connexion dépassé), constat "
        "renouvelé le 06/10 depuis GitHub Actions ; la source est inactive dans `sentry seed`. "
        "Un XPASS signale son retour : la réactiver alors (`sentry feeds enable`)."
    ),
    strict=False,
)
async def test_digitalside_taxii_reel() -> None:
    report = await probe_source(DIGITALSIDE, FeedType.TAXII, settings=get_settings())
    assert report.reachable, report.error
    assert report.pages == 1


async def test_mitre_attack_decouverte() -> None:
    found = await discover("https://attack-taxii.mitre.org/taxii2/", settings=get_settings())
    assert any("Enterprise" in c.title for c in found.collections), found.errors


@pytest.mark.parametrize(
    "url",
    [
        "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt",
        "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv",
    ],
)
async def test_sources_csv_sans_cle(url: str) -> None:
    report = await probe_source(url, FeedType.CSV, settings=get_settings())
    assert report.usable, report.error
