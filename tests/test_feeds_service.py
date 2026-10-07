"""Tests unitaires du service des sources de flux — validation d'URL (SSRF) et de nom."""

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.models import ThreatFeed
from illwatch.modules.threat_feeds import service
from illwatch.modules.threat_feeds.service import (
    FeedNameConflictError,
    UnsafeFeedURLError,
    normalize_feed_name,
    validate_feed_url,
)
from illwatch.shared.enums import FeedStatus, FeedType


@pytest.mark.parametrize(
    "url",
    [
        "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "https://otx.alienvault.com:443/api/v1/pulses/subscribed?page=1",
        "  https://example.org/feed.json  ",
        "https://8.8.8.8/feed.json",
    ],
)
def test_url_publiques_acceptees(url: str) -> None:
    assert validate_feed_url(url) == url.strip()


@pytest.mark.parametrize(
    ("url", "motif"),
    [
        ("http://example.org/feed.json", "HTTPS"),
        ("ftp://example.org/feed.json", "HTTPS"),
        ("file:///etc/passwd", "HTTPS"),
        ("https://user:secret@example.org/feed", "identifiants"),
        ("https://127.0.0.1/admin", "interne"),
        ("https://10.0.0.5/feed", "interne"),
        ("https://192.168.1.10/feed", "interne"),
        ("https://169.254.169.254/latest/meta-data/", "interne"),
        ("https://[::1]/feed", "interne"),
        ("https://0.0.0.0/feed", "interne"),
        ("https://localhost/feed", "local"),
        ("https://api.localhost/feed", "local"),
        ("https://nas.local/feed", "local"),
        ("https://intranet/feed", "invalide"),
        ("https://2130706433/feed", "invalide"),
        ("https://0x7f.1/feed", "invalide"),
        ("https://example.org:99999/feed", "malformée"),
        ("https:///feed", "hôte"),
        ("", "vide"),
        ("https://example.org/" + "a" * 500, "trop longue"),
    ],
)
def test_url_dangereuses_refusees(url: str, motif: str) -> None:
    with pytest.raises(UnsafeFeedURLError, match=motif):
        validate_feed_url(url)


def test_nom_normalise() -> None:
    assert normalize_feed_name("  abuse.ch   URLhaus  ") == "abuse.ch URLhaus"


@pytest.mark.parametrize("name", ["", "   ", "x" * 101])
def test_nom_invalide(name: str) -> None:
    with pytest.raises(ValueError):
        normalize_feed_name(name)


# --- Accès aux données --------------------------------------------------------


async def test_conflit_concurrent_detecte_par_la_base(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Deux créations simultanées passent toutes deux la vérification applicative :
    la contrainte UNIQUE tranche, et la transaction reste utilisable ensuite."""

    async def _race(*_: object, **__: object) -> None:
        return None

    monkeypatch.setattr(service, "_ensure_name_available", _race)
    await service.create_feed(
        db_session, name="KEV", url="https://a.example.org/kev.json", feed_type=FeedType.JSON
    )
    with pytest.raises(FeedNameConflictError):
        await service.create_feed(
            db_session, name="KEV", url="https://b.example.org/kev.json", feed_type=FeedType.JSON
        )

    count = await db_session.scalar(select(func.count()).select_from(ThreatFeed))
    assert count == 1


async def test_changer_de_format_reinitialise_l_etat(db_session: AsyncSession) -> None:
    feed = await service.create_feed(
        db_session, name="Flux", url="https://a.example.org/f.csv", feed_type=FeedType.CSV
    )
    feed.status = FeedStatus.HEALTHY
    await db_session.flush()

    same = await service.update_feed(db_session, feed.id, feed_type=FeedType.CSV)
    assert same.status == FeedStatus.HEALTHY

    changed = await service.update_feed(db_session, feed.id, feed_type=FeedType.STIX)
    assert changed.status == FeedStatus.PENDING
    assert changed.feed_type == FeedType.STIX


@pytest.mark.parametrize(
    "address",
    [
        "100.100.100.200",  # CGNAT : métadonnées Alibaba Cloud
        "100.64.0.1",
        "::ffff:127.0.0.1",  # IPv4 mappée
        "64:ff9b::7f00:1",  # NAT64 → 127.0.0.1
        "2002:a9fe:a9fe::1",  # 6to4 → 169.254.169.254
        "fc00::1",  # IPv6 unique local
        "192.0.2.10",  # documentation
        "224.0.0.1",  # multicast
    ],
)
def test_adresses_non_publiques_detectees(address: str) -> None:
    from illwatch.modules.threat_feeds.service import is_internal_ip

    assert is_internal_ip(address)


@pytest.mark.parametrize("address", ["8.8.8.8", "93.184.216.34", "2606:4700::1111"])
def test_adresses_publiques_admises(address: str) -> None:
    from illwatch.modules.threat_feeds.service import is_internal_ip

    assert not is_internal_ip(address)
