"""M10, incrément 3 (ADR-025) : export STIX 2.1 et serveur TAXII 2.1 en lecture seule."""

import base64
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from illwatch.app.api.taxii import CAMPAIGNS, INDICATORS, TAXII_MEDIA
from illwatch.app.security import create_access_token
from illwatch.modules.attack.campaigns import attach, create_campaign
from illwatch.modules.attack.demo import demo_attack_data
from illwatch.modules.attack.service import import_attack
from illwatch.modules.foundation.users import create_user
from illwatch.modules.soc.exclusions import create_exclusion
from illwatch.modules.stix.export import (
    IDENTITY_ID,
    export_bundle,
    indicator_page,
    pattern,
    stix_id,
)
from illwatch.modules.threat_feeds.indicators import Observation, ingest_indicators
from illwatch.modules.threat_feeds.parsers import parse_stix_objects
from illwatch.shared.enums import UserRole

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)
PASSWORD = "mot-de-passe-robuste-2026"


def test_motifs_stix() -> None:
    assert pattern("IPV4", "203.0.113.7") == "[ipv4-addr:value = '203.0.113.7']"
    assert pattern("NETWORK", "2001:db8::/32") == "[ipv6-addr:value = '2001:db8::/32']"
    assert pattern("NETWORK", "198.51.100.0/24") == "[ipv4-addr:value = '198.51.100.0/24']"
    assert pattern("URL", "http://x.test/a'b") == "[url:value = 'http://x.test/a\\'b']"
    assert pattern("HASH_SHA256", "a" * 64) == f"[file:hashes.'SHA-256' = '{'a' * 64}']"
    # Identifiants déterministes : même IOC, même identifiant d'un export à l'autre.
    assert stix_id("indicator", "IPV4:203.0.113.7") == stix_id("indicator", "IPV4:203.0.113.7")


async def _user(session: AsyncSession, role: UserRole = UserRole.VIEWER) -> tuple[str, dict]:
    name = f"taxii-{uuid4().hex[:8]}"
    user = await create_user(
        session, username=name, email=f"{name}@cyberill.test", password=PASSWORD, role=role
    )
    return name, {"Authorization": f"Bearer {create_access_token(user.id, user.role)}"}


async def test_export_aller_retour(db_session: AsyncSession) -> None:
    values = ["198.51.100.40", "c2.example.net", "http://dl.example.net/x.exe", "a" * 64]
    await ingest_indicators(db_session, [Observation(v, description="lot STIX") for v in values])
    await ingest_indicators(db_session, [Observation("www.example.org")])
    await create_exclusion(
        db_session, value="www.example.org", reason="faux positif qualifié", author_id=None
    )
    document = await export_bundle(db_session, content="indicateurs")
    assert document["type"] == "bundle" and document["objects"][0]["id"] == IDENTITY_ID
    indicators = [o for o in document["objects"] if o["type"] == "indicator"]
    assert all(
        o["created_by_ref"] == IDENTITY_ID and 0 <= o["confidence"] <= 100 for o in indicators
    )
    # Ce qu'ILL Watch exporte, ILL Watch (ou tout client STIX) le relit à l'identique.
    parsed = {o.value for o in parse_stix_objects(document["objects"]).observations}
    assert set(values) <= parsed
    assert "www.example.org" not in parsed  # IOC exclu (faux positif) : jamais partagé


async def test_pagination_par_curseur(db_session: AsyncSession) -> None:
    await ingest_indicators(
        db_session,
        [
            Observation(f"203.0.113.{i}", observed_at=NOW - timedelta(minutes=10 - i))
            for i in range(1, 8)
        ],
    )
    seen: list[str] = []
    token = None
    for _ in range(10):
        page = await indicator_page(db_session, now=NOW, limit=3, next_token=token)
        seen += [o["id"] for o in page.objects]
        if not page.more:
            break
        token = page.next
    assert len(seen) == len(set(seen)) >= 7
    with pytest.raises(ValueError):
        await indicator_page(db_session, now=NOW, next_token="pas-un-curseur")


async def test_serveur_taxii(client: AsyncClient, db_session: AsyncSession) -> None:
    await import_attack(db_session, demo_attack_data(), now=NOW)
    await ingest_indicators(
        db_session,
        [
            Observation("198.51.100.50", description="Opération TAXII"),
            Observation("evil.example.net", description="Opération TAXII"),
        ],
    )
    campaign = await create_campaign(db_session, name="Opération TAXII", actor_id="G0102")
    await attach(db_session, campaign.id, description_contains="Opération TAXII")
    name, headers = await _user(db_session)
    headers["Accept"] = TAXII_MEDIA

    assert (await client.get("/taxii2/")).status_code == 401
    refused = await client.get("/taxii2/", headers={"Authorization": "Basic " + "eDp5"})
    assert refused.status_code == 401 and refused.json()["http_status"] == "401"
    assert refused.headers["content-type"].startswith("application/taxii+json")

    basic = base64.b64encode(f"{name}:{PASSWORD}".encode()).decode()
    discovery = await client.get(
        "/taxii2/", headers={"Authorization": f"Basic {basic}", "Accept": TAXII_MEDIA}
    )
    assert discovery.status_code == 200, discovery.text
    assert discovery.json()["api_roots"][0].endswith("/taxii2/illwatch/")
    root = (await client.get("/taxii2/illwatch/", headers=headers)).json()
    assert root["versions"] == [TAXII_MEDIA]
    listed = (await client.get("/taxii2/illwatch/collections/", headers=headers)).json()
    assert {c["id"] for c in listed["collections"]} == {INDICATORS.id, CAMPAIGNS.id}
    assert all(c["can_read"] and not c["can_write"] for c in listed["collections"])
    assert (
        await client.get(f"/taxii2/illwatch/collections/{uuid4()}/", headers=headers)
    ).status_code == 404
    bad_accept = await client.get(
        "/taxii2/illwatch/", headers={**headers, "Accept": "application/xml"}
    )
    assert bad_accept.status_code == 406

    url = f"/taxii2/illwatch/collections/{INDICATORS.id}/objects/"
    first = await client.get(url, params={"limit": 1}, headers=headers)
    assert first.status_code == 200 and first.headers["content-type"].startswith(
        "application/taxii+json"
    )
    envelope = first.json()
    assert envelope["more"] is True and envelope["next"]
    assert "X-TAXII-Date-Added-Last" in first.headers
    second = (
        await client.get(url, params={"limit": 1000, "next": envelope["next"]}, headers=headers)
    ).json()
    values = {
        o.value
        for o in parse_stix_objects(envelope["objects"] + second.get("objects", [])).observations
    }
    assert {"198.51.100.50", "evil.example.net"} <= values
    later = await client.get(url, params={"added_after": "2999-01-01T00:00:00Z"}, headers=headers)
    assert later.json() == {"more": False}
    manifest = (
        await client.get(f"/taxii2/illwatch/collections/{INDICATORS.id}/manifest/", headers=headers)
    ).json()
    assert all(m["media_type"].startswith("application/stix+json") for m in manifest["objects"])

    campaigns = (
        await client.get(f"/taxii2/illwatch/collections/{CAMPAIGNS.id}/objects/", headers=headers)
    ).json()["objects"]
    kinds = {o["type"] for o in campaigns}
    assert {"campaign", "intrusion-set", "relationship", "indicator", "identity"} <= kinds
    actor = next(o for o in campaigns if o["type"] == "intrusion-set")
    assert actor["external_references"][0]["external_id"] == "G0102"
    relations = {o["relationship_type"] for o in campaigns if o["type"] == "relationship"}
    assert relations == {"attributed-to", "indicates"}
    only = (
        await client.get(
            f"/taxii2/illwatch/collections/{CAMPAIGNS.id}/objects/",
            params={"match[type]": "campaign"},
            headers=headers,
        )
    ).json()["objects"]
    assert [o["name"] for o in only] == ["Opération TAXII"]

    exported = await client.get(
        "/api/v1/stix/bundle", params={"contenu": "campagnes"}, headers=headers
    )
    assert exported.status_code == 200
    assert exported.headers["content-type"].startswith("application/stix+json")
    assert any(o["type"] == "campaign" for o in exported.json()["objects"])
    # L'interface web ne capte pas /taxii2 : une adresse inconnue répond 404, pas la page HTML.
    assert (await client.get("/taxii2/inconnu", headers=headers)).status_code == 404
