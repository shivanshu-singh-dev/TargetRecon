"""Unit tests for passive reconnaissance parsing, fixture ingestion, and missing tool handling."""

import json
from unittest.mock import MagicMock, patch
import pytest
import requests

from config import config
from models import DiscoveredAssetInventory
from passive.crtsh import query_crtsh
from passive.indexed_services import (
    query_censys_hosts,
    query_shodan_host,
    query_shodan_subdomains,
)
from passive.theharvester import run_theharvester
from passive.whois_lookup import parse_whois_text


def test_fixture_passive_data_ingestion():
    """Verify loading and parsing the complete passive_data.json fixture."""
    fixture_path = config.FIXTURES_DIR / "passive_data.json"
    assert fixture_path.is_file(), "passive_data.json must exist in fixtures"

    with open(fixture_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    inv = DiscoveredAssetInventory(root_domain=data["target_domain"])
    for sub in data["subdomains"]:
        inv.add_subdomain(sub["subdomain"], source="fixture")

    for r in data["dns_records"]:
        from models import DNSRecord
        rec = DNSRecord(
            record_type=r["record_type"],
            host=r["host"],
            value=r["value"],
            source=r["source"],
        )
        inv.add_dns_record(rec)

    assert len(inv.subdomains) == 5
    assert len(inv.dns_records) == 9
    assert "api.example.com" in inv.subdomains


def test_crtsh_mocked_success():
    """Verify crt.sh parsing with mocked valid HTTP response."""
    mock_response = [
        {"common_name": "example.com", "name_value": "api.example.com\nmail.example.com"},
        {"common_name": "*.corp.example.com", "name_value": "corp.example.com"},
    ]

    inv = DiscoveredAssetInventory(root_domain="example.com")
    with patch("requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = mock_response

        subs = query_crtsh("example.com", inv)

        assert "api.example.com" in subs
        assert "mail.example.com" in subs
        assert "corp.example.com" in subs
        assert len(inv.errors) == 0


def test_crtsh_rate_limit_and_timeout():
    """Verify crt.sh handles HTTP 429 rate limits and timeouts gracefully without crashing."""
    inv = DiscoveredAssetInventory(root_domain="example.com")

    # 429 Rate limit test
    with patch("requests.get") as mock_get:
        mock_get.return_value.status_code = 429
        subs = query_crtsh("example.com", inv)
        assert len(subs) == 0
        assert any("Rate Limited" in err["message"] for err in inv.errors)

    # Timeout test
    inv_timeout = DiscoveredAssetInventory(root_domain="example.com")
    with patch("requests.get", side_effect=requests.exceptions.Timeout("Timed out")):
        subs = query_crtsh("example.com", inv_timeout)
        assert len(subs) == 0
        assert any("timed out" in err["message"] for err in inv_timeout.errors)


def test_missing_theharvester():
    """Verify that when theHarvester is missing from PATH, clear warning is recorded and pipeline continues."""
    inv = DiscoveredAssetInventory(root_domain="example.com")
    with patch("config.AppConfig.is_tool_available", return_value=False):
        subs = run_theharvester("example.com", inv)
        assert len(subs) == 0
        assert any("theHarvester is not installed" in err["message"] for err in inv.errors)


def test_missing_api_keys_shodan_and_censys():
    """Verify that missing API credentials do not fail the pipeline and record informative status."""
    inv = DiscoveredAssetInventory(root_domain="example.com")

    # Shodan without key
    subs = query_shodan_subdomains("example.com", inv, api_key=None)
    assert len(subs) == 0
    assert any("Shodan API key not configured" in err["message"] for err in inv.errors)

    # Censys without keys
    ips = query_censys_hosts("example.com", inv, api_id=None, api_secret=None)
    assert len(ips) == 0
    assert any("Censys API credentials not configured" in err["message"] for err in inv.errors)


def test_parse_whois_redacted_fields():
    """Verify WHOIS parser handles GDPR and privacy redacted strings gracefully."""
    sample_whois = """
    Domain Name: example.com
    Registrar: Example Registrar, Inc.
    Registrant Organization: REDACTED FOR PRIVACY
    Registrant Country: US
    Creation Date: 1995-09-03T04:00:00Z
    """
    parsed = parse_whois_text(sample_whois)
    assert parsed["registrar"] == "Example Registrar, Inc."
    assert parsed["organization"] == "[REDACTED FOR PRIVACY]"
    assert parsed["country"] == "US"
    assert parsed["creation_date"] == "1995-09-03T04:00:00Z"
