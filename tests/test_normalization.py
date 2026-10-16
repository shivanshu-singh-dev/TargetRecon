"""Unit tests for domain, IP, and port normalization, and provenance preservation."""

import pytest
from models import (
    CollectionMethod,
    DiscoveredAssetInventory,
    Observation,
    normalize_domain,
    normalize_ip,
    normalize_port,
)


def test_normalize_domain():
    """Verify domain normalization cleans whitespace, dots, wildcards, and casing."""
    assert normalize_domain("EXAMPLE.COM") == "example.com"
    assert normalize_domain("  sub.example.com. ") == "sub.example.com"
    assert normalize_domain("*.corp.example.com") == "corp.example.com"
    assert normalize_domain("api.test.co.uk.") == "api.test.co.uk"
    assert normalize_domain("") == ""
    assert normalize_domain(None) == ""


def test_normalize_ip():
    """Verify IP canonicalization for IPv4 and IPv6."""
    assert normalize_ip("192.168.1.1") == "192.168.1.1"
    assert normalize_ip(" 10.0.0.1\n") == "10.0.0.1"
    assert normalize_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "2001:db8:85a3::8a2e:370:7334"
    assert normalize_ip("::1") == "::1"
    # Invalid IPs should return None
    assert normalize_ip("999.999.999.999") is None
    assert normalize_ip("invalid-ip") is None
    assert normalize_ip("") is None


def test_normalize_port():
    """Verify port validation bounds within 1-65535."""
    assert normalize_port(80) == 80
    assert normalize_port("443") == 443
    assert normalize_port(65535) == 65535
    assert normalize_port(1) == 1
    assert normalize_port(0) is None
    assert normalize_port(70000) is None
    assert normalize_port("invalid") is None


def test_deduplication_preserving_provenance():
    """Verify multiple sources for the same asset are deduplicated while preserving full provenance."""
    inv = DiscoveredAssetInventory(root_domain="example.com")

    # Add same subdomain from two different sources
    inv.add_subdomain("API.EXAMPLE.COM", source="crt.sh", method=CollectionMethod.PASSIVE)
    inv.add_subdomain("api.example.com.", source="dns_resolver", method=CollectionMethod.PASSIVE)
    inv.add_subdomain("*.api.example.com", source="whois", method=CollectionMethod.PASSIVE)

    # Subdomain set should contain exactly one normalized entry
    assert len(inv.subdomains) == 1
    assert "api.example.com" in inv.subdomains

    # Observations list preserves all three provenance records
    matching_obs = [o for o in inv.observations if o.asset_id == "api.example.com"]
    assert len(matching_obs) == 3
    sources = {o.source for o in matching_obs}
    assert sources == {"crt.sh", "dns_resolver", "whois"}
    for o in matching_obs:
        assert o.normalized_value == "api.example.com"
        assert o.timestamp is not None
