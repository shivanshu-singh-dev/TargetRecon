"""Unit tests for authorization scope enforcement and Nmap XML parsing without Nmap execution."""

import tempfile
from pathlib import Path
import pytest
from active.scope import ScopeManager, ScopeValidationError
from active.nmap_runner import parse_nmap_xml
from config import config


def test_scope_manager_hostnames_and_ips():
    """Verify scope manager permits authorized hosts/CIDRs and rejects out-of-scope targets."""
    mgr = ScopeManager()
    mgr.add_rule("example.com")
    mgr.add_rule("api.example.com")
    mgr.add_rule("*.corp.example.com")
    mgr.add_rule("192.168.1.0/24")
    mgr.add_rule("10.0.0.5")

    # In scope tests
    assert mgr.is_in_scope("example.com") is True
    assert mgr.is_in_scope("API.EXAMPLE.COM") is True
    assert mgr.is_in_scope("dev.corp.example.com") is True
    assert mgr.is_in_scope("192.168.1.50") is True
    assert mgr.is_in_scope("10.0.0.5") is True

    # Out of scope tests
    assert mgr.is_in_scope("unauthorized.com") is False
    assert mgr.is_in_scope("attacker.example.com") is False
    assert mgr.is_in_scope("192.168.2.1") is False
    assert mgr.is_in_scope("10.0.0.6") is False


def test_scope_validation_exception():
    """Verify validate_or_raise raises ScopeValidationError for unauthorized host."""
    mgr = ScopeManager()
    mgr.add_rule("authorized.example.com")

    # Should not raise for authorized target
    mgr.validate_or_raise("authorized.example.com")

    # Must raise for unauthorized target
    with pytest.raises(ScopeValidationError) as excinfo:
        mgr.validate_or_raise("malicious.example.com")
    assert "NOT in authorized scope" in str(excinfo.value)


def test_scope_file_loading():
    """Verify loading scope rules from a file with comments and empty lines."""
    content = """
    # Primary authorized scope
    example.com
    api.example.com
    
    # Subnets
    10.10.0.0/16
    """
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as f:
        f.write(content)
        tmp_name = f.name

    try:
        mgr = ScopeManager()
        count = mgr.load_from_file(tmp_name)
        assert count == 3
        assert mgr.is_in_scope("api.example.com") is True
        assert mgr.is_in_scope("10.10.5.1") is True
        assert mgr.is_in_scope("10.11.0.1") is False
    finally:
        Path(tmp_name).unlink(missing_ok=True)


def test_parse_nmap_xml_offline():
    """Verify parsing Nmap XML into ServiceEndpoints without executing Nmap."""
    sample_xml = config.FIXTURES_DIR / "nmap_sample.xml"
    assert sample_xml.is_file(), "nmap_sample.xml fixture must exist"

    xml_text = sample_xml.read_text(encoding="utf-8")
    endpoints = parse_nmap_xml(xml_text, source="test_nmap")

    assert len(endpoints) == 3
    # Check open ports: 80, 443, 8080 (port 22 was closed in fixture)
    ports = {e.port for e in endpoints}
    assert ports == {80, 443, 8080}

    # Check nginx service detection on 80
    ep80 = next(e for e in endpoints if e.port == 80)
    assert ep80.service_name == "http"
    assert ep80.product == "nginx"
    assert ep80.version == "1.24.0"
    assert ep80.confidence > 0.9

    # Check envoy on 8080
    ep8080 = next(e for e in endpoints if e.port == 8080)
    assert ep8080.product == "Envoy Proxy"
    assert ep8080.version == "1.28.0"


def test_parse_nmap_malformed_xml():
    """Verify robust handling of malformed XML."""
    endpoints = parse_nmap_xml("<invalid xml", source="test")
    assert endpoints == []


def test_hostname_suffix_matching():
    """Verify wildcard *.example.com matches subdomains but strictly rejects spoofed suffixes."""
    mgr = ScopeManager()
    mgr.add_rule("*.example.com")

    # Valid subdomains
    assert mgr.is_in_scope("sub.example.com") is True
    assert mgr.is_in_scope("deep.internal.example.com") is True
    assert mgr.is_in_scope("example.com") is True

    # Suffix spoofing attempts must be rejected
    assert mgr.is_in_scope("attacker-example.com") is False
    assert mgr.is_in_scope("notexample.com") is False
    assert mgr.is_in_scope("example.com.attacker.com") is False


def test_dns_rebinding_and_ip_auditing():
    """Verify anti-rebinding protection rejects loopback and out-of-subnet IPs."""
    mgr = ScopeManager()
    mgr.add_rule("api.example.com")
    mgr.add_rule("192.168.1.0/24")

    # Hostname is in scope, and resolved IP matches authorized subnet
    assert mgr.is_in_scope("api.example.com", resolved_ip="192.168.1.10") is True

    # Hostname in scope, but resolved IP rebinds to loopback 127.0.0.1 (must be blocked)
    assert mgr.is_in_scope("api.example.com", resolved_ip="127.0.0.1") is False

    # Hostname in scope, but resolved IP rebinds to unauthorized cloud metadata IP
    assert mgr.is_in_scope("api.example.com", resolved_ip="169.254.169.254") is False

    # Hostname in scope, but resolved IP is in unauthorized subnet 10.0.0.1
    assert mgr.is_in_scope("api.example.com", resolved_ip="10.0.0.1") is False

