"""Unit tests for Aho-Corasick multi-pattern matching and NaiveMatcher baseline."""

import pytest
from banner.matcher import (
    AhoCorasick,
    NaiveMatcher,
    Signature,
    extract_software_version,
)


def test_aho_corasick_basic_matching():
    """Verify standard Aho-Corasick search finds expected signatures."""
    ac = AhoCorasick(case_sensitive=False)
    ac.add_signature(Signature("sig1", "OpenSSH", "OpenSSH", "SSH"))
    ac.add_signature(Signature("sig2", "Debian", "Debian Linux", "OS"))
    ac.build()

    banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6 Debian"
    matches = ac.search(banner)

    matched_ids = [m.pattern_id for m in matches]
    assert "sig1" in matched_ids
    assert "sig2" in matched_ids


def test_overlapping_and_nested_patterns():
    """Verify classic Aho-Corasick benchmark on overlapping substrings ('he', 'she', 'his', 'hers')."""
    ac = AhoCorasick(case_sensitive=False)
    patterns = [
        ("p_he", "he"),
        ("p_she", "she"),
        ("p_his", "his"),
        ("p_hers", "hers"),
    ]
    for pid, pat in patterns:
        ac.add_signature(Signature(pid, pat, "Prod", "Proto"))
    ac.build()

    text = "ushers"
    matches = ac.search(text)
    # In 'ushers':
    # 'she' from index 1 to 4
    # 'he' from index 2 to 4
    # 'hers' from index 2 to 6
    matched_ids = [m.pattern_id for m in matches]
    assert "p_she" in matched_ids
    assert "p_he" in matched_ids
    assert "p_hers" in matched_ids
    assert len(matches) == 3


def test_repeated_occurrences():
    """Verify multiple occurrences of the same pattern are reported."""
    ac = AhoCorasick(case_sensitive=False)
    ac.add_signature(Signature("sig_nginx", "nginx", "nginx", "HTTP"))
    ac.build()

    banner = "Server: nginx/1.24.0 (nginx worker process)"
    matches = ac.search(banner)
    assert len(matches) == 2
    assert matches[0].start_pos == 8
    assert matches[1].start_pos == 22


def test_case_sensitivity():
    """Verify case sensitivity toggle behavior."""
    ac_ci = AhoCorasick(case_sensitive=False)
    ac_ci.add_signature(Signature("s1", "Apache", "Apache", "HTTP"))
    ac_ci.build()

    ac_cs = AhoCorasick(case_sensitive=True)
    ac_cs.add_signature(Signature("s1", "Apache", "Apache", "HTTP"))
    ac_cs.build()

    text = "server: apache/2.4.52"
    assert len(ac_ci.search(text)) == 1
    assert len(ac_cs.search(text)) == 0


def test_equivalence_with_naive_matcher():
    """Verify Aho-Corasick and NaiveMatcher produce identical matches across diverse inputs."""
    signatures = [
        Signature("sig1", "SSH-2.0", "SSH Protocol", "SSH"),
        Signature("sig2", "OpenSSH", "OpenSSH", "SSH"),
        Signature("sig3", "Ubuntu", "Ubuntu", "OS"),
        Signature("sig4", "nginx", "nginx", "HTTP"),
        Signature("sig5", "Apache", "Apache", "HTTP"),
        Signature("sig6", "PostgreSQL", "Postgres", "Database"),
    ]

    ac = AhoCorasick(case_sensitive=False)
    naive = NaiveMatcher(case_sensitive=False)

    for s in signatures:
        ac.add_signature(s)
        naive.add_signature(s)

    ac.build()

    sample_banners = [
        "SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.2",
        "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\nContent-Type: text/html",
        "220 (vsFTPd 3.0.3)\r\n530 Please login with USER and PASS.",
        "Server: Apache/2.4.58 (Unix) OpenSSH-proxy Ubuntu nginx-cache",
        "Random banner without any known signature here.",
    ]

    for banner in sample_banners:
        ac_matches = ac.search(banner)
        naive_matches = naive.search(banner)

        assert len(ac_matches) == len(naive_matches), f"Count mismatch on: {banner}"
        for ac_m, nv_m in zip(ac_matches, naive_matches):
            assert ac_m.pattern_id == nv_m.pattern_id
            assert ac_m.start_pos == nv_m.start_pos
            assert ac_m.end_pos == nv_m.end_pos
            assert ac_m.product == nv_m.product


def test_version_extraction():
    """Verify decoupled software version extraction heuristics."""
    assert extract_software_version("SSH-2.0-OpenSSH_9.3p1", "OpenSSH") == "9.3p1"
    assert extract_software_version("Server: nginx/1.24.0", "nginx") == "1.24.0"
    assert extract_software_version("Apache/2.4.58 (Ubuntu)", "Apache") == "2.4.58"
    assert extract_software_version("220 vsftpd 3.0.5 ready", "vsftpd") == "3.0.5"
    assert extract_software_version("220 ESMTP Postfix 3.8.1", "Postfix") == "3.8.1"
    assert extract_software_version("No version info present", "OpenSSH") is None
